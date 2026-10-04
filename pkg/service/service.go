// Package service 是引擎门面：串联授权、接入、判定、规则管理与查询，
// 以租户为粒度串行化写入/发布/回滚/重算，保证并发一致性。
package service

import (
	"context"
	"sync"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/auth"
	"github.com/lisama569/compliance-audit-engine-go/pkg/engine"
	"github.com/lisama569/compliance-audit-engine-go/pkg/ingest"
	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/rules"
	"github.com/lisama569/compliance-audit-engine-go/pkg/store"
)

// Service 是本地离线合规审计服务。
type Service struct {
	auth     auth.Authorizer
	registry rules.Registry
	mem      *store.Memory
	eng      *engine.Engine
	ing      *ingest.Ingester

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex // 每租户串行锁
}

// New 组装服务；cfg 控制接入层背压/限流/迟到窗口/时钟。
func New(cfg ingest.Config) *Service {
	mem := store.NewMemory()
	reg := rules.NewMemoryRegistry(cfg.Clock)
	eng := engine.New(reg, mem, cfg.Clock)
	return &Service{
		auth:     auth.NewStaticAuthorizer(),
		registry: reg,
		mem:      mem,
		eng:      eng,
		ing:      ingest.New(mem, eng, cfg),
		locks:    make(map[string]*sync.Mutex),
	}
}

// IngestEvent 鉴权后接入事件（写路径，租户内串行）。
func (s *Service) IngestEvent(ctx context.Context, p auth.Principal, ev model.Event) (ingest.IngestResult, error) {
	if ev.TenantID == "" {
		return ingest.IngestResult{}, model.ErrInvalidEvent
	}
	if err := s.auth.Authorize(p, auth.ActionIngest, ev.TenantID); err != nil {
		return ingest.IngestResult{}, err
	}
	// 租户级串行：与同租户的规则切换/重算互斥。
	unlock := s.lockTenant(ev.TenantID)
	defer unlock()
	return s.ing.Ingest(ctx, ev)
}

// PublishRules 鉴权后发布新规则版本。
// 校验失败时注册表返回错误，当前生效状态不变；成功后补齐当前版本结果。
func (s *Service) PublishRules(p auth.Principal, rs model.RuleSet) (model.RuleSet, error) {
	tenantID := rs.TenantID
	if tenantID == "" {
		tenantID = p.TenantID
	}
	if err := s.auth.Authorize(p, auth.ActionPublish, tenantID); err != nil {
		return model.RuleSet{}, err
	}
	unlock := s.lockTenant(tenantID)
	defer unlock()

	published, err := s.registry.Publish(tenantID, rs)
	if err != nil {
		return model.RuleSet{}, err
	}
	if _, err := s.eng.RefillCurrent(tenantID); err != nil {
		return model.RuleSet{}, err
	}
	return published, nil
}

// RollbackRules 鉴权后回滚当前规则版本，并按回滚后的版本刷新当前结果。
func (s *Service) RollbackRules(p auth.Principal) (model.RuleSet, error) {
	if err := s.auth.Authorize(p, auth.ActionPublish, p.TenantID); err != nil {
		return model.RuleSet{}, err
	}
	unlock := s.lockTenant(p.TenantID)
	defer unlock()

	rs, err := s.registry.Rollback(p.TenantID)
	if err != nil {
		return model.RuleSet{}, err
	}
	if _, err := s.eng.RefillCurrent(p.TenantID); err != nil {
		return model.RuleSet{}, err
	}
	return rs, nil
}

// Recompute 鉴权后重算租户历史事件（租户内串行，与写入/切换互斥）。
func (s *Service) Recompute(ctx context.Context, p auth.Principal, tenantID string) (int, error) {
	if err := s.auth.Authorize(p, auth.ActionRecompute, tenantID); err != nil {
		return 0, err
	}
	unlock := s.lockTenant(tenantID)
	defer unlock()
	return s.eng.RecomputeTenant(tenantID)
}

// QueryResults 鉴权后查询判定结果；ruleVersion <= 0 表示当前生效版本。
// 指定历史版本时返回该版本槽位下的重算/原始结论。
func (s *Service) QueryResults(p auth.Principal, tenantID string, ruleVersion int) ([]model.Result, error) {
	if err := s.auth.Authorize(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	if ruleVersion <= 0 {
		cur, err := s.registry.Current(tenantID)
		if err != nil {
			return nil, err
		}
		ruleVersion = cur.Version
	}
	return s.mem.ListResults(tenantID, ruleVersion), nil
}

// QueryQuarantined 鉴权后查询隔离事件。
func (s *Service) QueryQuarantined(p auth.Principal, tenantID string) ([]model.QuarantinedEvent, error) {
	if err := s.auth.Authorize(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return s.mem.ListQuarantined(tenantID), nil
}

// RuleHistory 鉴权后返回规则发布历史（含已回滚版本）。
func (s *Service) RuleHistory(p auth.Principal, tenantID string) ([]model.RuleSet, error) {
	if err := s.auth.Authorize(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return s.registry.History(tenantID), nil
}

// PreviewPublish 预演“若发布该规则集”对本租户已有事件的影响。
//
// 只读：不发布、不改当前生效规则、不写任何判定结果，报告不混入正式查询。
// 候选规则集先经过与正式发布相同的严格校验，非法规则集直接预演失败。
// 预演持有租户串行锁，期间的事件写入/规则切换/重算都被阻塞，
// 保证不会读到前后对不上的半截数据。
func (s *Service) PreviewPublish(p auth.Principal, rs model.RuleSet) (model.PreviewReport, error) {
	tenantID := rs.TenantID
	if tenantID == "" {
		tenantID = p.TenantID
	}
	if err := s.auth.Authorize(p, auth.ActionQuery, tenantID); err != nil {
		return model.PreviewReport{}, err
	}
	unlock := s.lockTenant(tenantID)
	defer unlock()

	rs.TenantID = tenantID
	if err := rules.ValidateRuleSet(rs); err != nil {
		return model.PreviewReport{}, err
	}
	return s.eng.PreviewTenant(tenantID, rs, "publish")
}

// PreviewRollback 预演“若回滚到上一版本”对本租户已有事件的影响。
// 只读：不执行回滚、不写任何判定结果。没有可回滚版本时明确失败且状态不变。
func (s *Service) PreviewRollback(p auth.Principal) (model.PreviewReport, error) {
	if err := s.auth.Authorize(p, auth.ActionQuery, p.TenantID); err != nil {
		return model.PreviewReport{}, err
	}
	unlock := s.lockTenant(p.TenantID)
	defer unlock()

	cur, err := s.registry.Current(p.TenantID)
	if err != nil {
		return model.PreviewReport{}, err
	}
	if cur.Version <= 1 {
		return model.PreviewReport{}, rules.ErrNothingToRollback
	}
	// 版本号按发布顺序连续分配，回滚目标即当前版本的前一个版本。
	var target model.RuleSet
	for _, rs := range s.registry.History(p.TenantID) {
		if rs.Version == cur.Version-1 {
			target = rs
			break
		}
	}
	if target.Version == 0 {
		return model.PreviewReport{}, rules.ErrNothingToRollback
	}
	return s.eng.PreviewTenant(p.TenantID, target, "rollback")
}

// RuleTimeline 鉴权后返回租户规则版本的生效时间轴（半开区间，含回滚段）。
func (s *Service) RuleTimeline(p auth.Principal, tenantID string) ([]model.VersionInterval, error) {
	if err := s.auth.Authorize(p, auth.ActionQuery, tenantID); err != nil {
		return nil, err
	}
	return s.registry.Timeline(tenantID), nil
}

// EffectiveVersionAt 鉴权后返回 t 时刻真正生效的规则版本。
func (s *Service) EffectiveVersionAt(p auth.Principal, tenantID string, t time.Time) (model.RuleSet, error) {
	if err := s.auth.Authorize(p, auth.ActionQuery, tenantID); err != nil {
		return model.RuleSet{}, err
	}
	return s.registry.EffectiveAt(tenantID, t)
}

// lockTenant 返回某租户的解锁函数；同租户所有写/重算路径借此串行化。
func (s *Service) lockTenant(tenantID string) func() {
	s.locksMu.Lock()
	l, ok := s.locks[tenantID]
	if !ok {
		l = &sync.Mutex{}
		s.locks[tenantID] = l
	}
	s.locksMu.Unlock()
	l.Lock()
	return l.Unlock
}
