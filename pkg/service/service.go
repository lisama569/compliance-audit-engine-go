// Package service 是引擎门面：串联授权、接入、判定、规则管理与查询，
// 以租户为粒度串行化写入/发布/回滚/重算，保证并发一致性。
package service

import (
	"context"
	"sync"

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
