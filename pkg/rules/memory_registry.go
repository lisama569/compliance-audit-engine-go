package rules

import (
	"sort"
	"sync"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// tenantHistory 保存某租户不可变的已发布版本序列（按版本号升序）。
type tenantHistory struct {
	released []model.RuleSet // 已发布（含已回滚）的不可变快照
	current  int             // 当前生效版本在 released 中的下标
}

// memoryRegistry 为进程内注册表。
type memoryRegistry struct {
	mu       sync.Mutex
	tenants  map[string]*tenantHistory
	clock    func() time.Time
}

// NewMemoryRegistry 创建内存规则注册表。
func NewMemoryRegistry(clock ...func() time.Time) Registry {
	c := time.Now
	if len(clock) > 0 && clock[0] != nil {
		c = clock[0]
	}
	return &memoryRegistry{tenants: make(map[string]*tenantHistory), clock: c}
}

// Publish 校验通过后发布新版本：失败时当前生效状态完全不变。
// 入参的 Version 字段由注册表统一分配，调用方无需提供。
func (r *memoryRegistry) Publish(tenantID string, rs model.RuleSet) (model.RuleSet, error) {
	rs.TenantID = tenantID
	if err := ValidateRuleSet(rs); err != nil {
		return model.RuleSet{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil {
		h = &tenantHistory{current: -1}
		r.tenants[tenantID] = h
	}
	rs.Version = len(h.released) + 1
	rs.PublishedAt = r.clock().UTC()
	stored := cloneRuleSet(rs) // 内部快照独立
	h.released = append(h.released, stored)
	h.current = len(h.released) - 1
	return cloneRuleSet(stored), nil // 返回值同样独立，防止调用方回写污染
}

// cloneRuleSet 返回规则集的深拷贝（仅切片层；Rule 为值类型）。
func cloneRuleSet(rs model.RuleSet) model.RuleSet {
	cp := make([]model.Rule, len(rs.Rules))
	copy(cp, rs.Rules)
	rs.Rules = cp
	return rs
}

// Rollback 将当前生效版本回退到上一个版本。
// 回滚只移动“当前指针”，不删除任何历史版本；再次发布将在序列尾部追加新版本。
func (r *memoryRegistry) Rollback(tenantID string) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil || h.current <= 0 {
		return model.RuleSet{}, ErrNothingToRollback
	}
	h.current--
	return cloneRuleSet(h.released[h.current]), nil
}

// EffectiveAt 选取 t 时刻已经生效的最新版本（发布时间 <= t）。
// 已回滚版本仍在历史序列中，可用于复现历史结论。
func (r *memoryRegistry) EffectiveAt(tenantID string, t time.Time) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil {
		return model.RuleSet{}, ErrNoRuleSet
	}
	picked := -1
	for i, rs := range h.released {
		if !rs.PublishedAt.After(t) {
			picked = i
		}
	}
	if picked < 0 {
		return model.RuleSet{}, ErrNoRuleSet
	}
	return cloneRuleSet(h.released[picked]), nil
}

// Current 返回当前生效规则集。
func (r *memoryRegistry) Current(tenantID string) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.tenants[tenantID]
	if h == nil || h.current < 0 {
		return model.RuleSet{}, ErrNoRuleSet
	}
	return cloneRuleSet(h.released[h.current]), nil
}

// History 返回按版本号升序排列的全部已发布版本（含已回滚版本）。
func (r *memoryRegistry) History(tenantID string) []model.RuleSet {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.tenants[tenantID]
	if h == nil {
		return nil
	}
	out := make([]model.RuleSet, len(h.released))
	copy(out, h.released)
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}
