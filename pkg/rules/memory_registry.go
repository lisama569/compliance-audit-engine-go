package rules

import (
	"sort"
	"sync"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// activation 记录一次“生效切换”：发布新版本或回滚到历史版本。
// 时间轴与 EffectiveAt 均以激活日志为准，保证回滚后任意时刻
// 都能追溯到当时真正生效的版本。
type activation struct {
	version int
	at      time.Time
	cause   string // "publish" 或 "rollback"
}

// tenantHistory 保存某租户不可变的已发布版本序列（按版本号升序）。
type tenantHistory struct {
	released    []model.RuleSet // 已发布（含已回滚）的不可变快照
	current     int             // 当前生效版本在 released 中的下标
	activations []activation    // 生效切换日志（按发生先后追加）
}

// memoryRegistry 为进程内注册表。
type memoryRegistry struct {
	mu      sync.Mutex
	tenants map[string]*tenantHistory
	clock   func() time.Time
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
	h.activations = append(h.activations, activation{version: stored.Version, at: stored.PublishedAt, cause: "publish"})
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
// 回滚只移动“当前指针”并追加一条激活记录，不删除任何历史版本；
// 再次发布将在序列尾部追加新版本。没有更早版本时明确失败且状态不变。
func (r *memoryRegistry) Rollback(tenantID string) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil || h.current <= 0 {
		return model.RuleSet{}, ErrNothingToRollback
	}
	h.current--
	target := h.released[h.current]
	h.activations = append(h.activations, activation{version: target.Version, at: r.clock().UTC(), cause: "rollback"})
	return cloneRuleSet(target), nil
}

// EffectiveAt 返回 t 时刻真正生效的规则集。
//
// 以激活日志为准：选取生效时刻 <= t 的最后一次切换（发布或回滚）。
// 因此回滚之后发生的时刻会解析到回滚后的版本，而回滚之前、
// 旧版本实际生效过的时段仍解析到旧版本，历史结论可严格复现。
func (r *memoryRegistry) EffectiveAt(tenantID string, t time.Time) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil {
		return model.RuleSet{}, ErrNoRuleSet
	}
	picked := -1
	for i, a := range h.activations {
		if !a.at.After(t) {
			picked = i
		}
	}
	if picked < 0 {
		return model.RuleSet{}, ErrNoRuleSet
	}
	return cloneRuleSet(h.released[h.activations[picked].version-1]), nil
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

// Timeline 返回规则版本的生效时间轴。
//
// 由激活日志展开为半开区间序列 [From, To)：第 i 段从 activations[i].at
// 开始，到下一段开始时结束；最后一段 To 为零值（至今仍生效）且 Current=true。
// 边界约定保证任意时刻至多命中一个区间。回滚产生的新段也会按时间顺序出现。
func (r *memoryRegistry) Timeline(tenantID string) []model.VersionInterval {
	r.mu.Lock()
	defer r.mu.Unlock()
	h := r.tenants[tenantID]
	if h == nil || len(h.activations) == 0 {
		return nil
	}
	out := make([]model.VersionInterval, len(h.activations))
	for i, a := range h.activations {
		iv := model.VersionInterval{
			TenantID: tenantID,
			Version:  a.version,
			From:     a.at,
			Cause:    a.cause,
			Current:  i == len(h.activations)-1,
		}
		if i+1 < len(h.activations) {
			iv.To = h.activations[i+1].at
		}
		out[i] = iv
	}
	return out
}
