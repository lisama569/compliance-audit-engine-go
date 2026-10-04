package rules

import (
	"sort"
	"sync"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// activation 是一次“某版本自某时刻起生效”的记录（发布或回滚触发）。
type activation struct {
	version int
	from    time.Time
	cause   model.ActivationCause
}

// tenantHistory 保存某租户不可变的已发布版本序列（按版本号升序）
// 以及生效记录序列（按发生先后追加，同一时刻后者覆盖前者）。
type tenantHistory struct {
	released    []model.RuleSet // 已发布（含已回滚）的不可变快照
	current     int             // 当前生效版本在 released 中的下标
	activations []activation    // 生效时间轴的原始记录
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
	h.activations = append(h.activations, activation{
		version: stored.Version, from: stored.PublishedAt, cause: model.CausePublish,
	})
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
// 回滚只移动“当前指针”并追加一条生效记录，不删除任何历史版本；
// 再次发布将在序列尾部追加新版本。回滚生效时刻起的新事件按回滚后版本判定。
// 没有更早版本可回滚时返回 ErrNothingToRollback，状态完全不变。
func (r *memoryRegistry) Rollback(tenantID string) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil || h.current <= 0 {
		return model.RuleSet{}, ErrNothingToRollback
	}
	h.current--
	target := h.released[h.current]
	h.activations = append(h.activations, activation{
		version: target.Version, from: r.clock().UTC(), cause: model.CauseRollback,
	})
	return cloneRuleSet(target), nil
}

// RollbackTarget 返回“若现在回滚”将生效的历史版本；不修改任何状态。
func (r *memoryRegistry) RollbackTarget(tenantID string) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil || h.current <= 0 {
		return model.RuleSet{}, ErrNothingToRollback
	}
	return cloneRuleSet(h.released[h.current-1]), nil
}

// EffectiveAt 选取 t 时刻真正生效的版本：取生效时刻不晚于 t 的最后一条
// 生效记录（发布或回滚）。同一时刻存在多条记录时，后发生者生效，
// 因此任意时刻有且仅有一个生效版本。t 早于首次生效时返回 ErrNoRuleSet。
func (r *memoryRegistry) EffectiveAt(tenantID string, t time.Time) (model.RuleSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil {
		return model.RuleSet{}, ErrNoRuleSet
	}
	picked := -1
	for i, a := range h.activations {
		if !a.from.After(t) {
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

// Timeline 把生效记录展开为半开区间序列：第 i 段为
// [activations[i].from, activations[i+1].from)，最后一段 EffectiveTo 为零值
// 表示至今生效。相邻记录同刻时前一段为零长区间，不会产生重叠，
// 任意时刻至多命中一个版本。
func (r *memoryRegistry) Timeline(tenantID string) []model.TimelineEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	h := r.tenants[tenantID]
	if h == nil {
		return nil
	}
	out := make([]model.TimelineEntry, len(h.activations))
	for i, a := range h.activations {
		e := model.TimelineEntry{
			Version:       a.version,
			EffectiveFrom: a.from,
			Cause:         a.cause,
			Current:       i == len(h.activations)-1,
		}
		if i+1 < len(h.activations) {
			e.EffectiveTo = h.activations[i+1].from
		}
		out[i] = e
	}
	return out
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
