package store

import (
	"sort"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// NewMemory 创建空的内存存储。
func NewMemory() *Memory {
	return &Memory{
		events:      make(map[string]map[string]eventRec),
		results:     make(map[string]map[string]map[int]model.Result),
		quarantined: make(map[string][]model.QuarantinedEvent),
	}
}

// PutEvent 按幂等键写入。
// 首次写入返回 PutAccepted；键与内容指纹均一致返回 PutDuplicated；
// 同键不同指纹返回 PutConflict（原记录保持不变，绝不静默改写）。
func (m *Memory) PutEvent(e model.Event) (PutEventOutcome, model.Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	byTenant := m.events[e.TenantID]
	if byTenant == nil {
		byTenant = make(map[string]eventRec)
		m.events[e.TenantID] = byTenant
	}
	key := e.Key()
	if existing, ok := byTenant[key]; ok {
		if existing.hash == e.Fingerprint() {
			return PutDuplicated, existing.event, true
		}
		return PutConflict, existing.event, true
	}
	byTenant[key] = eventRec{event: e, hash: e.Fingerprint()}
	return PutAccepted, e, false
}

func (m *Memory) GetEvent(tenantID, key string) (model.Event, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if rec, ok := m.events[tenantID][key]; ok {
		return rec.event, true
	}
	return model.Event{}, false
}

// ListEvents 返回某租户全部有效事件，按 (OccurredAt, Key) 排序以保证确定性。
func (m *Memory) ListEvents(tenantID string) []model.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]model.Event, 0, len(m.events[tenantID]))
	for _, rec := range m.events[tenantID] {
		out = append(out, rec.event)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].OccurredAt.Before(out[j].OccurredAt)
		}
		return out[i].Key() < out[j].Key()
	})
	return out
}

// PutResult 保存 (eventKey, ruleVersion) 维度的不可变结果。
// 若该槽位已有结果则拒绝覆盖（返回 overwrote=true），调用方应保留原件。
func (m *Memory) PutResult(r model.Result) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	byTenant := m.results[r.TenantID]
	if byTenant == nil {
		byTenant = make(map[string]map[int]model.Result)
		m.results[r.TenantID] = byTenant
	}
	byKey := byTenant[r.EventKey]
	if byKey == nil {
		byKey = make(map[int]model.Result)
		byTenant[r.EventKey] = byKey
	}
	if _, exists := byKey[r.RuleVersion]; exists {
		return true
	}
	byKey[r.RuleVersion] = r
	return false
}

func (m *Memory) GetResult(tenantID, key string, ruleVersion int) (model.Result, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if byKey, ok := m.results[tenantID][key]; ok {
		if r, ok := byKey[ruleVersion]; ok {
			return r, true
		}
	}
	return model.Result{}, false
}

func (m *Memory) ListResults(tenantID string, ruleVersion int) []model.Result {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []model.Result
	for _, byVersion := range m.results[tenantID] {
		if r, ok := byVersion[ruleVersion]; ok {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Event.OccurredAt.Equal(out[j].Event.OccurredAt) {
			return out[i].Event.OccurredAt.Before(out[j].Event.OccurredAt)
		}
		return out[i].EventKey < out[j].EventKey
	})
	return out
}

// PutQuarantined 追加隔离记录；同一键/原因的记录允许重复出现以保留重放痕迹。
func (m *Memory) PutQuarantined(q model.QuarantinedEvent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.quarantined[q.Event.TenantID] = append(m.quarantined[q.Event.TenantID], q)
}

func (m *Memory) ListQuarantined(tenantID string) []model.QuarantinedEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	src := m.quarantined[tenantID]
	out := make([]model.QuarantinedEvent, len(src))
	copy(out, src)
	return out
}
