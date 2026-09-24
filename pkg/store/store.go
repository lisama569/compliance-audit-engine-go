// Package store 提供事件、判定结果与隔离记录的内存存储，
// 所有实现均为并发安全并按租户隔离。
package store

import (
	"sync"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// PutEventOutcome 是事件写入去重的结果。
type PutEventOutcome int

const (
	// PutAccepted 首次接收该幂等键。
	PutAccepted PutEventOutcome = iota
	// PutDuplicated 幂等键与内容指纹完全一致。
	PutDuplicated
	// PutConflict 同幂等键但内容指纹不同。
	PutConflict
)

// EventStore 存储已归并的有效事件。
type EventStore interface {
	// PutEvent 按幂等键写入；返回写入结果与已存在事件（冲突时）。
	PutEvent(e model.Event) (PutEventOutcome, model.Event, bool)
	GetEvent(tenantID, key string) (model.Event, bool)
	ListEvents(tenantID string) []model.Event
}

// ResultStore 存储事件在各规则版本下的判定结果。
type ResultStore interface {
	// PutResult 保存 (eventKey, ruleVersion) 维度的结果；历史版本结果不可被覆盖。
	PutResult(r model.Result) (overwrote bool)
	GetResult(tenantID, key string, ruleVersion int) (model.Result, bool)
	// ListResults 列出某租户在指定规则版本下的结果（按事件发生时间排序）。
	ListResults(tenantID string, ruleVersion int) []model.Result
}

// QuarantineStore 存储被拒绝/隔离的事件。
type QuarantineStore interface {
	PutQuarantined(q model.QuarantinedEvent)
	ListQuarantined(tenantID string) []model.QuarantinedEvent
}

// Memory 是进程内的并发安全存储实现。
type Memory struct {
	mu          sync.Mutex
	events      map[string]map[string]eventRec // tenantID -> eventKey -> rec
	results     map[string]map[string]map[int]model.Result
	quarantined map[string][]model.QuarantinedEvent
}

type eventRec struct {
	event model.Event
	hash  string
}
