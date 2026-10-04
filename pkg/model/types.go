// Package model 定义合规审计引擎的核心领域类型：
// 审计事件、版本化规则集、判定结果以及隔离/拒绝记录。
package model

import "time"

// Decision 是单条事件依据某一版本规则集得到的判定结论。
type Decision string

const (
	// DecisionAllow 合规通过。
	DecisionAllow Decision = "ALLOW"
	// DecisionDeny 判定违规。
	DecisionDeny Decision = "DENY"
	// DecisionReview 证据不足或命中人工复核条件，需人工介入。
	DecisionReview Decision = "REVIEW"
)

// Event 是一条多来源审计事件。
//
// 幂等键 (TenantID, Source, EventID) 唯一标识一条业务事件；
// OccurredAt 为事件实际发生时间（用于选择生效规则版本与乱序判定），
// ReceivedAt 为系统接收时间（由接入层在归并时记录）。
type Event struct {
	TenantID    string            `json:"tenant_id"`
	Source      string            `json:"source"`
	EventID     string            `json:"event_id"`
	OccurredAt  time.Time         `json:"occurred_at"`
	ReceivedAt  time.Time         `json:"received_at"`
	Action      string            `json:"action"`
	ResourceID  string            `json:"resource_id"`
	Actor       string            `json:"actor"`
	AmountCents int64             `json:"amount_cents"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// Key 返回事件的幂等键。
func (e Event) Key() string { return e.TenantID + "|" + e.Source + "|" + e.EventID }

// RuleOp 是规则条件支持的操作符。
type RuleOp string

const (
	OpGTE RuleOp = "GTE" // AmountCents >= Value
	OpLTE RuleOp = "LTE" // AmountCents <= Value
	OpEQ  RuleOp = "EQ"  // Action/ResourceID 等于 Value
)

// Rule 是一条单版本规则；同一 RuleID 在不同 RuleSetVersion 中可被修订。
type Rule struct {
	RuleID   string   `json:"rule_id"`
	Scope    string   `json:"scope"`
	Action   string   `json:"action"`
	Op       RuleOp   `json:"op"`
	Field    string   `json:"field"`
	Value    string   `json:"value"`
	Decision Decision `json:"decision"`
	Reason   string   `json:"reason"`
}

// RuleSet 是一个不可变的版本化规则集快照。
type RuleSet struct {
	TenantID    string    `json:"tenant_id"`
	Version     int       `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	Note        string    `json:"note"`
	Rules       []Rule    `json:"rules"`
}

// Evidence 记录一条结论命中的规则，作为判定依据。
type Evidence struct {
	RuleID string `json:"rule_id"`
	Scope  string `json:"scope"`
	Op     RuleOp `json:"op"`
	Field  string `json:"field"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// Result 是单条事件在某一规则版本下的判定结果（不可变）。
type Result struct {
	TenantID     string     `json:"tenant_id"`
	EventKey     string     `json:"event_key"`
	Event        Event      `json:"event"`
	Decision     Decision   `json:"decision"`
	RuleVersion  int        `json:"rule_version"`
	MatchedRules []Evidence `json:"matched_rules"`
	EvaluatedAt  time.Time  `json:"evaluated_at"`
	Recomputed   bool       `json:"recomputed"`
}

// ActivationCause 标识一次规则版本生效记录的来源。
type ActivationCause string

const (
	// CausePublish 由发布新版本触发的生效记录。
	CausePublish ActivationCause = "publish"
	// CauseRollback 由回滚到历史版本触发的生效记录。
	CauseRollback ActivationCause = "rollback"
)

// TimelineEntry 是规则版本生效时间轴上的一段半开区间
// [EffectiveFrom, EffectiveTo)：区间内任意时刻有且仅有本版本生效，
// EffectiveTo 为零值表示该版本至今仍在生效。
type TimelineEntry struct {
	Version       int             `json:"version"`
	EffectiveFrom time.Time       `json:"effective_from"`
	EffectiveTo   time.Time       `json:"effective_to,omitempty"`
	Cause         ActivationCause `json:"cause"`
	Current       bool            `json:"current"`
}

// DryRunScenario 标识预演场景：发布候选规则集，或回滚到上一版本。
type DryRunScenario string

const (
	// DryRunPublish 预演“若发布该候选规则集”。
	DryRunPublish DryRunScenario = "publish"
	// DryRunRollback 预演“若回滚到上一历史版本”。
	DryRunRollback DryRunScenario = "rollback"
)

// DryRunItem 是单条已归并事件在预演规则下的结论对比（纯临时结论，不落库）。
type DryRunItem struct {
	EventKey        string     `json:"event_key"`
	Event           Event      `json:"event"`
	BaseVersion     int        `json:"base_version"`     // 对比基准：当前生效版本
	BaseDecision    Decision   `json:"base_decision"`    // 基准版本下的既有/应有结论
	PreviewDecision Decision   `json:"preview_decision"` // 候选规则下的临时结论
	Changed         bool       `json:"changed"`          // 判定是否发生变化
	MatchedRules    []Evidence `json:"matched_rules"`    // 预演命中依据
}

// DryRunReport 是一次规则变更预演的完整结果。
// 预演只读：不修改生效规则、不写入任何判定结果槽位。
type DryRunReport struct {
	TenantID         string         `json:"tenant_id"`
	Scenario         DryRunScenario `json:"scenario"`
	BaseVersion      int            `json:"base_version"`      // 当前生效版本号
	CandidateVersion int            `json:"candidate_version"` // 预演版本号（发布=下一版本号，回滚=目标历史版本号）
	TotalEvents      int            `json:"total_events"`
	ChangedCount     int            `json:"changed_count"`
	Items            []DryRunItem   `json:"items"`
}

// RejectReason 描述无法归并事件的可区分原因。
type RejectReason string

const (
	// RejectDuplicate 完全重复：幂等键与内容指纹均一致。
	RejectDuplicate RejectReason = "DUPLICATE"
	// RejectConflict 同键不同内容：潜在重放改写，拒绝并入有效记录。
	RejectConflict RejectReason = "CONFLICT"
	// RejectLate 迟到超过宽限窗口，隔离待人工处理，不静默改写结论。
	RejectLate RejectReason = "LATE"
	// RejectInvalid 关键字段缺失等非法事件。
	RejectInvalid RejectReason = "INVALID"
)

// QuarantinedEvent 是被隔离/拒绝的事件及其原因。
type QuarantinedEvent struct {
	Event      Event        `json:"event"`
	Reason     RejectReason `json:"reason"`
	Detail     string       `json:"detail"`
	ReceivedAt time.Time    `json:"received_at"`
}
