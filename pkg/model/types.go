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
