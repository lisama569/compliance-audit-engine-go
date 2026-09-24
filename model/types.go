// Package model defines the core domain types for the compliance audit engine.
package model

import (
	"errors"
	"time"
)

// Event is a single audit event produced by some source for a tenant.
type Event struct {
	TenantID   string         `json:"tenant_id"`
	EventID    string         `json:"event_id"`
	Source     string         `json:"source"`
	Type       string         `json:"type"`
	OccurredAt time.Time      `json:"occurred_at"`
	ReceivedAt time.Time      `json:"received_at"`
	Actor      string         `json:"actor"`
	Sequence   int64          `json:"sequence,omitempty"` // source-local sequence, used when Ordered is true
	Ordered    bool           `json:"ordered,omitempty"`  // source promises monotonic Sequence
	Payload    map[string]any `json:"payload"`
}

// RuleSet is a versioned, immutable set of rules effective for a time range.
type RuleSet struct {
	ID            string    `json:"id"`
	TenantID      string    `json:"tenant_id"` // empty means global
	Version       int       `json:"version"`
	PublishedBy   string    `json:"published_by"`
	PublishedAt   time.Time `json:"published_at"`
	EffectiveFrom time.Time `json:"effective_from"`
	EffectiveTo   time.Time `json:"effective_to"` // zero means open-ended
	Rules         []Rule    `json:"rules"`
	Checksum      string    `json:"checksum"`
	Status        string    `json:"status"`
}

// Rule is a single evaluation rule.
type Rule struct {
	ID         string      `json:"id"`
	EventTypes []string    `json:"event_types"`
	Priority   int         `json:"priority"`
	Name       string      `json:"name"`
	Conditions []Condition `json:"conditions"`
	Verdict    string      `json:"verdict"`
	Reason     string      `json:"reason"`
}

// Condition matches against an event payload.
type Condition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    any    `json:"value"`
}

// Decision is the evaluation outcome of an event under a specific rule version.
type Decision struct {
	TenantID    string    `json:"tenant_id"`
	EventID     string    `json:"event_id"`
	EventSource string    `json:"event_source"`
	EventType   string    `json:"event_type"`
	OccurredAt  time.Time `json:"occurred_at"`
	RuleSetID   string    `json:"rule_set_id"`
	RuleVersion int       `json:"rule_version"`
	RuleID      string    `json:"rule_id"`
	Verdict     string    `json:"verdict"`
	Reason      string    `json:"reason"`
	Basis       []string  `json:"basis"`
	Outcome     string    `json:"outcome"` // original/recomputed
	Late        bool      `json:"late"`
	Reordered   bool      `json:"reordered"`
	TriggeredBy string    `json:"triggered_by,omitempty"` // who triggered a recompute
	DecidedAt   time.Time `json:"decided_at"`
}

// QuarantineRecord holds an event that could not be merged/processed.
type QuarantineRecord struct {
	Event     Event     `json:"event"`
	Reason    string    `json:"reason"`
	Detail    string    `json:"detail"`
	Status    string    `json:"status"` // rejected / pending
	SeenCount int       `json:"seen_count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// IngestResult summarizes an ingest attempt.
type IngestResult struct {
	Accepted   bool              `json:"accepted"`
	Duplicate  bool              `json:"duplicate"`
	EventID    string            `json:"event_id"`
	Decision   *Decision         `json:"decision,omitempty"`
	Quarantine *QuarantineRecord `json:"quarantine,omitempty"`
}

// Rule set statuses.
const (
	RuleSetStatusActive     = "active"
	RuleSetStatusSuperseded = "superseded"
	RuleSetStatusRolledBack = "rolled_back"
)

// Verdicts.
const (
	VerdictCompliant    = "compliant"
	VerdictNonCompliant = "non_compliant"
	VerdictNeedsReview  = "needs_review"
)

// Operators.
const (
	OpEq        = "eq"
	OpNe        = "ne"
	OpIn        = "in"
	OpNotIn     = "not_in"
	OpGt        = "gt"
	OpGte       = "gte"
	OpLt        = "lt"
	OpLte       = "lte"
	OpExists    = "exists"
	OpNotExists = "not_exists"
	OpContains  = "contains"
)

// Common errors.
var (
	ErrNotFound      = errors.New("not found")
	ErrForbidden     = errors.New("forbidden")
	ErrOverloaded    = errors.New("overloaded: rate limit exceeded")
	ErrInvalidEvent  = errors.New("invalid event")
	ErrInvalidRule   = errors.New("invalid rule set")
	ErrConflict      = errors.New("conflict")
	ErrAlreadyExists = errors.New("already exists")
)
