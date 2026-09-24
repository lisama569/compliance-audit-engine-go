package model

// Quarantine statuses.
const (
	StatusRejected = "rejected" // definitively unusable
	StatusPending  = "pending"  // may be resolved later (e.g. rule gap)
)

// Distinguishable quarantine reasons.
const (
	// Rejected.
	ReasonMissingField      = "missing_field"
	ReasonInvalidPayload    = "invalid_payload"
	ReasonDuplicateConflict = "duplicate_conflict" // same dedup key, different content
	ReasonTooLate           = "too_late"
	ReasonFutureEvent       = "future_event"
	ReasonUnknownTenant     = "unknown_tenant"

	// Pending.
	ReasonOutOfOrder   = "out_of_order" // predecessor not seen yet
	ReasonNoRuleAtTime = "no_rule_at_occurrence_time"
)
