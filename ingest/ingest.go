// Package ingest implements idempotent event intake: validation, content-hash
// dedup, out-of-order/late detection and evaluation under the rule version
// effective at the event's occurrence time.
package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/rules"
	"github.com/lisama569/compliance-audit-engine-go/store"
)

// EventStore is the persistence surface required by Pipeline.
type EventStore interface {
	HasTenant(tenantID string) bool
	ClaimEvent(ev model.Event, hash string) (store.ClaimResult, error)
	AdvanceWatermark(ev model.Event)
	ReleaseClaim(tenantID, eventID, hash string)
	MarkPendingSeq(ev model.Event)
	GetEvent(tenantID, eventID string) (*model.Event, bool)
	SaveDecision(d *model.Decision) (bool, error)
	SaveQuarantine(q *model.QuarantineRecord) *model.QuarantineRecord
	CurrentDecision(tenantID, eventID string) (*model.Decision, error)
}

// RuleResolver resolves the rule set effective at a time.
type RuleResolver interface {
	EffectiveAt(tenantID string, t time.Time) (*model.RuleSet, error)
}

// Pipeline ingests events with idempotency, ordering and late-event handling.
type Pipeline struct {
	store         EventStore
	resolver      RuleResolver
	now           func() time.Time
	maxLate       time.Duration
	maxSkew       time.Duration
	lateThreshold time.Duration
}

// Config holds ingest-tuning parameters.
type Config struct {
	MaxLate       time.Duration // events older than now-MaxLate are rejected
	MaxSkew       time.Duration // events further in the future are rejected
	LateThreshold time.Duration // lag above which accepted events are flagged late
}

// NewPipeline constructs a Pipeline.
func NewPipeline(store EventStore, resolver RuleResolver, cfg Config) *Pipeline {
	if cfg.MaxLate == 0 {
		cfg.MaxLate = 72 * time.Hour
	}
	if cfg.MaxSkew == 0 {
		cfg.MaxSkew = 5 * time.Minute
	}
	if cfg.LateThreshold == 0 {
		cfg.LateThreshold = 5 * time.Minute
	}
	return &Pipeline{
		store: store, resolver: resolver,
		now: time.Now, maxLate: cfg.MaxLate, maxSkew: cfg.MaxSkew,
		lateThreshold: cfg.LateThreshold,
	}
}

// SetClock overrides the clock.
func (p *Pipeline) SetClock(now func() time.Time) { p.now = now }

// ContentHash computes the canonical content hash used for idempotent merge.
// It excludes ReceivedAt (delivery metadata) so identical re-deliveries merge.
func ContentHash(ev *model.Event) string {
	type dto struct {
		TenantID   string         `json:"tenant_id"`
		EventID    string         `json:"event_id"`
		Source     string         `json:"source"`
		Type       string         `json:"type"`
		OccurredAt time.Time      `json:"occurred_at"`
		Actor      string         `json:"actor"`
		Sequence   int64          `json:"sequence"`
		Payload    map[string]any `json:"payload"`
	}
	b, _ := json.Marshal(dto{
		TenantID: ev.TenantID, EventID: ev.EventID, Source: ev.Source,
		Type: ev.Type, OccurredAt: ev.OccurredAt, Actor: ev.Actor,
		Sequence: ev.Sequence, Payload: ev.Payload,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Ingest processes one event exactly-once semantically:
//
//	duplicate (same key+content) -> merged, original decision returned
//	same key, different content  -> quarantined: duplicate_conflict (rejected)
//	missing key fields           -> quarantined: missing_field (rejected)
//	unknown tenant               -> quarantined: unknown_tenant (rejected)
//	too old / too new            -> quarantined: too_late / future_event
//	out-of-order (ordered source, gap/old sequence) -> quarantined: out_of_order (pending)
//	no rules at occurrence time  -> quarantined: no_rule_at_occurrence_time (pending)
func (p *Pipeline) Ingest(ev *model.Event) (*model.IngestResult, error) {
	now := p.now()
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = now
	}

	// 1. Structural validation.
	if reason, detail := validateEvent(ev); reason != "" {
		return p.quarantine(ev, reason, detail, model.StatusRejected), nil
	}

	// 2. Known tenant.
	if !p.store.HasTenant(ev.TenantID) {
		return p.quarantine(ev, model.ReasonUnknownTenant,
			fmt.Sprintf("tenant %q is not registered", ev.TenantID), model.StatusRejected), nil
	}

	// 3. Temporal validity. "Late" is delivery lag: the event arrived
	// materially after it occurred (out-of-order vs. the source's watermark is
	// tracked separately below).
	deliveryLag := now.Sub(ev.OccurredAt)
	if deliveryLag > p.maxLate {
		return p.quarantine(ev, model.ReasonTooLate,
			fmt.Sprintf("event occurred %s ago, max allowed late window is %s",
				deliveryLag.Round(time.Second), p.maxLate), model.StatusRejected), nil
	}
	if skew := ev.OccurredAt.Sub(now); skew > p.maxSkew {
		return p.quarantine(ev, model.ReasonFutureEvent,
			fmt.Sprintf("event is %s in the future, max clock skew is %s",
				skew.Round(time.Second), p.maxSkew), model.StatusRejected), nil
	}
	late := deliveryLag > p.lateThreshold

	hash := ContentHash(ev)

	// Atomic claim: dedup only; ordering watermarks are committed later.
	// This single call is the authority under concurrency — there is no
	// separate read-fast-path that could race between two writers.
	claim, err := p.store.ClaimEvent(*ev, hash)
	if err != nil {
		return nil, err
	}
	switch claim.Outcome {
	case store.ClaimDuplicate:
		return p.alreadySeen(ev, hash), nil
	case store.ClaimConflict:
		// Either an accepted conclusion already exists for this ID with
		// different content, or another writer is concurrently claiming it
		// with different content. Either way: isolate, never overwrite.
		return p.quarantine(ev, model.ReasonDuplicateConflict,
			"same event id already exists with different content", model.StatusRejected), nil
	}

	// 5. Ordering semantics for sources that promise a monotonic sequence.
	reordered := false
	if claim.HadWatermark && ev.OccurredAt.Before(claim.PrevWatermark) {
		late = true
	}
	if ev.Ordered && claim.HadSeq && ev.Sequence < claim.PrevSeq {
		// A strictly older sequence after newer ones have been accepted is a
		// reordering that must not rewrite anything; park it pending.
		p.store.MarkPendingSeq(*ev)
		p.store.ReleaseClaim(ev.TenantID, ev.EventID, hash)
		return p.quarantine(ev, model.ReasonOutOfOrder,
			fmt.Sprintf("sequence %d arrived after high-water mark %d", ev.Sequence, claim.PrevSeq),
			model.StatusPending), nil
	}
	if ev.Ordered && len(claim.MissingSeqs) > 0 {
		// Gap: one or more predecessors are parked pending. The event is
		// still evaluable, but flagged so auditors can chase the gap.
		reordered = true
	}

	// 6. Resolve the rule version effective AT OCCURRENCE TIME (history-safe).
	rs, err := p.resolver.EffectiveAt(ev.TenantID, ev.OccurredAt)
	if err != nil {
		p.store.ReleaseClaim(ev.TenantID, ev.EventID, hash)
		return p.quarantine(ev, model.ReasonNoRuleAtTime,
			fmt.Sprintf("no rule set effective at %s: %v",
				ev.OccurredAt.UTC().Format(time.RFC3339), err), model.StatusPending), nil
	}

	// 7. Evaluate and persist the immutable original decision.
	d := rules.Evaluate(rs, ev)
	d.TenantID = ev.TenantID
	d.EventID = ev.EventID
	d.EventSource = ev.Source
	d.EventType = ev.Type
	d.OccurredAt = ev.OccurredAt
	d.Outcome = "original"
	d.Late = late
	d.Reordered = reordered
	d.DecidedAt = now

	if _, err := p.store.SaveDecision(d); err != nil {
		return nil, err
	}
	// 8. Only now, after a valid conclusion exists, commit ordering state.
	p.store.AdvanceWatermark(*ev)
	return &model.IngestResult{Accepted: true, EventID: ev.EventID, Decision: d}, nil
}

// alreadySeen handles a re-delivered event: identical content merges
// (idempotent), different content is quarantined with a distinct reason.
func (p *Pipeline) alreadySeen(ev *model.Event, hash string) *model.IngestResult {
	stored, _ := p.store.GetEvent(ev.TenantID, ev.EventID)
	if stored != nil && ContentHash(stored) == hash {
		d, _ := p.store.CurrentDecision(ev.TenantID, ev.EventID)
		return &model.IngestResult{Accepted: true, Duplicate: true, EventID: ev.EventID, Decision: d}
	}
	return p.quarantine(ev, model.ReasonDuplicateConflict,
		"same event id already exists with different content", model.StatusRejected)
}

func (p *Pipeline) quarantine(ev *model.Event, reason, detail, status string) *model.IngestResult {
	q := &model.QuarantineRecord{
		Event: *ev, Reason: reason, Detail: detail, Status: status,
		FirstSeen: ev.ReceivedAt, LastSeen: ev.ReceivedAt,
	}
	saved := p.store.SaveQuarantine(q)
	return &model.IngestResult{Accepted: false, EventID: ev.EventID, Quarantine: saved}
}

func validateEvent(ev *model.Event) (reason, detail string) {
	if ev.TenantID == "" {
		return model.ReasonMissingField, "tenant_id is required"
	}
	if ev.EventID == "" {
		return model.ReasonMissingField, "event_id is required"
	}
	if ev.Source == "" {
		return model.ReasonMissingField, "source is required"
	}
	if ev.Type == "" {
		return model.ReasonMissingField, "type is required"
	}
	if ev.OccurredAt.IsZero() {
		return model.ReasonMissingField, "occurred_at is required"
	}
	if ev.Payload == nil {
		return model.ReasonInvalidPayload, "payload must not be null"
	}
	return "", ""
}
