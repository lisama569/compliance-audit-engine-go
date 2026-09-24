// Package replay implements historical recomputation. Re-evaluation always
// uses the rule set effective at the event's occurrence time, so releasing a
// new rule version never silently rewrites the past; the immutable original
// decision is kept and every recomputation is appended to a per-event history.
package replay

import (
	"fmt"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/rules"
)

// Store is the persistence surface required by Replayer.
type Store interface {
	GetEvent(tenantID, eventID string) (*model.Event, bool)
	ListEvents(tenantID string) []model.Event
	GetOriginalDecision(tenantID, eventID string) (*model.Decision, error)
	AppendRecomputed(d *model.Decision)
	SaveQuarantine(q *model.QuarantineRecord) *model.QuarantineRecord
	GetQuarantine(tenantID, eventID string) (*model.QuarantineRecord, error)
	RemoveQuarantine(tenantID, eventID string)
}

// resolveIfPending removes a quarantine record only when it is a PENDING
// record that recomputation is allowed to clear. REJECTED records (e.g.
// duplicate_conflict) survive any number of recomputations.
func (r *Replayer) resolveIfPending(tenantID, eventID string) {
	q, err := r.store.GetQuarantine(tenantID, eventID)
	if err != nil || q.Status != model.StatusPending {
		return
	}
	r.store.RemoveQuarantine(tenantID, eventID)
}

// RuleResolver resolves the rule set effective at a time.
type RuleResolver interface {
	EffectiveAt(tenantID string, t time.Time) (*model.RuleSet, error)
}

// Replayer recomputes historical decisions.
type Replayer struct {
	store    Store
	resolver RuleResolver
	now      func() time.Time
	sem      chan struct{} // bounds concurrent recomputation runs
}

// NewReplayer constructs a Replayer. maxConcurrency bounds in-flight workers.
func NewReplayer(store Store, resolver RuleResolver, maxConcurrency int) *Replayer {
	if maxConcurrency <= 0 {
		maxConcurrency = 4
	}
	return &Replayer{
		store:    store,
		resolver: resolver,
		now:      time.Now,
		sem:      make(chan struct{}, maxConcurrency),
	}
}

// SetClock overrides the clock.
func (r *Replayer) SetClock(now func() time.Time) { r.now = now }

// Report summarizes a recomputation run.
type Report struct {
	TenantID    string `json:"tenant_id"`
	Scanned     int    `json:"scanned"`
	Recomputed  int    `json:"recomputed"`
	Changed     int    `json:"changed"`
	Unchanged   int    `json:"unchanged"`
	Quarantined int    `json:"quarantined"`
	TriggeredBy string `json:"triggered_by"`
}

// RecomputeEvent recomputes one event against the rules effective at its
// occurrence time and appends the result to the event's recomputation history.
func (r *Replayer) RecomputeEvent(tenantID, eventID, triggeredBy string) (*model.Decision, error) {
	ev, ok := r.store.GetEvent(tenantID, eventID)
	if !ok {
		return nil, fmt.Errorf("%w: event %q", model.ErrNotFound, eventID)
	}

	rs, err := r.resolver.EffectiveAt(tenantID, ev.OccurredAt)
	if err != nil {
		// Still unresolved (e.g. gap never filled): keep it isolated/pending.
		q := &model.QuarantineRecord{
			Event:     *ev,
			Reason:    model.ReasonNoRuleAtTime,
			Detail:    fmt.Sprintf("recompute: %v", err),
			Status:    model.StatusPending,
			FirstSeen: r.now(),
			LastSeen:  r.now(),
		}
		r.store.SaveQuarantine(q)
		return nil, err
	}

	orig, err := r.store.GetOriginalDecision(tenantID, eventID)
	if err != nil {
		return nil, fmt.Errorf("original decision missing for %q: %w", eventID, err)
	}

	d := rules.Evaluate(rs, ev)
	d.TenantID = ev.TenantID
	d.EventID = ev.EventID
	d.EventSource = ev.Source
	d.EventType = ev.Type
	d.OccurredAt = ev.OccurredAt
	d.Outcome = "recomputed"
	d.TriggeredBy = triggeredBy
	d.Late = orig.Late
	d.Reordered = orig.Reordered
	d.DecidedAt = r.now()

	r.store.AppendRecomputed(d)
	r.resolveIfPending(tenantID, eventID) // a previously pending event now resolves
	return d, nil
}

// RecomputeTenant recomputes all stored events for a tenant sequentially
// within one run (cross-run concurrency is bounded by the semaphore).
func (r *Replayer) RecomputeTenant(tenantID string, triggeredBy string) (*Report, error) {
	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	default:
		return nil, model.ErrOverloaded
	}

	events := r.store.ListEvents(tenantID)
	rep := &Report{TenantID: tenantID, Scanned: len(events), TriggeredBy: triggeredBy}

	for _, ev := range events {
		ev := ev
		rs, err := r.resolver.EffectiveAt(tenantID, ev.OccurredAt)
		if err != nil {
			rep.Quarantined++
			r.store.SaveQuarantine(&model.QuarantineRecord{
				Event: ev, Reason: model.ReasonNoRuleAtTime,
				Detail: fmt.Sprintf("recompute: %v", err), Status: model.StatusPending,
				FirstSeen: r.now(), LastSeen: r.now(),
			})
			continue
		}
		orig, err := r.store.GetOriginalDecision(tenantID, ev.EventID)
		if err != nil {
			// Event claimed but never got an original decision (shouldn't happen);
			// count as quarantined rather than silently dropping.
			rep.Quarantined++
			continue
		}
		d := rules.Evaluate(rs, &ev)
		d.TenantID = ev.TenantID
		d.EventID = ev.EventID
		d.EventSource = ev.Source
		d.EventType = ev.Type
		d.OccurredAt = ev.OccurredAt
		d.Outcome = "recomputed"
		d.TriggeredBy = triggeredBy
		d.Late = orig.Late
		d.Reordered = orig.Reordered
		d.DecidedAt = r.now()
		r.store.AppendRecomputed(d)
		rep.Recomputed++
		if d.Verdict != orig.Verdict || d.RuleVersion != orig.RuleVersion || d.RuleID != orig.RuleID {
			rep.Changed++
		} else {
			rep.Unchanged++
		}
		r.resolveIfPending(tenantID, ev.EventID)
	}
	return rep, nil
}
