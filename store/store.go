// Package store provides in-memory, concurrency-safe persistence for the
// compliance audit engine. A single RWMutex gives a simple, auditable
// serializability story: all multi-map invariants are updated under one lock.
package store

import (
	"sort"
	"sync"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
)

// Store is the in-memory persistence facade.
type Store struct {
	mu sync.RWMutex

	tenants map[string]bool

	// events: tenantID -> eventID -> event
	events map[string]map[string]model.Event
	// hashes: tenantID -> eventID -> content hash (idempotency key)
	hashes map[string]map[string]string
	// watermarks: tenantID|source -> highest occurred_at seen
	watermarks map[string]time.Time
	// sequences: tenantID|source -> highest sequence number seen
	sequences map[string]int64
	// pendingSeqs: tenantID|source -> set of sequence numbers quarantined as
	// out-of-order and not yet resolved (used to detect gaps precisely).
	pendingSeqs map[string]map[int64]bool

	// decisions: tenantID -> eventID -> original (immutable) decision
	decisions map[string]map[string]*model.Decision
	// recomputed: tenantID -> eventID -> recomputation history (append only)
	recomputed map[string]map[string][]*model.Decision

	// rulesets: scopeKey ("" = global) -> version -> rule set
	rulesets map[string]map[int]*model.RuleSet

	// quarantine: tenantID -> eventID -> record
	quarantine map[string]map[string]*model.QuarantineRecord
}

// New creates an empty Store. The global tenant scope is always registered.
func New() *Store {
	return &Store{
		tenants:     map[string]bool{"": true},
		events:      map[string]map[string]model.Event{},
		hashes:      map[string]map[string]string{},
		watermarks:  map[string]time.Time{},
		sequences:   map[string]int64{},
		pendingSeqs: map[string]map[int64]bool{},
		decisions:   map[string]map[string]*model.Decision{},
		recomputed:  map[string]map[string][]*model.Decision{},
		rulesets:    map[string]map[int]*model.RuleSet{},
		quarantine:  map[string]map[string]*model.QuarantineRecord{},
	}
}

// ---------- tenants ----------

// RegisterTenant registers a tenant so that its events are accepted.
func (s *Store) RegisterTenant(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tenants[tenantID] = true
}

// HasTenant reports whether a tenant is known.
func (s *Store) HasTenant(tenantID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tenants[tenantID]
}

// ---------- events / idempotent claim ----------

// ClaimOutcome is the result of atomically claiming an event.
type ClaimOutcome int

const (
	ClaimNew       ClaimOutcome = iota // first time seen
	ClaimDuplicate                     // same dedup key, same content hash
	ClaimConflict                      // same dedup key, different content
)

// ClaimResult describes the claim and the ordering context at claim time.
type ClaimResult struct {
	Outcome       ClaimOutcome
	PrevWatermark time.Time
	HadWatermark  bool
	PrevSeq       int64
	HadSeq        bool
	// MissingSeqs holds pending predecessor sequence numbers strictly below
	// the claimed event's sequence (gap detection).
	MissingSeqs []int64
}

// ClaimEvent atomically registers an event for idempotent dedup. The content
// hash is the caller's canonical hash of the event body. Ordering watermarks
// are NOT advanced here; callers commit them with AdvanceWatermark only after
// the event is fully accepted, so quarantined events do not poison the order
// tracking of later events.
func (s *Store) ClaimEvent(ev model.Event, hash string) (ClaimResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	wk := ev.TenantID + "|" + ev.Source
	res := ClaimResult{Outcome: ClaimNew}
	if wm, ok := s.watermarks[wk]; ok {
		res.PrevWatermark, res.HadWatermark = wm, true
	}
	if ps, ok := s.sequences[wk]; ok {
		res.PrevSeq, res.HadSeq = ps, true
	}

	if _, ok := s.events[ev.TenantID][ev.EventID]; ok {
		if s.hashes[ev.TenantID][ev.EventID] == hash {
			res.Outcome = ClaimDuplicate
		} else {
			res.Outcome = ClaimConflict
		}
		return res, nil
	}

	// Gap detection: report pending predecessors below this sequence.
	if ev.Ordered {
		for seq := range s.pendingSeqs[wk] {
			if seq < ev.Sequence {
				res.MissingSeqs = append(res.MissingSeqs, seq)
			}
		}
		sort.Slice(res.MissingSeqs, func(i, j int) bool { return res.MissingSeqs[i] < res.MissingSeqs[j] })
	}

	if s.events[ev.TenantID] == nil {
		s.events[ev.TenantID] = map[string]model.Event{}
		s.hashes[ev.TenantID] = map[string]string{}
	}
	s.events[ev.TenantID][ev.EventID] = ev
	s.hashes[ev.TenantID][ev.EventID] = hash
	return res, nil
}

// MarkPendingSeq records that sequence seq for a source is quarantined
// pending (awaiting resolution).
func (s *Store) MarkPendingSeq(ev model.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !ev.Ordered {
		return
	}
	wk := ev.TenantID + "|" + ev.Source
	if s.pendingSeqs[wk] == nil {
		s.pendingSeqs[wk] = map[int64]bool{}
	}
	s.pendingSeqs[wk][ev.Sequence] = true
}

// AdvanceWatermark commits the per-source ordering watermark and sequence for
// an accepted event using max semantics, so late replays never move them
// backwards.
func (s *Store) AdvanceWatermark(ev model.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wk := ev.TenantID + "|" + ev.Source
	if wm, ok := s.watermarks[wk]; !ok || ev.OccurredAt.After(wm) {
		s.watermarks[wk] = ev.OccurredAt
	}
	if ev.Ordered {
		if ps, ok := s.sequences[wk]; !ok || ev.Sequence > ps {
			s.sequences[wk] = ev.Sequence
		}
	}
}

// ReleaseClaim rolls back a ClaimEvent when the event is subsequently
// quarantined, so a rejected/pending event does not permanently occupy the
// dedup key. Its quarantine record remains the authoritative marker.
func (s *Store) ReleaseClaim(tenantID, eventID, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h, ok := s.hashes[tenantID][eventID]; ok && h == hash {
		delete(s.events[tenantID], eventID)
		delete(s.hashes[tenantID], eventID)
	}
}

// GetEvent returns a stored event.
func (s *Store) GetEvent(tenantID, eventID string) (*model.Event, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev, ok := s.events[tenantID][eventID]
	if !ok {
		return nil, false
	}
	cp := ev
	return &cp, true
}

// ListEvents returns copies of all events for a tenant, ordered by event ID.
func (s *Store) ListEvents(tenantID string) []model.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.events[tenantID]))
	for id := range s.events[tenantID] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]model.Event, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.events[tenantID][id])
	}
	return out
}

// ---------- decisions ----------

// SaveDecision stores the immutable original decision for an event.
// A second save for the same event is ignored: the first conclusion wins.
func (s *Store) SaveDecision(d *model.Decision) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.decisions[d.TenantID] == nil {
		s.decisions[d.TenantID] = map[string]*model.Decision{}
	}
	if _, exists := s.decisions[d.TenantID][d.EventID]; exists {
		return false, nil
	}
	cp := *d
	s.decisions[d.TenantID][d.EventID] = &cp
	return true, nil
}

// GetOriginalDecision returns the immutable original decision.
func (s *Store) GetOriginalDecision(tenantID, eventID string) (*model.Decision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.decisions[tenantID][eventID]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *d
	return &cp, nil
}

// AppendRecomputed appends a recomputed decision to the event's history.
func (s *Store) AppendRecomputed(d *model.Decision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recomputed[d.TenantID] == nil {
		s.recomputed[d.TenantID] = map[string][]*model.Decision{}
	}
	cp := *d
	s.recomputed[d.TenantID][d.EventID] = append(s.recomputed[d.TenantID][d.EventID], &cp)
}

// RecomputeHistory returns the recomputation history of an event, oldest first.
func (s *Store) RecomputeHistory(tenantID, eventID string) []*model.Decision {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hist := s.recomputed[tenantID][eventID]
	out := make([]*model.Decision, len(hist))
	for i, d := range hist {
		cp := *d
		out[i] = &cp
	}
	return out
}

// CurrentDecision returns the currently effective decision: the latest
// recomputation if present, otherwise the immutable original.
func (s *Store) CurrentDecision(tenantID, eventID string) (*model.Decision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if hist := s.recomputed[tenantID][eventID]; len(hist) > 0 {
		cp := *hist[len(hist)-1]
		return &cp, nil
	}
	if d, ok := s.decisions[tenantID][eventID]; ok {
		cp := *d
		return &cp, nil
	}
	return nil, model.ErrNotFound
}

// DecisionFilter narrows decision queries.
type DecisionFilter struct {
	EventID   string
	EventType string
	Source    string
	Verdict   string
	Outcome   string
	Since     time.Time
	Until     time.Time
	Limit     int
}

// QueryDecisions lists current decisions for a tenant under a filter.
// It never returns data for any other tenant.
func (s *Store) QueryDecisions(tenantID string, f DecisionFilter) ([]*model.Decision, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.decisions[tenantID]))
	for id := range s.decisions[tenantID] {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]*model.Decision, 0)
	for _, id := range ids {
		var d *model.Decision
		if hist := s.recomputed[tenantID][id]; len(hist) > 0 {
			d = hist[len(hist)-1]
		} else {
			d = s.decisions[tenantID][id]
		}
		if !matchFilter(d, f) {
			continue
		}
		cp := *d
		out = append(out, &cp)
		if f.Limit > 0 && len(out) >= f.Limit {
			break
		}
	}
	return out, nil
}

func matchFilter(d *model.Decision, f DecisionFilter) bool {
	if f.EventID != "" && d.EventID != f.EventID {
		return false
	}
	if f.EventType != "" && d.EventType != f.EventType {
		return false
	}
	if f.Source != "" && d.EventSource != f.Source {
		return false
	}
	if f.Verdict != "" && d.Verdict != f.Verdict {
		return false
	}
	if f.Outcome != "" && d.Outcome != f.Outcome {
		return false
	}
	if !f.Since.IsZero() && d.OccurredAt.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && d.OccurredAt.After(f.Until) {
		return false
	}
	return true
}

// ---------- rule sets ----------

// SaveRuleSet upserts a rule set under its scope key and version.
func (s *Store) SaveRuleSet(rs *model.RuleSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := rs.TenantID
	if s.rulesets[key] == nil {
		s.rulesets[key] = map[int]*model.RuleSet{}
	}
	cp := *rs
	cp.Rules = append([]model.Rule(nil), rs.Rules...)
	s.rulesets[key][rs.Version] = &cp
	return nil
}

// GetRuleSet fetches one version within a scope.
func (s *Store) GetRuleSet(scopeKey string, version int) (*model.RuleSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rs, ok := s.rulesets[scopeKey][version]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *rs
	cp.Rules = append([]model.Rule(nil), rs.Rules...)
	return &cp, nil
}

// ListRuleSets returns all versions within a scope, ascending by version.
func (s *Store) ListRuleSets(scopeKey string) ([]*model.RuleSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	versions := make([]int, 0, len(s.rulesets[scopeKey]))
	for v := range s.rulesets[scopeKey] {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	out := make([]*model.RuleSet, 0, len(versions))
	for _, v := range versions {
		rs := s.rulesets[scopeKey][v]
		cp := *rs
		cp.Rules = append([]model.Rule(nil), rs.Rules...)
		out = append(out, &cp)
	}
	return out, nil
}

// LatestVersion returns the highest version number in a scope, or 0.
func (s *Store) LatestVersion(scopeKey string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	max := 0
	for v := range s.rulesets[scopeKey] {
		if v > max {
			max = v
		}
	}
	return max
}

// EffectiveRuleSet returns the rule set effective at time t in the scope,
// or ErrNotFound if none covers t.
func (s *Store) EffectiveRuleSet(scopeKey string, t time.Time) (*model.RuleSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *model.RuleSet
	for _, rs := range s.rulesets[scopeKey] {
		// Time ranges alone encode validity: even a superseded/rolled-back
		// set must still be resolvable for points in time when it was active.
		if t.Before(rs.EffectiveFrom) {
			continue
		}
		if !rs.EffectiveTo.IsZero() && !t.Before(rs.EffectiveTo) {
			continue
		}
		if best == nil || rs.EffectiveFrom.After(best.EffectiveFrom) {
			best = rs
		}
	}
	if best == nil {
		return nil, model.ErrNotFound
	}
	cp := *best
	cp.Rules = append([]model.Rule(nil), best.Rules...)
	return &cp, nil
}

// CloseActiveRange marks the current open-ended active set as superseded at t.
func (s *Store) CloseActiveRange(scopeKey string, t time.Time) {
	s.closeActiveRange(scopeKey, t, model.RuleSetStatusSuperseded)
}

// RollbackActiveRange marks the current open-ended active set as rolled_back.
func (s *Store) RollbackActiveRange(scopeKey string, t time.Time) {
	s.closeActiveRange(scopeKey, t, model.RuleSetStatusRolledBack)
}

func (s *Store) closeActiveRange(scopeKey string, t time.Time, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rs := range s.rulesets[scopeKey] {
		if rs.Status == model.RuleSetStatusActive && rs.EffectiveTo.IsZero() {
			rs.EffectiveTo = t
			rs.Status = status
		}
	}
}

// ---------- quarantine ----------

// SaveQuarantine upserts a quarantine record, bumping seen counters.
func (s *Store) SaveQuarantine(q *model.QuarantineRecord) *model.QuarantineRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quarantine[q.Event.TenantID] == nil {
		s.quarantine[q.Event.TenantID] = map[string]*model.QuarantineRecord{}
	}
	if existing, ok := s.quarantine[q.Event.TenantID][q.Event.EventID]; ok {
		existing.SeenCount++
		existing.LastSeen = q.Event.ReceivedAt
		// The first distinguished reason is never silently overwritten.
		cp := *existing
		return &cp
	}
	cp := *q
	cp.SeenCount = 1
	s.quarantine[q.Event.TenantID][q.Event.EventID] = &cp
	out := cp
	return &out
}

// GetQuarantine fetches one quarantine record.
func (s *Store) GetQuarantine(tenantID, eventID string) (*model.QuarantineRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q, ok := s.quarantine[tenantID][eventID]
	if !ok {
		return nil, model.ErrNotFound
	}
	cp := *q
	return &cp, nil
}

// ListQuarantine lists records for a tenant, optionally filtered by status.
func (s *Store) ListQuarantine(tenantID, status string) ([]*model.QuarantineRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.quarantine[tenantID]))
	for id := range s.quarantine[tenantID] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]*model.QuarantineRecord, 0)
	for _, id := range ids {
		q := s.quarantine[tenantID][id]
		if status != "" && q.Status != status {
			continue
		}
		cp := *q
		out = append(out, &cp)
	}
	return out, nil
}

// RemoveQuarantine deletes a record after it has been resolved.
func (s *Store) RemoveQuarantine(tenantID, eventID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.quarantine[tenantID], eventID)
}
