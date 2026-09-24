package rules

import (
	"fmt"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
)

// RuleStore is the persistence surface required by Registry. *store.Store
// satisfies it.
type RuleStore interface {
	LatestVersion(scopeKey string) int
	GetRuleSet(scopeKey string, version int) (*model.RuleSet, error)
	SaveRuleSet(rs *model.RuleSet) error
	CloseActiveRange(scopeKey string, t time.Time)
	RollbackActiveRange(scopeKey string, t time.Time)
	EffectiveRuleSet(scopeKey string, t time.Time) (*model.RuleSet, error)
	ListRuleSets(scopeKey string) ([]*model.RuleSet, error)
}

// Registry publishes versioned rule sets, supports rollback and resolves the
// rule set effective at a given point in time.
type Registry struct {
	store RuleStore
	now   func() time.Time
	mu    chan struct{} // serializes publish/rollback per registry
}

// NewRegistry constructs a Registry backed by store.
func NewRegistry(store RuleStore) *Registry {
	return &Registry{store: store, now: time.Now, mu: make(chan struct{}, 1)}
}

// SetClock overrides the clock (used in tests).
func (r *Registry) SetClock(now func() time.Time) { r.now = now }

func (r *Registry) lock()   { r.mu <- struct{}{} }
func (r *Registry) unlock() { <-r.mu }

// Publish validates and publishes a new immutable rule set version for a
// tenant scope ("" = global). The previous open-ended active set is closed at
// the new set's effective time so historical time-point resolution remains
// correct. Invalid sets are rejected before any state is touched.
func (r *Registry) Publish(tenantID string, rules []model.Rule, by string, effectiveFrom time.Time) (*model.RuleSet, error) {
	if effectiveFrom.IsZero() {
		effectiveFrom = r.now()
	}
	rs := &model.RuleSet{
		TenantID:      tenantID,
		Rules:         append([]model.Rule(nil), rules...),
		PublishedBy:   by,
		PublishedAt:   r.now(),
		EffectiveFrom: effectiveFrom,
		Status:        model.RuleSetStatusActive,
	}
	if err := ValidateRuleSetVersion1(rs); err != nil {
		return nil, err
	}
	rs.Checksum = ChecksumRuleSet(rs)

	r.lock()
	defer r.unlock()

	next := r.store.LatestVersion(tenantID) + 1
	rs.Version = next
	rs.ID = fmt.Sprintf("rules-%s-v%d", scopeName(tenantID), next)

	// Re-publishing byte-identical rule content is meaningless and must not
	// masquerade as a new effective version, regardless of effective time.
	if prev := r.store.LatestVersion(tenantID); prev > 0 {
		if old, err := r.store.GetRuleSet(tenantID, prev); err == nil &&
			RulesContentChecksum(old.Rules) == RulesContentChecksum(rs.Rules) {
			return nil, fmt.Errorf("%w: rule content identical to version %d", model.ErrAlreadyExists, prev)
		}
	}

	// Validate before mutating anything: close + save happen only for a valid set.
	r.store.CloseActiveRange(tenantID, effectiveFrom)
	if err := r.store.SaveRuleSet(rs); err != nil {
		return nil, err
	}
	return rs, nil
}

// ValidateRuleSetVersion1 validates a draft rule set (version 1 placeholders
// are allowed pre-assignment).
func ValidateRuleSetVersion1(rs *model.RuleSet) error {
	// Version is assigned by the registry; validate with a stand-in >= 1.
	draft := *rs
	if draft.Version < 1 {
		draft.Version = 1
	}
	return ValidateRuleSet(&draft)
}

// Rollback creates a NEW version whose rules are copied from a prior version.
// History is never rewritten: the target version remains intact and the
// currently open-ended set is closed and marked rolled_back.
func (r *Registry) Rollback(tenantID string, toVersion int, by string) (*model.RuleSet, error) {
	r.lock()
	defer r.unlock()

	target, err := r.store.GetRuleSet(tenantID, toVersion)
	if err != nil {
		return nil, fmt.Errorf("rollback target: %w", err)
	}
	if err := ValidateRuleSet(target); err != nil {
		return nil, fmt.Errorf("rollback target invalid: %w", err)
	}
	now := r.now()
	next := r.store.LatestVersion(tenantID) + 1
	rs := &model.RuleSet{
		ID:            fmt.Sprintf("rules-%s-v%d", scopeName(tenantID), next),
		TenantID:      tenantID,
		Version:       next,
		PublishedBy:   by,
		PublishedAt:   now,
		EffectiveFrom: now,
		Rules:         append([]model.Rule(nil), target.Rules...),
		Status:        model.RuleSetStatusActive,
	}
	rs.Checksum = ChecksumRuleSet(rs)

	r.store.RollbackActiveRange(tenantID, now)
	if err := r.store.SaveRuleSet(rs); err != nil {
		return nil, err
	}
	return rs, nil
}

// EffectiveAt resolves the rule set effective for tenantID at time t. A
// tenant-specific set takes precedence; the global scope ("") is the fallback.
func (r *Registry) EffectiveAt(tenantID string, t time.Time) (*model.RuleSet, error) {
	if rs, err := r.store.EffectiveRuleSet(tenantID, t); err == nil {
		return rs, nil
	}
	if tenantID != "" {
		if rs, err := r.store.EffectiveRuleSet("", t); err == nil {
			return rs, nil
		}
	}
	return nil, fmt.Errorf("%w: no effective rule set for tenant %q at %s",
		model.ErrNotFound, tenantID, t.UTC().Format(time.RFC3339))
}

// ListVersions returns all published versions for a tenant scope.
func (r *Registry) ListVersions(tenantID string) ([]*model.RuleSet, error) {
	return r.store.ListRuleSets(tenantID)
}

func scopeName(tenantID string) string {
	if tenantID == "" {
		return "global"
	}
	return tenantID
}
