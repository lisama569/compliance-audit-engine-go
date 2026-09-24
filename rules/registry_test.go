package rules

import (
	"errors"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/store"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

func regFixture(t *testing.T) (*Registry, *store.Store, time.Time, func(time.Duration)) {
	t.Helper()
	now := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cur := now
	st := store.New()
	r := NewRegistry(st)
	r.SetClock(func() time.Time { return cur })
	advance := func(d time.Duration) { cur = cur.Add(d) }
	return r, st, now, advance
}

func rulesV1() []model.Rule {
	return []model.Rule{{
		ID: "r1", Name: "r1", EventTypes: []string{"login"}, Priority: 10,
		Conditions: []model.Condition{{Field: "user", Operator: model.OpEq, Value: "root"}},
		Verdict:    model.VerdictNonCompliant, Reason: "x",
	}}
}

func rulesV2() []model.Rule {
	return []model.Rule{{
		ID: "r1", Name: "r1", EventTypes: []string{"login"}, Priority: 10,
		Conditions: []model.Condition{{Field: "user", Operator: model.OpEq, Value: "root"}},
		Verdict:    model.VerdictNeedsReview, Reason: "x",
	}}
}

func TestRegistry_PublishAssignsVersionsAndEffectiveRanges(t *testing.T) {
	log := testutil.NewLogger(t)
	r, _, t0, _ := regFixture(t)

	v1, err := r.Publish("t1", rulesV1(), "admin", t0)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := r.Publish("t1", rulesV2(), "admin", t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	log.Logf("published v%d eff=%s, then v%d eff=%s",
		v1.Version, v1.EffectiveFrom, v2.Version, v2.EffectiveFrom)

	// Historical time resolves to v1; current time resolves to v2.
	at, err := r.EffectiveAt("t1", t0.Add(time.Hour))
	if err != nil || at.Version != 1 {
		t.Fatalf("historical resolution: %+v err=%v", at, err)
	}
	at2, err := r.EffectiveAt("t1", t0.Add(25*time.Hour))
	if err != nil || at2.Version != 2 {
		t.Fatalf("current resolution: %+v err=%v", at2, err)
	}
	log.Logf("effective at t0+1h -> v%d; at t0+25h -> v%d", at.Version, at2.Version)

	// Old v1 must have been closed exactly when v2 became effective.
	if !v1.EffectiveTo.IsZero() && !v1.EffectiveTo.Equal(v2.EffectiveFrom) {
		t.Fatalf("v1 closed at %v, want %v", v1.EffectiveTo, v2.EffectiveFrom)
	}
}

func TestRegistry_RejectsIdenticalRepublish(t *testing.T) {
	log := testutil.NewLogger(t)
	r, _, t0, _ := regFixture(t)
	if _, err := r.Publish("t1", rulesV1(), "admin", t0); err != nil {
		t.Fatal(err)
	}
	_, err := r.Publish("t1", rulesV1(), "admin", t0.Add(time.Hour))
	if !errors.Is(err, model.ErrAlreadyExists) {
		t.Fatalf("identical republish must fail, got %v", err)
	}
	log.Logf("identical republish rejected: %v", err)
}

func TestRegistry_RollbackCreatesNewVersion(t *testing.T) {
	log := testutil.NewLogger(t)
	r, _, t0, advance := regFixture(t)
	v1, _ := r.Publish("t1", rulesV1(), "admin", t0)
	v2, _ := r.Publish("t1", rulesV2(), "admin", t0.Add(24*time.Hour))
	advance(48 * time.Hour)
	v3, err := r.Rollback("t1", v1.Version, "admin")
	if err != nil {
		t.Fatal(err)
	}
	log.Logf("rollback v%d -> v%d (rules copied, checksum v1=%s v3=%s)",
		v2.Version, v3.Version, v1.Checksum[:12], v3.Checksum[:12])

	if v3.Version != 3 {
		t.Fatalf("rollback must create a new version, got %d", v3.Version)
	}
	if v3.Rules[0].Verdict != v1.Rules[0].Verdict {
		t.Fatal("rollback content must equal target version content")
	}

	// History intact: v2 still resolvable at its era; v3 effective now.
	at2, err := r.EffectiveAt("t1", t0.Add(25*time.Hour))
	if err != nil || at2.Version != 2 {
		t.Fatalf("v2 era must remain resolvable: %+v", at2)
	}
	at3, err := r.EffectiveAt("t1", t0.Add(49*time.Hour))
	if err != nil || at3.Version != 3 {
		t.Fatalf("rollback era must resolve v3: %+v", at3)
	}
	log.Logf("history preserved: v2 era -> v%d, post-rollback -> v%d", at2.Version, at3.Version)

	// The version immediately preceding a rollback is marked rolled_back;
	// normal supersession is marked superseded (v1 was closed by v2).
	sets, _ := r.store.ListRuleSets("t1")
	statuses := map[int]string{}
	for _, s := range sets {
		statuses[s.Version] = s.Status
	}
	log.Logf("statuses after rollback: v1=%s v2=%s v3=%s",
		statuses[1], statuses[2], statuses[3])
	if statuses[2] != model.RuleSetStatusRolledBack {
		t.Fatalf("v2 must be rolled_back, got %q", statuses[2])
	}
	if statuses[1] != model.RuleSetStatusSuperseded {
		t.Fatalf("v1 must be superseded, got %q", statuses[1])
	}
	if statuses[3] != model.RuleSetStatusActive {
		t.Fatalf("v3 must be active, got %q", statuses[3])
	}
}

func TestRegistry_GlobalFallback(t *testing.T) {
	log := testutil.NewLogger(t)
	r, _, t0, _ := regFixture(t)
	g, err := r.Publish("", rulesV1(), "platform", t0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.EffectiveAt("no-tenant-rules", t0.Add(time.Hour))
	if err != nil {
		t.Fatalf("tenant without rules must fall back to global: %v", err)
	}
	log.Logf("tenant fell back to global v%d (%s)", got.Version, g.ID)
	if got.Version != 1 || got.TenantID != "" {
		t.Fatalf("bad fallback: %+v", got)
	}
}

func TestRegistry_PublishRejectsInvalidSet(t *testing.T) {
	log := testutil.NewLogger(t)
	r, _, t0, _ := regFixture(t)
	bad := []model.Rule{{
		ID: "", Name: "", EventTypes: nil, Priority: 1,
		Conditions: nil, Verdict: "bogus",
	}}
	_, err := r.Publish("t1", bad, "admin", t0)
	if err == nil {
		t.Fatal("invalid set must not be published")
	}
	log.Logf("invalid publish rejected before state mutation: %v", err)
	if r.store.LatestVersion("t1") != 0 {
		t.Fatal("failed publish must not advance version counter")
	}
}
