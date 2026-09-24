package replay

import (
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/rules"
	"github.com/lisama569/compliance-audit-engine-go/store"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

type fx struct {
	st  *store.Store
	reg *rules.Registry
	rp  *Replayer
	log *testutil.Logger
}

func setup(t *testing.T) (*fx, time.Time) {
	t.Helper()
	t0 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cur := t0
	st := store.New()
	st.RegisterTenant("t1")
	reg := rules.NewRegistry(st)
	reg.SetClock(func() time.Time { return cur })
	rp := NewReplayer(st, reg, 2)
	rp.SetClock(func() time.Time { return cur })
	advance := func(d time.Duration) { cur = cur.Add(d) }
	_ = advance
	return &fx{st: st, reg: reg, rp: rp, log: testutil.NewLogger(t)}, t0
}

func ruleSet(verdict, reason string) []model.Rule {
	return []model.Rule{{
		ID: "root", Name: "root rule", EventTypes: []string{"login"}, Priority: 10,
		Conditions: []model.Condition{
			{Field: "user", Operator: model.OpEq, Value: "root"},
			{Field: "env", Operator: model.OpEq, Value: "prod"},
		},
		Verdict: verdict, Reason: reason,
	}}
}

func ingest(t *testing.T, f *fx, id string, occ time.Time, payload map[string]any) {
	t.Helper()
	ev := &model.Event{
		TenantID: "t1", EventID: id, Source: "idp", Type: "login",
		OccurredAt: occ, ReceivedAt: occ.Add(time.Minute), Payload: payload,
	}
	rs, err := f.reg.EffectiveAt("t1", occ)
	if err != nil {
		t.Fatalf("no rules at %s: %v", occ, err)
	}
	d := rules.Evaluate(rs, ev)
	d.TenantID, d.EventID, d.EventSource, d.EventType = "t1", id, "idp", "login"
	d.OccurredAt = occ
	d.Outcome = "original"
	d.DecidedAt = occ.Add(time.Minute)
	if _, err := f.st.ClaimEvent(*ev, "hash-"+id); err != nil {
		t.Fatal(err)
	}
	if _, err := f.st.SaveDecision(d); err != nil {
		t.Fatal(err)
	}
	f.st.AdvanceWatermark(*ev)
}

func TestRecompute_ReproducesVerdictAtOccurrenceAfterRollback(t *testing.T) {
	f, t0 := setup(t)

	// v1: root in prod -> non_compliant, effective from t0-7d.
	v1, err := f.reg.Publish("t1", ruleSet(model.VerdictNonCompliant, "v1 deny"), "a", t0.Add(-7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, f, "e1", t0.Add(-48*time.Hour), map[string]any{"user": "root", "env": "prod"})
	orig, _ := f.st.GetOriginalDecision("t1", "e1")
	if orig.Verdict != model.VerdictNonCompliant || orig.RuleVersion != 1 {
		t.Fatalf("setup: %+v", orig)
	}

	// v2: root in prod -> needs_review, effective from t0.
	v2, err := f.reg.Publish("t1", ruleSet(model.VerdictNeedsReview, "v2 review"), "a", t0)
	if err != nil {
		t.Fatal(err)
	}

	// Recompute must STILL reproduce v1 because the event occurred before v2.
	rep, err := f.rp.RecomputeTenant("t1", "auditor")
	if err != nil {
		t.Fatal(err)
	}
	f.log.Logf("after v2 publish: report scanned=%d recomputed=%d changed=%d", rep.Scanned, rep.Recomputed, rep.Changed)
	if rep.Changed != 0 {
		t.Fatalf("recompute under history-aware rules must not change verdicts: %+v", rep)
	}
	hist := f.st.RecomputeHistory("t1", "e1")
	if len(hist) != 1 || hist[0].RuleVersion != 1 || hist[0].Verdict != model.VerdictNonCompliant {
		t.Fatalf("recomputed must equal original v1 verdict: %+v", hist)
	}

	// Original remains immutable.
	orig2, _ := f.st.GetOriginalDecision("t1", "e1")
	if orig2.Verdict != model.VerdictNonCompliant || orig2.Outcome != "original" {
		t.Fatalf("original decision was mutated: %+v", orig2)
	}
	f.log.Logf("original preserved: v%d verdict=%s; recomputed: v%d verdict=%s triggeredBy=%s",
		orig2.RuleVersion, orig2.Verdict, hist[0].RuleVersion, hist[0].Verdict, hist[0].TriggeredBy)

	// Now roll back to v1 (creates v3, same content as v1) — recompute unchanged.
	v3, err := f.reg.Rollback("t1", v1.Version, "a")
	if err != nil {
		t.Fatal(err)
	}
	f.log.Logf("rollback published new version v%d (history versions v1,v2 remain intact)", v3.Version)
	_ = v2
	d, err := f.rp.RecomputeEvent("t1", "e1", "auditor2")
	if err != nil {
		t.Fatal(err)
	}
	f.log.Logf("after rollback v3: single recompute ruleVersionApplied=%d verdict=%s (event predates v2; basis=%v)",
		d.RuleVersion, d.Verdict, d.Basis)
	if d.RuleVersion != 1 || d.Verdict != model.VerdictNonCompliant {
		t.Fatalf("recompute must use v1 at occurrence, got v%d %s", d.RuleVersion, d.Verdict)
	}
	if len(f.st.RecomputeHistory("t1", "e1")) != 2 {
		t.Fatal("recomputation history must be append-only")
	}
}

func TestRecompute_DetectsChangedVerdictWhenRulesAtTimeChange(t *testing.T) {
	f, t0 := setup(t)
	// Event occurred exactly at t0+25h; publish v1 effective t0, then v2
	// effective at t0+24h so the event's era changes between runs.
	if _, err := f.reg.Publish("t1", ruleSet(model.VerdictNonCompliant, "v1"), "a", t0); err != nil {
		t.Fatal(err)
	}
	occ := t0.Add(25 * time.Hour)
	ingest(t, f, "e9", occ, map[string]any{"user": "root", "env": "prod"})
	// Publish v2 retroactively covering the event's occurrence (simulates
	// delayed/corrected rule publication; replay picks it up).
	_, err := f.reg.Publish("t1", ruleSet(model.VerdictNeedsReview, "v2"), "a", t0.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.rp.RecomputeTenant("t1", "auditor")
	if err != nil {
		t.Fatal(err)
	}
	f.log.Logf("changed-detection report changed=%d unchanged=%d", rep.Changed, rep.Unchanged)
	if rep.Changed != 1 {
		t.Fatalf("expected 1 changed verdict, got %+v", rep)
	}
	cur, _ := f.st.CurrentDecision("t1", "e9")
	if cur.Verdict != model.VerdictNeedsReview || cur.Outcome != "recomputed" {
		t.Fatalf("current decision should reflect recompute: %+v", cur)
	}
	orig, _ := f.st.GetOriginalDecision("t1", "e9")
	if orig.Verdict != model.VerdictNonCompliant {
		t.Fatalf("original must remain non_compliant, got %s", orig.Verdict)
	}
}

func TestRecompute_OverloadWhenConcurrencyExceeded(t *testing.T) {
	f, t0 := setup(t)
	if _, err := f.reg.Publish("t1", ruleSet(model.VerdictNeedsReview, "x"), "a", t0.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	ingest(t, f, "a1", t0.Add(-30*time.Minute), map[string]any{"user": "root", "env": "prod"})

	// maxConcurrency in fixture is 2; fill the semaphore synchronously via
	// a helper by launching goroutines that block is not trivial, so instead
	// create a capacity-1 replayer and occupy its slot manually.
	rp1 := NewReplayer(f.st, f.reg, 1)
	rp1.sem <- struct{}{}
	_, err := rp1.RecomputeTenant("t1", "a")
	if err != model.ErrOverloaded {
		t.Fatalf("expected overload, got %v", err)
	}
	f.log.Logf("concurrent recompute rejected with back-pressure: %v", err)
}
