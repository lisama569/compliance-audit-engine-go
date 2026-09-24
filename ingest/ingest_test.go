package ingest

import (
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/rules"
	"github.com/lisama569/compliance-audit-engine-go/store"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

var (
	t0   = time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	hour = time.Hour
)

type fixture struct {
	st  *store.Store
	reg *rules.Registry
	p   *Pipeline
	log *testutil.Logger
}

func newFixture(t *testing.T, cfg Config) *fixture {
	t.Helper()
	st := store.New()
	st.RegisterTenant("t1")
	reg := rules.NewRegistry(st)
	clock := t0
	reg.SetClock(func() time.Time { return clock })
	p := NewPipeline(st, reg, cfg)
	p.SetClock(func() time.Time { return clock })
	return &fixture{st: st, reg: reg, p: p, log: testutil.NewLogger(t)}
}

func mustPublish(t *testing.T, f *fixture, rules_ []model.Rule, eff time.Time) *model.RuleSet {
	t.Helper()
	rs, err := f.reg.Publish("t1", rules_, "tester", eff)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	return rs
}

func loginRules() []model.Rule {
	return []model.Rule{
		{
			ID: "root-deny", Name: "deny root", EventTypes: []string{"login"}, Priority: 100,
			Conditions: []model.Condition{
				{Field: "user", Operator: model.OpEq, Value: "root"},
				{Field: "env", Operator: model.OpEq, Value: "prod"},
			},
			Verdict: model.VerdictNonCompliant, Reason: "no root in prod",
		},
		{
			ID: "allow", Name: "allow", EventTypes: []string{"login"}, Priority: 1,
			Conditions: []model.Condition{{Field: "env", Operator: model.OpExists}},
			Verdict:    model.VerdictCompliant, Reason: "ok",
		},
	}
}

func ev(id string, occurred time.Time, payload map[string]any) *model.Event {
	return &model.Event{
		TenantID: "t1", EventID: id, Source: "idp", Type: "login",
		OccurredAt: occurred, ReceivedAt: t0, Actor: "a", Payload: payload,
	}
}

func TestIngest_HappyPathAndDecisionPersistence(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	rs := mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))

	res, err := f.p.Ingest(ev("e1", t0.Add(-time.Hour), map[string]any{"user": "root", "env": "prod"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Accepted || res.Decision.Verdict != model.VerdictNonCompliant {
		t.Fatalf("unexpected result: %+v", res)
	}
	f.log.Logf("accepted event=%s ruleSet=%s ruleVersion=%d basis=%v verdict=%s",
		res.EventID, rs.ID, res.Decision.RuleVersion, res.Decision.Basis, res.Decision.Verdict)

	got, err := f.st.GetOriginalDecision("t1", "e1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Verdict != model.VerdictNonCompliant || got.Outcome != "original" {
		t.Fatalf("persisted decision wrong: %+v", got)
	}
}

func TestIngest_DuplicateIsMerged(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))
	payload := map[string]any{"user": "alice", "env": "prod"}

	r1, err := f.p.Ingest(ev("dup", t0.Add(-time.Hour), payload))
	if err != nil || !r1.Accepted || r1.Duplicate {
		t.Fatalf("first ingest: %+v err=%v", r1, err)
	}
	r2, err := f.p.Ingest(ev("dup", t0.Add(-time.Hour), payload))
	if err != nil || !r2.Accepted || !r2.Duplicate {
		t.Fatalf("duplicate must merge: %+v err=%v", r2, err)
	}
	f.log.Logf("duplicate event=%s merged, verdict=%s ruleVersion=%d",
		r2.EventID, r2.Decision.Verdict, r2.Decision.RuleVersion)

	events := f.st.ListEvents("t1")
	if len(events) != 1 {
		t.Fatalf("expected exactly one stored event, got %d", len(events))
	}
	ds, _ := f.st.QueryDecisions("t1", store.DecisionFilter{})
	if len(ds) != 1 {
		t.Fatalf("expected exactly one valid decision, got %d", len(ds))
	}
}

func TestIngest_SameIDDifferentContentIsRejected(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))

	r1, _ := f.p.Ingest(ev("cf", t0.Add(-time.Hour), map[string]any{"user": "alice", "env": "prod"}))
	if !r1.Accepted {
		t.Fatal("first should accept")
	}
	// Same id, SAME occurred_at but different payload -> must not silently rewrite.
	r2, err := f.p.Ingest(ev("cf", t0.Add(-time.Hour), map[string]any{"user": "mallory", "env": "prod"}))
	if err != nil {
		t.Fatal(err)
	}
	if r2.Accepted || r2.Quarantine == nil ||
		r2.Quarantine.Reason != model.ReasonDuplicateConflict ||
		r2.Quarantine.Status != model.StatusRejected {
		t.Fatalf("conflict must be quarantined rejected, got %+v", r2)
	}
	f.log.Logf("conflict event=%s quarantined reason=%s detail=%q",
		r2.EventID, r2.Quarantine.Reason, r2.Quarantine.Detail)

	// The original conclusion must remain intact.
	d, _ := f.st.GetOriginalDecision("t1", "cf")
	if d.Basis == nil || d.Verdict != model.VerdictCompliant {
		t.Fatalf("original decision was altered: %+v", d)
	}
}

func TestIngest_LateEventWithinWindowUsesRulesAtOccurrence(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))
	// New version becomes effective at t0; event occurred 10h before t0.
	mustPublish(t, f, []model.Rule{{
		ID: "noop", Name: "noop", EventTypes: []string{"login"}, Priority: 1,
		Conditions: []model.Condition{{Field: "never", Operator: model.OpExists}},
		Verdict:    model.VerdictNeedsReview, Reason: "noop",
	}}, t0)

	r, err := f.p.Ingest(ev("late", t0.Add(-10*hour), map[string]any{"user": "root", "env": "prod"}))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Accepted || !r.Decision.Late || r.Decision.RuleVersion != 1 {
		t.Fatalf("late event must be judged by v1 at occurrence: %+v", r.Decision)
	}
	f.log.Logf("late event=%s applied ruleVersion=%d verdict=%s late=%v",
		r.EventID, r.Decision.RuleVersion, r.Decision.Verdict, r.Decision.Late)
}

func TestIngest_TooLateIsRejected(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-30*24*hour))
	r, _ := f.p.Ingest(ev("old", t0.Add(-25*hour), map[string]any{"user": "root", "env": "prod"}))
	if r.Accepted || r.Quarantine.Reason != model.ReasonTooLate {
		t.Fatalf("expected too_late rejection, got %+v", r)
	}
	f.log.Logf("too-late event=%s reason=%s", r.EventID, r.Quarantine.Reason)
}

func TestIngest_FutureEventIsRejected(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))
	r, _ := f.p.Ingest(ev("future", t0.Add(10*time.Minute), map[string]any{"user": "x", "env": "prod"}))
	if r.Accepted || r.Quarantine.Reason != model.ReasonFutureEvent {
		t.Fatalf("expected future_event rejection, got %+v", r)
	}
	f.log.Logf("future event=%s reason=%s", r.EventID, r.Quarantine.Reason)
}

func TestIngest_MissingFieldsRejected(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))
	cases := []struct {
		name string
		ev   *model.Event
		want string
	}{
		{"no tenant", &model.Event{TenantID: "", EventID: "x", Source: "s", Type: "login",
			OccurredAt: t0.Add(-time.Hour), Payload: map[string]any{}}, model.ReasonMissingField},
		{"no payload", ev("x", t0.Add(-time.Hour), nil), model.ReasonInvalidPayload},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := f.p.Ingest(tc.ev)
			if err != nil {
				t.Fatal(err)
			}
			if r.Accepted || r.Quarantine.Reason != tc.want || r.Quarantine.Status != model.StatusRejected {
				t.Fatalf("case %s: %+v", tc.name, r)
			}
			f.log.Logf("case=%s rejected reason=%s", tc.name, r.Quarantine.Reason)
		})
	}
}

func TestIngest_UnknownTenantRejected(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))
	e := ev("x", t0.Add(-time.Hour), map[string]any{"user": "a", "env": "prod"})
	e.TenantID = "ghost"
	r, _ := f.p.Ingest(e)
	if r.Accepted || r.Quarantine.Reason != model.ReasonUnknownTenant {
		t.Fatalf("got %+v", r)
	}
	f.log.Logf("unknown tenant rejected reason=%s", r.Quarantine.Reason)
}

func TestIngest_OrderedSourceOutOfOrderPending(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	mustPublish(t, f, loginRules(), t0.Add(-7*24*hour))
	ordered := func(id string, seq int64, occurred time.Time, user string) *model.Event {
		e := ev(id, occurred, map[string]any{"user": user, "env": "prod"})
		e.Ordered = true
		e.Sequence = seq
		return e
	}

	// seq=2 first, then seq=1: seq=1 must be parked pending, not applied.
	r2, err := f.p.Ingest(ordered("s2", 2, t0.Add(-2*time.Minute), "alice"))
	if err != nil || !r2.Accepted {
		t.Fatalf("seq2: %+v %v", r2, err)
	}
	r1, err := f.p.Ingest(ordered("s1", 1, t0.Add(-3*time.Minute), "root"))
	if err != nil || r1.Accepted {
		t.Fatalf("late seq must be pending, got %+v err=%v", r1, err)
	}
	if r1.Quarantine.Status != model.StatusPending || r1.Quarantine.Reason != model.ReasonOutOfOrder {
		t.Fatalf("want pending out_of_order, got %+v", r1.Quarantine)
	}
	f.log.Logf("out-of-order event=%s pending reason=%s detail=%q",
		r1.EventID, r1.Quarantine.Reason, r1.Quarantine.Detail)

	// seq=3 arriving before seq=2 resolution creates a gap: accepted but flagged.
	r3, err := f.p.Ingest(ordered("s3", 3, t0.Add(-time.Minute), "alice"))
	if err != nil || !r3.Accepted || !r3.Decision.Reordered {
		t.Fatalf("gap event accepted+flagged, got %+v err=%v", r3, err)
	}
	f.log.Logf("gap event=%s accepted reordered=%v verdict=%s",
		r3.EventID, r3.Decision.Reordered, r3.Decision.Verdict)
}

func TestIngest_NoRuleAtOccurrenceTimePending(t *testing.T) {
	f := newFixture(t, Config{MaxLate: 24 * hour, MaxSkew: time.Minute})
	// Rules only become effective later than the event's occurrence time.
	mustPublish(t, f, loginRules(), t0.Add(-time.Hour))
	r, err := f.p.Ingest(ev("gap", t0.Add(-5*time.Hour), map[string]any{"user": "root", "env": "prod"}))
	if err != nil || r.Accepted {
		t.Fatalf("must be pending, got %+v err=%v", r, err)
	}
	if r.Quarantine.Status != model.StatusPending ||
		r.Quarantine.Reason != model.ReasonNoRuleAtTime {
		t.Fatalf("want pending no_rule_at_occurrence_time, got %+v", r.Quarantine)
	}
	f.log.Logf("no-rule event=%s pending reason=%s detail=%q",
		r.EventID, r.Quarantine.Reason, r.Quarantine.Detail)
}
