package rules

import (
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

func sampleEvent(typ string, payload map[string]any) *model.Event {
	return &model.Event{
		TenantID: "t1", EventID: "e1", Source: "src", Type: typ,
		OccurredAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Payload:    payload,
	}
}

func validSet() *model.RuleSet {
	return &model.RuleSet{
		TenantID: "t1", Version: 1,
		EffectiveFrom: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		Rules: []model.Rule{
			{
				ID: "root-deny", Name: "deny root", EventTypes: []string{"login"}, Priority: 100,
				Conditions: []model.Condition{
					{Field: "user", Operator: model.OpEq, Value: "root"},
					{Field: "env", Operator: model.OpEq, Value: "prod"},
				},
				Verdict: model.VerdictNonCompliant, Reason: "no root in prod",
			},
			{
				ID: "allow", Name: "allow others", EventTypes: []string{"login"}, Priority: 1,
				Conditions: []model.Condition{
					{Field: "env", Operator: model.OpExists},
				},
				Verdict: model.VerdictCompliant, Reason: "ok",
			},
		},
	}
}

func TestValidateRuleSet_AcceptsValid(t *testing.T) {
	log := testutil.NewLogger(t)
	rs := validSet()
	if err := ValidateRuleSet(rs); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}
	log.Logf("validated set rules=%d checksum=%s", len(rs.Rules), ChecksumRuleSet(rs))
}

func TestValidateRuleSet_RejectsBadInputs(t *testing.T) {
	log := testutil.NewLogger(t)
	cases := []struct {
		name string
		mut  func(rs *model.RuleSet)
	}{
		{"zero version", func(rs *model.RuleSet) { rs.Version = 0 }},
		{"no effective_from", func(rs *model.RuleSet) { rs.EffectiveFrom = time.Time{} }},
		{"empty rules", func(rs *model.RuleSet) { rs.Rules = nil }},
		{"missing rule id", func(rs *model.RuleSet) { rs.Rules[0].ID = "" }},
		{"duplicate rule id", func(rs *model.RuleSet) { rs.Rules[1].ID = "root-deny" }},
		{"missing event types", func(rs *model.RuleSet) { rs.Rules[0].EventTypes = nil }},
		{"bad verdict", func(rs *model.RuleSet) { rs.Rules[0].Verdict = "maybe" }},
		{"empty conditions", func(rs *model.RuleSet) { rs.Rules[0].Conditions = nil }},
		{"unknown operator", func(rs *model.RuleSet) { rs.Rules[0].Conditions[0].Operator = "??" }},
		{"in requires list", func(rs *model.RuleSet) {
			rs.Rules[0].Conditions[0].Operator = model.OpIn
			rs.Rules[0].Conditions[0].Value = "root"
		}},
		{"gt requires number", func(rs *model.RuleSet) {
			rs.Rules[0].Conditions[0].Operator = model.OpGt
			rs.Rules[0].Conditions[0].Value = "x"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := validSet()
			tc.mut(rs)
			err := ValidateRuleSet(rs)
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			log.Logf("case=%-20s rejected: %v", tc.name, err)
		})
	}
}

func TestValidateRuleSet_RejectsScopeConflict(t *testing.T) {
	log := testutil.NewLogger(t)
	rs := validSet()
	// Same priority, same event type, conflicting verdict -> ambiguous.
	rs.Rules[1].Priority = 100
	rs.Rules[1].Verdict = model.VerdictNeedsReview
	err := ValidateRuleSet(rs)
	if err == nil {
		t.Fatal("expected scope conflict error")
	}
	log.Logf("scope conflict rejected: %v", err)
}

func TestChecksum_StableAndSensitive(t *testing.T) {
	log := testutil.NewLogger(t)
	rs := validSet()
	c1 := ChecksumRuleSet(rs)
	c2 := ChecksumRuleSet(rs)
	if c1 != c2 {
		t.Fatal("checksum not stable")
	}
	// Order independence.
	rs2 := validSet()
	rs2.Rules[0], rs2.Rules[1] = rs2.Rules[1], rs2.Rules[0]
	if ChecksumRuleSet(rs2) != c1 {
		t.Fatal("checksum must be order independent")
	}
	// Content sensitivity.
	rs3 := validSet()
	rs3.Rules[0].Conditions[0].Value = "admin"
	if ChecksumRuleSet(rs3) == c1 {
		t.Fatal("checksum must change with content")
	}
	log.Logf("checksum stable/order-independent/content-sensitive: %s", c1[:16])
}

func TestEvaluate_PriorityAndBasis(t *testing.T) {
	log := testutil.NewLogger(t)
	rs := validSet()

	// Non-compliant: high-priority root rule matches.
	ev := sampleEvent("login", map[string]any{"user": "root", "env": "prod"})
	d := Evaluate(rs, ev)
	log.Logf("input event=%s payload=%s -> rule=%s v%d verdict=%s basis=%v",
		ev.EventID, testutil.JSON(ev.Payload), d.RuleID, d.RuleVersion, d.Verdict, d.Basis)
	if d.Verdict != model.VerdictNonCompliant || d.RuleID != "root-deny" {
		t.Fatalf("unexpected: %+v", d)
	}
	if len(d.Basis) != 2 {
		t.Fatalf("expected 2 basis lines, got %v", d.Basis)
	}

	// Compliant: root rule does not match, fallback rule does.
	ev2 := sampleEvent("login", map[string]any{"user": "alice", "env": "prod"})
	d2 := Evaluate(rs, ev2)
	log.Logf("input event payload=%s -> rule=%s verdict=%s basis=%v",
		testutil.JSON(ev2.Payload), d2.RuleID, d2.Verdict, d2.Basis)
	if d2.Verdict != model.VerdictCompliant || d2.RuleID != "allow" {
		t.Fatalf("unexpected: %+v", d2)
	}
}

func TestEvaluate_NoMatchNeedsReview(t *testing.T) {
	log := testutil.NewLogger(t)
	rs := validSet()
	ev := sampleEvent("logout", map[string]any{"user": "root"})
	d := Evaluate(rs, ev)
	log.Logf("unmatched event type=%s -> verdict=%s reason=%s", ev.Type, d.Verdict, d.Reason)
	if d.Verdict != model.VerdictNeedsReview || d.RuleID != "" {
		t.Fatalf("expected unmatched needs_review, got %+v", d)
	}
}

func TestEvaluate_Operators(t *testing.T) {
	log := testutil.NewLogger(t)
	rs := &model.RuleSet{
		Version: 1, EffectiveFrom: time.Now(),
		Rules: []model.Rule{{
			ID: "r", Name: "r", EventTypes: []string{"*"}, Priority: 10,
			Conditions: []model.Condition{
				{Field: "amount", Operator: model.OpGte, Value: 1000.0},
				{Field: "region", Operator: model.OpIn, Value: []any{"us", "eu"}},
				{Field: "note", Operator: model.OpContains, Value: "urgent"},
			},
			Verdict: model.VerdictNonCompliant, Reason: "large transfer",
		}},
	}
	ev := sampleEvent("transfer", map[string]any{"amount": 1500.0, "region": "eu", "note": "urgent review"})
	d := Evaluate(rs, ev)
	log.Logf("numeric/in/contains -> verdict=%s basis=%v", d.Verdict, d.Basis)
	if d.Verdict != model.VerdictNonCompliant {
		t.Fatalf("expected match, got %+v", d)
	}
}
