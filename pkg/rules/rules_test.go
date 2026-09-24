package rules

import (
	"errors"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

func goodRules() []model.Rule {
	return []model.Rule{
		{RuleID: "r1", Scope: "payments", Action: "transfer", Op: model.OpGTE,
			Field: "amount_cents", Value: "5000", Decision: model.DecisionDeny, Reason: "large"},
	}
}

func TestValidateRuleSet(t *testing.T) {
	base := model.RuleSet{TenantID: "t1", Rules: goodRules()}
	if err := ValidateRuleSet(base); err != nil {
		t.Fatalf("valid set rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*model.RuleSet)
		wantErr error
	}{
		{"missing tenant", func(rs *model.RuleSet) { rs.TenantID = "" }, ErrMissingField},
		{"empty rules", func(rs *model.RuleSet) { rs.Rules = nil }, ErrMissingField},
		{"missing rule id", func(rs *model.RuleSet) { rs.Rules[0].RuleID = "" }, ErrMissingField},
		{"bad operator", func(rs *model.RuleSet) { rs.Rules[0].Op = "NOPE" }, ErrInvalidRule},
		{"non-numeric threshold", func(rs *model.RuleSet) { rs.Rules[0].Value = "x" }, ErrInvalidRule},
		{"gte on bad field", func(rs *model.RuleSet) { rs.Rules[0].Field = "actor" }, ErrInvalidRule},
		{"eq on bad field", func(rs *model.RuleSet) {
			rs.Rules[0].Op = model.OpEQ
			rs.Rules[0].Field = "nope"
			rs.Rules[0].Value = "v"
		}, ErrInvalidRule},
		{"bad decision", func(rs *model.RuleSet) { rs.Rules[0].Decision = "MAYBE" }, ErrInvalidRule},
		{"duplicate rule id", func(rs *model.RuleSet) {
			rs.Rules = append(rs.Rules, rs.Rules[0])
		}, ErrScopeConflict},
		{"scope conflict", func(rs *model.RuleSet) {
			rs.Rules = append(rs.Rules, model.Rule{RuleID: "r2", Scope: "payments", Action: "transfer",
				Op: model.OpGTE, Field: "amount_cents", Value: "5000", Decision: model.DecisionAllow})
		}, ErrScopeConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs := base
			rs.Rules = append([]model.Rule(nil), base.Rules...)
			tc.mutate(&rs)
			err := ValidateRuleSet(rs)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestPublishRollbackAndEffectiveAt(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	cur := t0
	reg := NewMemoryRegistry(func() time.Time { return cur })

	if _, err := reg.Current("t1"); !errors.Is(err, ErrNoRuleSet) {
		t.Fatalf("want ErrNoRuleSet, got %v", err)
	}

	v1, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()})
	if err != nil {
		t.Fatalf("publish v1: %v", err)
	}
	if v1.Version != 1 || !v1.PublishedAt.Equal(t0) {
		t.Fatalf("unexpected v1: %+v", v1)
	}

	// 非法发布不得污染当前状态。
	bad := model.RuleSet{Rules: []model.Rule{{RuleID: "bad", Op: "X"}}}
	if _, err := reg.Publish("t1", bad); err == nil {
		t.Fatal("invalid publish must fail")
	}
	cur = t0.Add(time.Hour)
	v2, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()})
	if err != nil {
		t.Fatalf("publish v2: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("invalid publish must not consume version, got v%d", v2.Version)
	}

	// 已发布快照不可被外部修改（防御性拷贝）。
	v2.Rules[0].Value = "1"
	got, _ := reg.Current("t1")
	if got.Rules[0].Value == "1" {
		t.Fatal("published snapshot must be isolated from caller slice mutation")
	}

	// EffectiveAt：按事件发生时间选取当时生效版本。
	eff, err := reg.EffectiveAt("t1", t0.Add(30*time.Minute))
	if err != nil || eff.Version != 1 {
		t.Fatalf("effective at t0+30m want v1, got v%d err=%v", eff.Version, err)
	}
	eff, _ = reg.EffectiveAt("t1", cur.Add(time.Minute))
	if eff.Version != 2 {
		t.Fatalf("want v2, got v%d", eff.Version)
	}

	// 回滚只移动当前指针，历史保留。
	rb, err := reg.Rollback("t1")
	if err != nil || rb.Version != 1 {
		t.Fatalf("rollback want v1, got v%d err=%v", rb.Version, err)
	}
	curRS, _ := reg.Current("t1")
	if curRS.Version != 1 {
		t.Fatalf("current after rollback want v1, got v%d", curRS.Version)
	}
	if hist := reg.History("t1"); len(hist) != 2 || hist[0].Version != 1 || hist[1].Version != 2 {
		t.Fatalf("history must retain both versions, got %+v", hist)
	}
	if _, err := reg.Rollback("t1"); !errors.Is(err, ErrNothingToRollback) {
		t.Fatalf("want ErrNothingToRollback, got %v", err)
	}

	// 回滚后再发布：版本号继续单调递增为 3。
	v3, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()})
	if err != nil || v3.Version != 3 {
		t.Fatalf("post-rollback publish want v3, got v%d err=%v", v3.Version, err)
	}
}

func TestTenantIsolation(t *testing.T) {
	reg := NewMemoryRegistry(nil)
	if _, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()}); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Current("t2"); !errors.Is(err, ErrNoRuleSet) {
		t.Fatalf("tenant t2 must be isolated, got err=%v", err)
	}
}
