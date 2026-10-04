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

func TestTimelineAndEffectiveAtBoundaries(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Hour)
	t2 := t0.Add(4 * time.Hour)
	cur := t0
	reg := NewMemoryRegistry(func() time.Time { return cur })

	if tl := reg.Timeline("t1"); tl != nil {
		t.Fatalf("no publish yet, timeline must be empty, got %+v", tl)
	}

	if _, err := reg.Publish("t1", model.RuleSet{Note: "v1", Rules: goodRules()}); err != nil {
		t.Fatal(err)
	}
	cur = t1
	if _, err := reg.Publish("t1", model.RuleSet{Note: "v2", Rules: goodRules()}); err != nil {
		t.Fatal(err)
	}
	cur = t2
	if _, err := reg.Rollback("t1"); err != nil {
		t.Fatal(err)
	}

	// 时间轴：v1 生效 [t0,t1)，v2 生效 [t1,t2)，回滚后 v1 再生效 [t2,∞)。
	tl := reg.Timeline("t1")
	if len(tl) != 3 {
		t.Fatalf("want 3 intervals (publish/publish/rollback), got %d: %+v", len(tl), tl)
	}
	for i, iv := range tl {
		t.Logf("[timeline] interval#%d version=v%d from=%s to=%s cause=%s current=%v",
			i, iv.Version, iv.From.Format(time.RFC3339), iv.To.Format(time.RFC3339), iv.Cause, iv.Current)
	}
	wantVersions := []int{1, 2, 1}
	wantCauses := []string{"publish", "publish", "rollback"}
	wantFrom := []time.Time{t0, t1, t2}
	for i, iv := range tl {
		if iv.Version != wantVersions[i] || iv.Cause != wantCauses[i] || !iv.From.Equal(wantFrom[i]) {
			t.Fatalf("interval#%d want v%d/%s@%s, got %+v", i, wantVersions[i], wantCauses[i], wantFrom[i], iv)
		}
		if iv.Current != (i == 2) {
			t.Fatalf("interval#%d current flag wrong: %+v", i, iv)
		}
		if i < 2 {
			if !iv.To.Equal(wantFrom[i+1]) {
				t.Fatalf("interval#%d must end where next begins, got to=%s", i, iv.To)
			}
		} else if !iv.To.IsZero() {
			t.Fatalf("last interval must be open-ended, got to=%s", iv.To)
		}
	}

	// 边界：半开区间 [From, To)，任意时刻至多命中一个版本。
	cases := []struct {
		at   time.Time
		want int // 0 表示期望 ErrNoRuleSet
	}{
		{t0.Add(-time.Second), 0},
		{t0, 1}, // 区间左端闭：生效时刻即命中新版本
		{t1.Add(-time.Nanosecond), 1},
		{t1, 2}, // 接替时刻归属新区间，不会同时命中 v1/v2
		{t2.Add(-time.Nanosecond), 2},
		{t2, 1}, // 回滚生效时刻起解析到回滚后版本
		{t2.Add(time.Hour), 1},
	}
	for _, tc := range cases {
		rs, err := reg.EffectiveAt("t1", tc.at)
		if tc.want == 0 {
			if !errors.Is(err, ErrNoRuleSet) {
				t.Fatalf("effective@%s want ErrNoRuleSet, got v%d err=%v", tc.at, rs.Version, err)
			}
			continue
		}
		if err != nil || rs.Version != tc.want {
			t.Fatalf("effective@%s want v%d, got v%d err=%v", tc.at, tc.want, rs.Version, err)
		}
		t.Logf("[effective] at=%s -> ruleVersion=v%d", tc.at.Format(time.RFC3339), rs.Version)
	}

	// 不变量：t0 之后任意采样时刻恰好命中一个区间。
	for i := 0; i <= 480; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		hits := 0
		for _, iv := range tl {
			if !at.Before(iv.From) && (iv.To.IsZero() || at.Before(iv.To)) {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("at=%s hit %d intervals, want exactly 1", at, hits)
		}
	}

	// 已回滚到最早版本：再次回滚明确失败，且时间轴/当前版本不被改坏。
	if _, err := reg.Rollback("t1"); !errors.Is(err, ErrNothingToRollback) {
		t.Fatalf("want ErrNothingToRollback, got %v", err)
	}
	if tl2 := reg.Timeline("t1"); len(tl2) != 3 {
		t.Fatalf("failed rollback must not alter timeline, got %d intervals", len(tl2))
	}
	if cur, err := reg.Current("t1"); err != nil || cur.Version != 1 {
		t.Fatalf("failed rollback must not alter current, got v%d err=%v", cur.Version, err)
	}
	t.Log("[rollback] no earlier version: explicit ErrNothingToRollback, timeline/current unchanged")
}
