package engine

import (
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/rules"
	"github.com/lisama569/compliance-audit-engine-go/pkg/store"
)

func mkEvent(id string, t time.Time, amount int64) model.Event {
	return model.Event{
		TenantID: "t1", Source: "payments", EventID: id, OccurredAt: t,
		Action: "transfer", ResourceID: "r", Actor: "alice", AmountCents: amount,
	}
}

func ruleSet(v int, threshold string, note string) model.RuleSet {
	return model.RuleSet{
		Version: v, Note: note,
		Rules: []model.Rule{
			{RuleID: "r-large", Scope: "payments", Action: "transfer", Op: model.OpGTE,
				Field: "amount_cents", Value: threshold, Decision: model.DecisionDeny, Reason: "over " + threshold},
			{RuleID: "r-ok", Scope: "payments", Action: "transfer", Op: model.OpLTE,
				Field: "amount_cents", Value: below(threshold), Decision: model.DecisionAllow, Reason: "within " + threshold},
		},
	}
}

func below(s string) string {
	switch s {
	case "5000":
		return "4999"
	case "3000":
		return "2999"
	}
	return "0"
}

func TestApplyRulesPrecedence(t *testing.T) {
	rs := model.RuleSet{Rules: []model.Rule{
		{RuleID: "allow-all", Scope: "*", Action: "*", Op: model.OpLTE,
			Field: "amount_cents", Value: "1000000", Decision: model.DecisionAllow},
		{RuleID: "deny-big", Scope: "payments", Action: "transfer", Op: model.OpGTE,
			Field: "amount_cents", Value: "5000", Decision: model.DecisionDeny, Reason: "risk"},
	}}
	ev := mkEvent("e", time.Now(), 6000)
	d, evd := applyRules(rs, ev)
	if d != model.DecisionDeny {
		t.Fatalf("DENY must take precedence over ALLOW, got %s", d)
	}
	if len(evd) != 2 {
		t.Fatalf("all matched rules must be recorded as evidence, got %d", len(evd))
	}

	// 无命中 -> REVIEW。
	noneRS := model.RuleSet{Rules: []model.Rule{{
		RuleID: "x", Scope: "other-source", Action: "transfer", Op: model.OpGTE,
		Field: "amount_cents", Value: "1", Decision: model.DecisionDeny}}}
	d, evd = applyRules(noneRS, ev)
	if d != model.DecisionReview || len(evd) != 0 {
		t.Fatalf("no match must yield REVIEW with empty evidence, got %s %d", d, len(evd))
	}
}

func TestEvaluateUsesVersionAtOccurrenceAndRecompute(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	cur := t0
	reg := rules.NewMemoryRegistry(func() time.Time { return cur })
	st := store.NewMemory()
	eng := New(reg, st)

	// v1 阈值 5000，09:00 发生 4000 的事件 -> ALLOW@v1。
	v1, err := reg.Publish("t1", ruleSet(1, "5000", "v1"))
	if err != nil {
		t.Fatal(err)
	}
	old := mkEvent("old", t0.Add(time.Hour), 4000)
	if out, _, existed := st.PutEvent(old); out != store.PutAccepted || existed {
		t.Fatal("seed event insert failed")
	}
	res, err := eng.Evaluate(old)
	if err != nil {
		t.Fatal(err)
	}
	if res.RuleVersion != v1.Version || res.Decision != model.DecisionAllow {
		t.Fatalf("want ALLOW@v1, got %s@v%d", res.Decision, res.RuleVersion)
	}

	// v2 收紧到 3000，11:00 发布；旧事件在 v2 下应为 DENY，但当前查询仍保持 v1 结论。
	cur = t0.Add(3 * time.Hour)
	if _, err := reg.Publish("t1", ruleSet(2, "3000", "v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RefillCurrent("t1"); err != nil {
		t.Fatal(err)
	}
	v2now := mkEvent("new", cur.Add(time.Minute), 4000)
	if out, _, _ := st.PutEvent(v2now); out != store.PutAccepted {
		t.Fatal("seed new event insert failed")
	}
	resNew, err := eng.Evaluate(v2now)
	if err != nil {
		t.Fatal(err)
	}
	if resNew.Decision != model.DecisionDeny || resNew.RuleVersion != 2 {
		t.Fatalf("new event under v2 want DENY@v2, got %s@v%d", resNew.Decision, resNew.RuleVersion)
	}

	// 历史重算：补齐每个 (事件,版本) 槽位，且 v1 原结论不可变。
	n, err := eng.RecomputeTenant("t1")
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("recompute should fill missing historical slots")
	}
	oldV1, ok := st.GetResult("t1", old.Key(), 1)
	if !ok || oldV1.Decision != model.DecisionAllow {
		t.Fatalf("historical v1 conclusion must remain reproducible, got %+v ok=%v", oldV1, ok)
	}
	oldV2, ok := st.GetResult("t1", old.Key(), 2)
	if !ok || oldV2.Decision != model.DecisionDeny {
		t.Fatalf("old event under v2 want DENY, got %+v ok=%v", oldV2, ok)
	}

	// 再次重算必须严格幂等：槽位不可变，不新增、不改写。
	n2, err := eng.RecomputeTenant("t1")
	if err != nil || n2 != 0 {
		t.Fatalf("second recompute must fill 0 slots, got n=%d err=%v", n2, err)
	}
}

func TestRollbackReproducesOldConclusion(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	cur := t0
	reg := rules.NewMemoryRegistry(func() time.Time { return cur })
	st := store.NewMemory()
	eng := New(reg, st)

	if _, err := reg.Publish("t1", ruleSet(1, "5000", "v1")); err != nil {
		t.Fatal(err)
	}
	ev := mkEvent("e", cur.Add(time.Minute), 4000)
	if out, _, _ := st.PutEvent(ev); out != store.PutAccepted {
		t.Fatal("seed event insert failed")
	}
	if _, err := eng.Evaluate(ev); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(2 * time.Hour)
	if _, err := reg.Publish("t1", ruleSet(2, "3000", "v2")); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RefillCurrent("t1"); err != nil {
		t.Fatal(err)
	}
	// v2 当前结论为 DENY。
	got, _ := st.GetResult("t1", ev.Key(), 2)
	if got.Decision != model.DecisionDeny {
		t.Fatalf("under v2 want DENY, got %s", got.Decision)
	}
	// 回滚 v2 -> v1，当前结论恢复 ALLOW。
	if _, err := reg.Rollback("t1"); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.RefillCurrent("t1"); err != nil {
		t.Fatal(err)
	}
	curRS, _ := reg.Current("t1")
	rows := st.ListResults("t1", curRS.Version)
	if len(rows) != 1 || rows[0].Decision != model.DecisionAllow {
		t.Fatalf("after rollback current query must reproduce ALLOW@v1, got %+v", rows)
	}
}
