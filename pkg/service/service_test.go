package service

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/auth"
	"github.com/lisama569/compliance-audit-engine-go/pkg/ingest"
	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/rules"
)

func newSvc() *Service {
	return New(ingest.Config{LateGrace: time.Minute})
}

func adminOf(tenant string) auth.Principal {
	return auth.Principal{Name: "admin-" + tenant, TenantID: tenant, Roles: []auth.Role{auth.RoleTenantAdmin}}
}

func rulesV(threshold string) []model.Rule {
	return []model.Rule{
		{RuleID: "r-large", Scope: "payments", Action: "transfer", Op: model.OpGTE,
			Field: "amount_cents", Value: threshold, Decision: model.DecisionDeny,
			Reason: "amount >= " + threshold},
		{RuleID: "r-ok", Scope: "payments", Action: "transfer", Op: model.OpLTE,
			Field: "amount_cents", Value: dec(threshold), Decision: model.DecisionAllow,
			Reason: "amount <= " + dec(threshold)},
	}
}

func dec(s string) string {
	switch s {
	case "5000":
		return "4999"
	case "3000":
		return "2999"
	}
	return "0"
}

func ev(id string, amount int64) model.Event {
	return model.Event{
		TenantID: "t1", Source: "payments", EventID: id,
		OccurredAt: time.Now().UTC().Add(time.Duration(0)), Action: "transfer",
		ResourceID: "acct-1", Actor: "alice", AmountCents: amount,
	}
}

func logResult(t *testing.T, tag string, r *model.Result) {
	t.Helper()
	if r == nil {
		t.Logf("[%s] result=<nil>", tag)
		return
	}
	t.Logf("[%s] input=%s amount=%d ruleVersion=v%d evidence=%v finalDecision=%s",
		tag, r.EventKey, r.Event.AmountCents, r.RuleVersion, r.MatchedRules, r.Decision)
}

func TestCrossTenantAndRoleBoundaries(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	t1Admin := adminOf("t1")
	t2Admin := adminOf("t2")
	reader := auth.Principal{Name: "r1", TenantID: "t1", Roles: []auth.Role{auth.RoleTenantReader}}
	auditor := auth.Principal{Name: "auditor", Roles: []auth.Role{auth.RoleGlobalAuditor}}

	if _, err := svc.PublishRules(t1Admin, model.RuleSet{Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestEvent(ctx, t1Admin, ev("e1", 4000)); err != nil {
		t.Fatal(err)
	}

	// 越权：他租户管理员读/重算 t1。
	if _, err := svc.QueryResults(t2Admin, "t1", 0); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant query must be forbidden, got %v", err)
	}
	if _, err := svc.Recompute(ctx, t2Admin, "t1"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant recompute must be forbidden, got %v", err)
	}
	// 越权：他租户管理员向 t1 写事件（事件体租户与身份不符）。
	if _, err := svc.IngestEvent(ctx, t2Admin, ev("x", 1)); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant ingest must be forbidden, got %v", err)
	}
	// 只读角色不可写入/发布/重算。
	if _, err := svc.IngestEvent(ctx, reader, ev("y", 1)); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader ingest must be forbidden, got %v", err)
	}
	if _, err := svc.PublishRules(reader, model.RuleSet{TenantID: "t1", Rules: rulesV("1")}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader publish must be forbidden, got %v", err)
	}
	// 全局审计员只读：可查，不可重算。
	rows, err := svc.QueryResults(auditor, "t1", 0)
	if err != nil {
		t.Fatalf("auditor query failed: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("auditor should see exactly t1 rows, got %d", len(rows))
	}
	if _, err := svc.Recompute(ctx, auditor, "t1"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("auditor recompute must be forbidden, got %v", err)
	}
	// 越权拒绝不得泄露他租户数据：t2 视角为空。
	if rows, _ := svc.QueryResults(t2Admin, "t2", 0); len(rows) != 0 {
		t.Fatalf("t2 must not see t1 data, got %d rows", len(rows))
	}
	t.Log("[authz] all cross-tenant / privilege-escalation attempts rejected; no cross-tenant data leaked")
}

func TestEndToEndRollbackAndRecompute(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	admin := adminOf("t1")

	// v1 阈值 5000，4000 允许；稍后发布 v2 阈值 3000；重算补齐历史槽位后回滚。
	v1, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.IngestEvent(ctx, admin, ev("old", 4000))
	if err != nil {
		t.Fatal(err)
	}
	logResult(t, "ingest@v1", r.Result)
	if r.Result.Decision != model.DecisionAllow || r.Result.RuleVersion != v1.Version {
		t.Fatalf("want ALLOW@v1, got %s@v%d", r.Result.Decision, r.Result.RuleVersion)
	}

	time.Sleep(5 * time.Millisecond)
	v2, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[publish] new current ruleVersion=v%d threshold=3000 (old events still reproducible at v%d)", v2.Version, v1.Version)

	n, err := svc.Recompute(ctx, admin, "t1")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[recompute] filled historical result slots=%d", n)

	// 历史版本结论：旧事件在 v2 下为 DENY，在 v1 下仍为 ALLOW。
	v2rows, err := svc.QueryResults(admin, "t1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(v2rows) != 1 || v2rows[0].Decision != model.DecisionDeny {
		t.Fatalf("historical v2 must reproduce DENY, got %+v", v2rows)
	}
	logResult(t, "history@v2", &v2rows[0])

	// 回滚到 v1，当前查询恢复 ALLOW，v2 历史仍可查询。
	rb, err := svc.RollbackRules(admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[rollback] current ruleVersion=v%d", rb.Version)
	cur, err := svc.QueryResults(admin, "t1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) != 1 || cur[0].Decision != model.DecisionAllow || cur[0].RuleVersion != 1 {
		t.Fatalf("after rollback current must reproduce ALLOW@v1, got %+v", cur)
	}
	logResult(t, "current@after-rollback", &cur[0])

	hist, err := svc.RuleHistory(admin, "t1")
	if err != nil || len(hist) != 2 {
		t.Fatalf("both versions must remain in history, got %d err=%v", len(hist), err)
	}
	v2still, _ := svc.QueryResults(admin, "t1", 2)
	if len(v2still) != 1 || v2still[0].Decision != model.DecisionDeny {
		t.Fatal("v2 historical conclusion must survive rollback")
	}
}

func TestInvalidPublishDoesNotPollute(t *testing.T) {
	svc := newSvc()
	admin := adminOf("t1")
	if _, err := svc.PublishRules(admin, model.RuleSet{Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	bad := model.RuleSet{Rules: []model.Rule{{
		RuleID: "bad", Scope: "payments", Action: "transfer", Op: "BOGUS",
		Field: "amount_cents", Value: "1", Decision: model.DecisionAllow,
	}}}
	if _, err := svc.PublishRules(admin, bad); err == nil {
		t.Fatal("invalid rule publish must fail")
	} else {
		t.Logf("[rules] invalid publish rejected as expected: %v", err)
	}
	hist, _ := svc.RuleHistory(admin, "t1")
	if len(hist) != 1 {
		t.Fatalf("failed publish must not create a version, history=%d", len(hist))
	}
	cur, err := svc.PublishRules(admin, model.RuleSet{Rules: rulesV("3000")})
	if err != nil || cur.Version != 2 {
		t.Fatalf("next valid publish must be v2, got v%d err=%v", cur.Version, err)
	}
}

func TestConcurrentWritesPublishAndRecompute(t *testing.T) {
	// 无背压限制，避免本用例出现 ErrBusy；专注并发一致性。
	svc := New(ingest.Config{LateGrace: time.Minute})
	ctx := context.Background()
	admin := adminOf("t1")

	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}

	const unique = 30
	const replicas = 4
	type spec struct {
		amount int64
		occ    time.Time
	}
	specs := make(map[string]spec, unique)
	base := time.Now().UTC()
	for i := 0; i < unique; i++ {
		id := "evt-" + itoa(i)
		amount := int64(2000)
		if i%2 == 0 {
			amount = 4000 // 一半大额（v2 下结论会翻转）
		}
		// 同一事件的所有副本共享完全相同的业务载荷（含发生时间）。
		specs[id] = spec{amount: amount, occ: base.Add(time.Duration(i) * time.Second)}
	}

	var wg sync.WaitGroup
	writeErr := make(chan error, unique*replicas)

	// 1) 并发写入：每个事件 4 个副本同时投递（内容完全一致）。
	for i := 0; i < unique; i++ {
		id := "evt-" + itoa(i)
		sp := specs[id]
		for r := 0; r < replicas; r++ {
			wg.Add(1)
			go func(id string, sp spec) {
				defer wg.Done()
				e := model.Event{
					TenantID: "t1", Source: "payments", EventID: id,
					OccurredAt: sp.occ, Action: "transfer",
					ResourceID: "acct-1", Actor: "alice", AmountCents: sp.amount,
				}
				res, err := svc.IngestEvent(ctx, admin, e)
				if err != nil {
					writeErr <- err
					return
				}
				if res.Quarantine != nil {
					writeErr <- fmt.Errorf("identical replica quarantined: %s", res.Quarantine.Reason)
				}
			}(id, sp)
		}
	}

	// 2) 规则切换与 3) 重算与写入同时进行。
	switched := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
			writeErr <- fmt.Errorf("concurrent publish: %w", err)
		}
		close(switched)
	}()
	for rc := 0; rc < 4; rc++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-switched
			for k := 0; k < 10; k++ {
				if _, err := svc.Recompute(ctx, admin, "t1"); err != nil {
					writeErr <- err
				}
			}
		}()
	}
	wg.Wait()
	close(writeErr)
	for err := range writeErr {
		t.Fatalf("concurrent path error: %v", err)
	}

	// 最终再做一次全量重算，确保所有历史槽位齐备。
	if _, err := svc.Recompute(ctx, admin, "t1"); err != nil {
		t.Fatal(err)
	}

	// 不变量 1：有效记录数 == 去重后的唯一事件数；无冲突隔离。
	events := svc.mem.ListEvents("t1")
	if len(events) != unique {
		t.Fatalf("valid records=%d want %d (duplicates leaked through)", len(events), unique)
	}
	if q := svc.mem.ListQuarantined("t1"); len(q) != 0 {
		t.Fatalf("identical concurrent replicas must not be quarantined, got %d", len(q))
	}

	// 不变量 2：每个历史版本恰好 unique 条结果，且每条都确定性复现。
	wantDecision := func(version int, amount int64) model.Decision {
		threshold := int64(5000)
		if version >= 2 {
			threshold = 3000
		}
		if amount >= threshold {
			return model.DecisionDeny
		}
		return model.DecisionAllow
	}
	hist, _ := svc.RuleHistory(admin, "t1")
	if len(hist) != 2 {
		t.Fatalf("want exactly 2 published versions, got %d", len(hist))
	}
	seen := 0
	for _, h := range hist {
		rows, err := svc.QueryResults(admin, "t1", h.Version)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != unique {
			t.Fatalf("v%d rows=%d want %d", h.Version, len(rows), unique)
		}
		keys := make(map[string]bool, len(rows))
		for _, row := range rows {
			if row.RuleVersion != h.Version {
				t.Fatalf("slot mismatch: queried v%d got v%d", h.Version, row.RuleVersion)
			}
			if keys[row.EventKey] {
				t.Fatalf("duplicate result slot for %s at v%d", row.EventKey, h.Version)
			}
			keys[row.EventKey] = true
			want := wantDecision(h.Version, row.Event.AmountCents)
			if row.Decision != want {
				t.Fatalf("key=%s v%d amount=%d decision=%s want %s (basis=%v)",
					row.EventKey, h.Version, row.Event.AmountCents, row.Decision, want, row.MatchedRules)
			}
			seen++
		}
	}
	t.Logf("[concurrency] uniqueEvents=%d versions=%d verifiedSlots=%d ruleVersion/decision/basis all consistent",
		unique, len(hist), seen)

	// 不变量 3：v1 结论未被 v2 静默改写（旧版本槽位仍可复现）。
	v1, err := svc.QueryResults(admin, "t1", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range v1 {
		if r.Decision != wantDecision(1, r.Event.AmountCents) {
			t.Fatalf("v1 conclusion rewritten for %s: %s", r.EventKey, r.Decision)
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func TestLateEventBoundaryIsQuarantinedNotRewritten(t *testing.T) {
	base := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	cur := base
	svc := New(ingest.Config{
		LateGrace: 5 * time.Minute,
		Clock:     func() time.Time { return cur },
	})
	ctx := context.Background()
	admin := adminOf("t1")
	if _, err := svc.PublishRules(admin, model.RuleSet{Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	at := func(id string, occ time.Time, amount int64) model.Event {
		return model.Event{
			TenantID: "t1", Source: "payments", EventID: id, OccurredAt: occ,
			Action: "transfer", Actor: "alice", AmountCents: amount,
		}
	}
	// 10:00 事件先到。
	if r, err := svc.IngestEvent(ctx, admin, at("e1", base, 100)); err != nil || !r.Accepted {
		t.Fatalf("first ingest failed: %+v %v", r, err)
	}
	// 09:54（落后 6 分钟）超出 5 分钟宽限 -> LATE 隔离。
	late := at("e2", base.Add(-6*time.Minute), 100)
	r, err := svc.IngestEvent(ctx, admin, late)
	if err != nil {
		t.Fatal(err)
	}
	if r.Quarantine == nil || r.Quarantine.Reason != model.RejectLate {
		t.Fatalf("beyond-grace event must be LATE, got %+v", r.Quarantine)
	}
	t.Logf("[late] key=%s ruleVersion=n/a reason=%s finalResult=quarantined (no valid record, no rewrite)",
		late.Key(), r.Quarantine.Reason)
	if rows, _ := svc.QueryResults(admin, "t1", 0); len(rows) != 1 {
		t.Fatalf("late event must not create a result, rows=%d", len(rows))
	}
}

func TestPreviewDoesNotMutateState(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	admin := adminOf("t1")

	v1, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")})
	if err != nil {
		t.Fatal(err)
	}
	// e1=4000（v1 ALLOW / v2 DENY），e2=6000（两版均 DENY）。
	for _, e := range []model.Event{ev("e1", 4000), ev("e2", 6000)} {
		if r, err := svc.IngestEvent(ctx, admin, e); err != nil || !r.Accepted {
			t.Fatalf("ingest %s failed: %+v %v", e.EventID, r, err)
		}
	}
	before, err := svc.QueryResults(admin, "t1", 0)
	if err != nil || len(before) != 2 {
		t.Fatalf("seed query failed: %d %v", len(before), err)
	}

	// 预演发布 v2（阈值 3000）：e1 会翻转 ALLOW->DENY，e2 不变。
	rep, err := svc.PreviewPublish(admin, model.RuleSet{Note: "v2-candidate", Rules: rulesV("3000")})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[preview-publish] kind=%s baseVersion=v%d candidateVersion=v%d total=%d changed=%d",
		rep.Kind, rep.BaseVersion, rep.CandidateVersion, rep.Total, rep.Changed)
	for _, c := range rep.Changes {
		t.Logf("[preview-publish] input=%s amount=%d base=v%d:%s candidate=v%d:%s changed=%v evidence=%v",
			c.EventKey, c.Event.AmountCents, c.BaseVersion, c.Before, rep.CandidateVersion, c.After, c.Changed, c.MatchedRules)
	}
	if rep.Kind != "publish" || rep.BaseVersion != v1.Version || rep.CandidateVersion != 2 {
		t.Fatalf("unexpected report header: %+v", rep)
	}
	if rep.Total != 2 || rep.Changed != 1 || len(rep.Changes) != 2 {
		t.Fatalf("want total=2 changed=1, got %+v", rep)
	}
	byKey := map[string]model.PreviewChange{}
	for _, c := range rep.Changes {
		byKey[c.EventKey] = c
	}
	if c := byKey["t1|payments|e1"]; c.Before != model.DecisionAllow || c.After != model.DecisionDeny || !c.Changed {
		t.Fatalf("e1 want ALLOW->DENY changed, got %+v", c)
	}
	if c := byKey["t1|payments|e2"]; c.Before != model.DecisionDeny || c.After != model.DecisionDeny || c.Changed {
		t.Fatalf("e2 want DENY->DENY unchanged, got %+v", c)
	}

	// 预演不改状态：当前版本/历史/正式查询结果全部保持原样。
	if hist, _ := svc.RuleHistory(admin, "t1"); len(hist) != 1 {
		t.Fatalf("preview must not publish, history=%d", len(hist))
	}
	after, _ := svc.QueryResults(admin, "t1", 0)
	if len(after) != len(before) {
		t.Fatalf("preview must not create results, before=%d after=%d", len(before), len(after))
	}
	for i := range before {
		if before[i].Decision != after[i].Decision || after[i].RuleVersion != 1 {
			t.Fatalf("formal query result mutated by preview: %+v -> %+v", before[i], after[i])
		}
	}
	if rows, _ := svc.QueryResults(admin, "t1", 2); len(rows) != 0 {
		t.Fatalf("preview conclusions must not leak into formal v2 slots, got %d", len(rows))
	}

	// 只有一个版本时预演回滚：明确失败且无副作用。
	if _, err := svc.PreviewRollback(admin); !errors.Is(err, rules.ErrNothingToRollback) {
		t.Fatalf("want ErrNothingToRollback, got %v", err)
	}
	// 非法候选规则集：与正式发布相同的校验，预演直接失败。
	bad := model.RuleSet{Rules: []model.Rule{{RuleID: "bad", Scope: "*", Action: "*", Op: "BOGUS",
		Field: "amount_cents", Value: "1", Decision: model.DecisionAllow}}}
	if _, err := svc.PreviewPublish(admin, bad); !errors.Is(err, rules.ErrInvalidRule) {
		t.Fatalf("invalid candidate must fail preview, got %v", err)
	}

	// 真正发布 v2 后预演回滚：对照当前 v2 结论，候选为 v1。
	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
		t.Fatal(err)
	}
	repRb, err := svc.PreviewRollback(admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[preview-rollback] kind=%s baseVersion=v%d candidateVersion=v%d total=%d changed=%d",
		repRb.Kind, repRb.BaseVersion, repRb.CandidateVersion, repRb.Total, repRb.Changed)
	if repRb.Kind != "rollback" || repRb.BaseVersion != 2 || repRb.CandidateVersion != 1 {
		t.Fatalf("unexpected rollback preview header: %+v", repRb)
	}
	if repRb.Total != 2 || repRb.Changed != 1 {
		t.Fatalf("rollback preview want total=2 changed=1, got %+v", repRb)
	}
	// 预演回滚同样不改状态：当前仍是 v2，正式查询仍是 v2 结论。
	cur, _ := svc.QueryResults(admin, "t1", 0)
	for _, r := range cur {
		if r.RuleVersion != 2 {
			t.Fatalf("preview rollback must not switch current, got %+v", r)
		}
	}
	t.Log("[preview] reports are read-only: no publish, no result slots, no current-version switch")
}

func TestRollbackClosedLoopForNewEvents(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Hour)
	t2 := t0.Add(4 * time.Hour)
	cur := t0
	svc := New(ingest.Config{LateGrace: 24 * time.Hour, Clock: func() time.Time { return cur }})
	ctx := context.Background()
	admin := adminOf("t1")
	at := func(id string, occ time.Time, amount int64) model.Event {
		return model.Event{
			TenantID: "t1", Source: "payments", EventID: id, OccurredAt: occ,
			Action: "transfer", Actor: "alice", AmountCents: amount,
		}
	}

	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	cur = t1
	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
		t.Fatal(err)
	}
	cur = t2
	rb, err := svc.RollbackRules(admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[rollback] at=%s current ruleVersion=v%d", t2.Format(time.RFC3339), rb.Version)

	// 回滚后新发生的事件：按回滚后当前生效的 v1 判定，且当前查询可见。
	r, err := svc.IngestEvent(ctx, admin, at("new", t2.Add(time.Minute), 4000))
	if err != nil || !r.Accepted {
		t.Fatalf("ingest new failed: %+v %v", r, err)
	}
	logResult(t, "post-rollback-new", r.Result)
	if r.Result.Decision != model.DecisionAllow || r.Result.RuleVersion != 1 {
		t.Fatalf("post-rollback event want ALLOW@v1, got %s@v%d", r.Result.Decision, r.Result.RuleVersion)
	}

	// 回滚前发生（v2 生效时段）、回滚后才到达的迟到事件：
	// 发生时版本 v2 下为 DENY；闭环要求当前版本 v1 查询同样可见（ALLOW@v1）。
	rl, err := svc.IngestEvent(ctx, admin, at("late", t1.Add(30*time.Minute), 4000))
	if err != nil || !rl.Accepted {
		t.Fatalf("ingest late failed: %+v %v", rl, err)
	}
	logResult(t, "post-rollback-late", rl.Result)
	if rl.Result.Decision != model.DecisionDeny || rl.Result.RuleVersion != 2 {
		t.Fatalf("late event want DENY@v2 (version at occurrence), got %s@v%d", rl.Result.Decision, rl.Result.RuleVersion)
	}

	curRows, err := svc.QueryResults(admin, "t1", 0)
	if err != nil || len(curRows) != 2 {
		t.Fatalf("current query must see both events, got %d err=%v", len(curRows), err)
	}
	for _, row := range curRows {
		logResult(t, "current-query", &row)
		if row.RuleVersion != 1 || row.Decision != model.DecisionAllow {
			t.Fatalf("current query must show ALLOW@v1 for every event, got %+v", row)
		}
	}
	v2Rows, _ := svc.QueryResults(admin, "t1", 2)
	if len(v2Rows) != 1 || v2Rows[0].Event.EventID != "late" || v2Rows[0].Decision != model.DecisionDeny {
		t.Fatalf("v2 slot must keep DENY for the late event only, got %+v", v2Rows)
	}

	// 服务层时间轴与按时刻追溯：回滚段可见，边界与判定口径一致。
	tl, err := svc.RuleTimeline(admin, "t1")
	if err != nil || len(tl) != 3 {
		t.Fatalf("want 3 timeline intervals, got %d err=%v", len(tl), err)
	}
	for _, iv := range tl {
		t.Logf("[timeline] v%d [%s, %s) cause=%s current=%v",
			iv.Version, iv.From.Format(time.RFC3339), iv.To.Format(time.RFC3339), iv.Cause, iv.Current)
	}
	if eff, err := svc.EffectiveVersionAt(admin, "t1", t1.Add(30*time.Minute)); err != nil || eff.Version != 2 {
		t.Fatalf("effective@t1+30m want v2, got v%d err=%v", eff.Version, err)
	}
	if eff, err := svc.EffectiveVersionAt(admin, "t1", t2.Add(time.Minute)); err != nil || eff.Version != 1 {
		t.Fatalf("effective@t2+1m want v1 (post-rollback), got v%d err=%v", eff.Version, err)
	}
}

func TestRollbackExhaustedFailsClean(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	admin := adminOf("t1")
	if _, err := svc.PublishRules(admin, model.RuleSet{Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	if r, err := svc.IngestEvent(ctx, admin, ev("e1", 4000)); err != nil || !r.Accepted {
		t.Fatalf("ingest failed: %+v %v", r, err)
	}
	if _, err := svc.RollbackRules(admin); !errors.Is(err, rules.ErrNothingToRollback) {
		t.Fatalf("want ErrNothingToRollback, got %v", err)
	}
	rows, err := svc.QueryResults(admin, "t1", 0)
	if err != nil || len(rows) != 1 || rows[0].RuleVersion != 1 {
		t.Fatalf("failed rollback must not corrupt state, rows=%+v err=%v", rows, err)
	}
	tl, _ := svc.RuleTimeline(admin, "t1")
	if len(tl) != 1 || !tl[0].Current {
		t.Fatalf("timeline must keep single current interval, got %+v", tl)
	}
	t.Log("[rollback] exhausted: explicit failure, current version/results/timeline intact")
}

func TestConcurrentPreviewPublishRollbackAndWrites(t *testing.T) {
	svc := New(ingest.Config{LateGrace: time.Minute})
	ctx := context.Background()
	admin := adminOf("t1")

	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}

	const unique = 24
	const replicas = 3
	base := time.Now().UTC()
	amountOf := func(i int) int64 {
		if i%2 == 0 {
			return 4000 // v1 ALLOW / v2 DENY
		}
		return 2000 // 两版均 ALLOW
	}

	var wg sync.WaitGroup     // 有限任务：写入、发布/回滚、重算
	var loopWg sync.WaitGroup // 循环任务：预演、时间轴巡检（靠 stop 退出）
	errs := make(chan error, 256)

	// 1) 并发写入（每事件 3 个完全相同副本）。
	for i := 0; i < unique; i++ {
		for r := 0; r < replicas; r++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				e := model.Event{
					TenantID: "t1", Source: "payments", EventID: "evt-" + itoa(i),
					OccurredAt: base.Add(time.Duration(i) * time.Second), Action: "transfer",
					ResourceID: "acct-1", Actor: "alice", AmountCents: amountOf(i),
				}
				res, err := svc.IngestEvent(ctx, admin, e)
				if err != nil {
					errs <- err
					return
				}
				if res.Quarantine != nil {
					errs <- fmt.Errorf("identical replica quarantined: %s", res.Quarantine.Reason)
				}
			}(i)
		}
	}

	// 2) 并发预演：只读，报告必须结构自洽，且不得影响正式状态。
	checkReport := func(rep model.PreviewReport) error {
		if rep.Total != len(rep.Changes) {
			return fmt.Errorf("report total=%d but %d changes", rep.Total, len(rep.Changes))
		}
		changed := 0
		for _, c := range rep.Changes {
			if c.BaseVersion != rep.BaseVersion {
				return fmt.Errorf("mixed base versions in one report: %d vs %d", c.BaseVersion, rep.BaseVersion)
			}
			if c.Changed {
				changed++
			}
		}
		if changed != rep.Changed {
			return fmt.Errorf("report changed=%d but counted %d", rep.Changed, changed)
		}
		if rep.Kind == "rollback" && rep.CandidateVersion != rep.BaseVersion-1 {
			return fmt.Errorf("rollback preview candidate=v%d base=v%d", rep.CandidateVersion, rep.BaseVersion)
		}
		return nil
	}
	stop := make(chan struct{})
	for k := 0; k < 3; k++ {
		loopWg.Add(1)
		go func() {
			defer loopWg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				rep, err := svc.PreviewPublish(admin, model.RuleSet{Rules: rulesV("3000")})
				if err == nil {
					if err := checkReport(rep); err != nil {
						errs <- fmt.Errorf("preview publish: %w", err)
					}
				}
				repRb, err := svc.PreviewRollback(admin)
				if err != nil && !errors.Is(err, rules.ErrNothingToRollback) {
					errs <- fmt.Errorf("preview rollback: %w", err)
				} else if err == nil {
					if err := checkReport(repRb); err != nil {
						errs <- fmt.Errorf("preview rollback: %w", err)
					}
				}
			}
		}()
	}

	// 3) 时间轴任意时刻都必须链式自洽：区间首尾相接、恰好一个当前区间。
	loopWg.Add(1)
	go func() {
		defer loopWg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tl, err := svc.RuleTimeline(admin, "t1")
			if err != nil {
				errs <- err
				return
			}
			current := 0
			for i, iv := range tl {
				if iv.Current {
					current++
				}
				if i+1 < len(tl) && !iv.To.Equal(tl[i+1].From) {
					errs <- fmt.Errorf("timeline gap/overlap: %+v -> %+v", iv, tl[i+1])
				}
			}
			if len(tl) > 0 && current != 1 {
				errs <- fmt.Errorf("timeline must have exactly one current interval: %+v", tl)
			}
		}
	}()

	// 4) 规则切换与重算同时进行。
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
			errs <- fmt.Errorf("concurrent publish: %w", err)
		}
		if _, err := svc.RollbackRules(admin); err != nil {
			errs <- fmt.Errorf("concurrent rollback: %w", err)
		}
	}()
	for rc := 0; rc < 3; rc++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(3 * time.Millisecond)
			for k := 0; k < 5; k++ {
				if _, err := svc.Recompute(ctx, admin, "t1"); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()     // 有限任务全部完成
	close(stop)   // 通知预演/巡检循环退出
	loopWg.Wait() // 循环任务全部退出
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent path error: %v", err)
	}

	// 最终全量重算后校验不变量：回滚后当前版本为 v1。
	if _, err := svc.Recompute(ctx, admin, "t1"); err != nil {
		t.Fatal(err)
	}
	events := svc.mem.ListEvents("t1")
	if len(events) != unique {
		t.Fatalf("valid records=%d want %d", len(events), unique)
	}
	hist, _ := svc.RuleHistory(admin, "t1")
	if len(hist) != 2 {
		t.Fatalf("want 2 published versions, got %d", len(hist))
	}
	wantDecision := func(version int, amount int64) model.Decision {
		threshold := int64(5000)
		if version >= 2 {
			threshold = 3000
		}
		if amount >= threshold {
			return model.DecisionDeny
		}
		return model.DecisionAllow
	}
	for _, h := range hist {
		rows, err := svc.QueryResults(admin, "t1", h.Version)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != unique {
			t.Fatalf("v%d rows=%d want %d", h.Version, len(rows), unique)
		}
		keys := map[string]bool{}
		for _, row := range rows {
			if keys[row.EventKey] {
				t.Fatalf("duplicate slot %s at v%d", row.EventKey, h.Version)
			}
			keys[row.EventKey] = true
			if want := wantDecision(h.Version, row.Event.AmountCents); row.Decision != want {
				t.Fatalf("key=%s v%d decision=%s want %s", row.EventKey, h.Version, row.Decision, want)
			}
		}
	}
	// 回滚后当前查询必须是 v1 视角且覆盖全部事件。
	cur, err := svc.QueryResults(admin, "t1", 0)
	if err != nil || len(cur) != unique {
		t.Fatalf("post-rollback current query rows=%d want %d err=%v", len(cur), unique, err)
	}
	for _, row := range cur {
		if row.RuleVersion != 1 {
			t.Fatalf("current query must be v1 view after rollback, got %+v", row)
		}
	}
	t.Logf("[concurrency] uniqueEvents=%d versions=%d previews/timeline consistent, post-rollback current=v1",
		unique, len(hist))
}

func TestPreviewAndTimelineAuthorization(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	t1Admin := adminOf("t1")
	t2Admin := adminOf("t2")
	reader := auth.Principal{Name: "r1", TenantID: "t1", Roles: []auth.Role{auth.RoleTenantReader}}
	auditor := auth.Principal{Name: "auditor", Roles: []auth.Role{auth.RoleGlobalAuditor}}

	if _, err := svc.PublishRules(t1Admin, model.RuleSet{Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestEvent(ctx, t1Admin, ev("e1", 4000)); err != nil {
		t.Fatal(err)
	}

	// 跨租户：t2 管理员对 t1 的预演/时间轴/按时刻追溯一律拒绝。
	if _, err := svc.PreviewPublish(t2Admin, model.RuleSet{TenantID: "t1", Rules: rulesV("3000")}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant preview must be forbidden, got %v", err)
	}
	if _, err := svc.RuleTimeline(t2Admin, "t1"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant timeline must be forbidden, got %v", err)
	}
	if _, err := svc.EffectiveVersionAt(t2Admin, "t1", time.Now()); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant effective-at must be forbidden, got %v", err)
	}

	// 只读角色：预演/时间轴是只读操作，允许；但写入/发布/回滚/重算仍被拒。
	if _, err := svc.PreviewPublish(reader, model.RuleSet{Rules: rulesV("3000")}); err != nil {
		t.Fatalf("reader preview (read-only) must be allowed, got %v", err)
	}
	if _, err := svc.RuleTimeline(reader, "t1"); err != nil {
		t.Fatalf("reader timeline must be allowed, got %v", err)
	}
	if _, err := svc.RollbackRules(reader); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader rollback must be forbidden, got %v", err)
	}
	if _, err := svc.Recompute(ctx, reader, "t1"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader recompute must be forbidden, got %v", err)
	}

	// 全局审计员：可查时间轴/按时刻追溯，任何写操作仍被拒。
	if _, err := svc.RuleTimeline(auditor, "t1"); err != nil {
		t.Fatalf("auditor timeline must be allowed, got %v", err)
	}
	if _, err := svc.EffectiveVersionAt(auditor, "t1", time.Now()); err != nil {
		t.Fatalf("auditor effective-at must be allowed, got %v", err)
	}
	if _, err := svc.PublishRules(auditor, model.RuleSet{TenantID: "t1", Rules: rulesV("1")}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("auditor publish must be forbidden, got %v", err)
	}
	t.Log("[authz] preview/timeline read-only for reader+auditor; all writes still rejected across tenants/roles")
}
