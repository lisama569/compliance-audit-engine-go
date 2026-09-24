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
