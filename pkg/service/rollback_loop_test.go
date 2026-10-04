package service

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/ingest"
	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/rules"
)

// 回滚闭环：回滚生效后，新发生的事件按回滚后当前版本判定并出现在当前查询里；
// 回滚后才到达的乱序旧事件同样在当前版本查询可见（发生时版本槽位也保留）；
// 没有更早版本可回滚时明确失败且状态不变。
func TestRollbackClosesLoopForNewEvents(t *testing.T) {
	base := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	cur := base
	svc := New(ingest.Config{LateGrace: 2 * time.Hour, Clock: func() time.Time { return cur }})
	ctx := context.Background()
	admin := adminOf("t1")
	at := func(id string, occ time.Time, amount int64) model.Event {
		return model.Event{
			TenantID: "t1", Source: "payments", EventID: id, OccurredAt: occ,
			Action: "transfer", ResourceID: "acct-1", Actor: "alice", AmountCents: amount,
		}
	}

	// v1 阈值 5000：e1(4000) -> ALLOW@v1。
	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	r1, err := svc.IngestEvent(ctx, admin, at("e1", base.Add(10*time.Minute), 4000))
	if err != nil {
		t.Fatal(err)
	}
	logResult(t, "before-v2", r1.Result)

	// v2 阈值 3000：e2(3500) -> DENY@v2。
	cur = base.Add(time.Hour)
	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
		t.Fatal(err)
	}
	r2, err := svc.IngestEvent(ctx, admin, at("e2", base.Add(70*time.Minute), 3500))
	if err != nil {
		t.Fatal(err)
	}
	logResult(t, "under-v2", r2.Result)
	if r2.Result.Decision != model.DecisionDeny || r2.Result.RuleVersion != 2 {
		t.Fatalf("e2 want DENY@v2, got %s@v%d", r2.Result.Decision, r2.Result.RuleVersion)
	}

	// 回滚到 v1。
	cur = base.Add(2 * time.Hour)
	rb, err := svc.RollbackRules(admin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[rollback] current=v%d at %s", rb.Version, cur)

	// 新发生事件 e3(4500)：按回滚后当前版本 v1 判定 -> ALLOW，且当前查询可见。
	r3, err := svc.IngestEvent(ctx, admin, at("e3", base.Add(130*time.Minute), 4500))
	if err != nil {
		t.Fatal(err)
	}
	logResult(t, "after-rollback-new", r3.Result)
	if r3.Result.Decision != model.DecisionAllow || r3.Result.RuleVersion != 1 {
		t.Fatalf("post-rollback event must be judged by rolled-back v1, got %s@v%d",
			r3.Result.Decision, r3.Result.RuleVersion)
	}

	// 乱序旧事件 e4(3200) 发生在 v2 生效窗口内、回滚后才到达：
	// 发生时版本槽位为 DENY@v2，同时当前版本（v1）槽位也被补齐 -> 当前查询可见。
	r4, err := svc.IngestEvent(ctx, admin, at("e4", base.Add(80*time.Minute), 3200))
	if err != nil {
		t.Fatal(err)
	}
	logResult(t, "after-rollback-out-of-order", r4.Result)
	if r4.Result.Decision != model.DecisionDeny || r4.Result.RuleVersion != 2 {
		t.Fatalf("out-of-order event keeps occurrence-time version, want DENY@v2, got %s@v%d",
			r4.Result.Decision, r4.Result.RuleVersion)
	}

	// 当前查询（v1）：四条事件全部可见，判定与 v1 规则一致。
	curRows, err := svc.QueryResults(admin, "t1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(curRows) != 4 {
		t.Fatalf("current query must show all 4 events after rollback, got %d", len(curRows))
	}
	byKey := make(map[string]model.Result, len(curRows))
	for _, row := range curRows {
		if row.RuleVersion != 1 {
			t.Fatalf("current query row must be at v1, got v%d for %s", row.RuleVersion, row.EventKey)
		}
		byKey[row.EventKey] = row
		t.Logf("[query:current] key=%s amount=%d ruleVersion=v%d finalDecision=%s",
			row.EventKey, row.Event.AmountCents, row.RuleVersion, row.Decision)
	}
	if got := byKey["t1|payments|e3"].Decision; got != model.DecisionAllow {
		t.Fatalf("e3 in current query want ALLOW, got %s", got)
	}
	if got := byKey["t1|payments|e4"].Decision; got != model.DecisionAllow {
		t.Fatalf("e4 must also appear in current query as ALLOW@v1, got %s", got)
	}
	// 发生时视角同样可查：e4 在 v2 下仍是 DENY（两个视角互不矛盾、各自稳定）。
	v2Rows, _ := svc.QueryResults(admin, "t1", 2)
	found := false
	for _, row := range v2Rows {
		if row.EventKey == "t1|payments|e4" {
			found = true
			if row.Decision != model.DecisionDeny {
				t.Fatalf("e4@v2 want DENY, got %s", row.Decision)
			}
		}
	}
	if !found {
		t.Fatal("e4 occurrence-time slot at v2 must be queryable")
	}
	t.Log("[rollback-loop] new & out-of-order events visible in current query; occurrence-time view intact")

	// 再次回滚：v1 之前没有更早版本，必须明确失败且状态不变。
	if _, err := svc.RollbackRules(admin); !errors.Is(err, rules.ErrNothingToRollback) {
		t.Fatalf("rollback beyond earliest version must fail, got %v", err)
	}
	curRows2, _ := svc.QueryResults(admin, "t1", 0)
	if len(curRows2) != 4 {
		t.Fatalf("failed rollback must not corrupt state, rows=%d", len(curRows2))
	}
	tl, _ := svc.RuleTimeline(admin, "t1")
	if len(tl) != 3 || !tl[2].Current || tl[2].Version != 1 {
		t.Fatalf("failed rollback must not append timeline entries, got %+v", tl)
	}
	t.Log("[rollback-loop] rollback beyond earliest version rejected; state intact")
}

// 并发闭环：发布、回滚、预演、重算与写入同时进行，
// 每个事件在各版本下结论唯一且稳定，当前查询始终覆盖全部事件。
func TestConcurrentDryRunRollbackPublishAndIngest(t *testing.T) {
	svc := New(ingest.Config{LateGrace: time.Hour})
	ctx := context.Background()
	admin := adminOf("t1")

	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}

	const unique = 24
	base := time.Now().UTC()
	amountOf := func(i int) int64 {
		if i%2 == 0 {
			return 4000 // v1 下 ALLOW，收紧版本下 DENY
		}
		return 2000
	}

	errCh := make(chan error, 256)
	var wg sync.WaitGroup

	// 写入：唯一事件并发接入。
	for i := 0; i < unique; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := model.Event{
				TenantID: "t1", Source: "payments", EventID: "ce-" + itoa(i),
				OccurredAt: base.Add(time.Duration(i) * time.Second), Action: "transfer",
				ResourceID: "acct-1", Actor: "alice", AmountCents: amountOf(i),
			}
			if _, err := svc.IngestEvent(ctx, admin, e); err != nil {
				errCh <- fmt.Errorf("ingest %d: %w", i, err)
			}
		}(i)
	}

	// 预演：与写入/切换并发，只能读不能出错。
	reports := make(chan model.DryRunReport, 16)
	for k := 0; k < 4; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rep, err := svc.DryRunRules(admin, model.RuleSet{TenantID: "t1", Rules: rulesV("3000")})
			if err != nil {
				errCh <- fmt.Errorf("dry-run: %w", err)
				return
			}
			reports <- rep
		}()
	}

	// 规则切换：发布 v2 后并发回滚（回滚到尽头允许明确失败）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(2 * time.Millisecond)
		if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
			errCh <- fmt.Errorf("publish v2: %w", err)
		}
	}()
	for k := 0; k < 2; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Millisecond)
			if _, err := svc.RollbackRules(admin); err != nil && !errors.Is(err, rules.ErrNothingToRollback) {
				errCh <- fmt.Errorf("rollback: %w", err)
			}
		}()
	}
	// 重算并发。
	for k := 0; k < 2; k++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(3 * time.Millisecond)
			if _, err := svc.Recompute(ctx, admin, "t1"); err != nil {
				errCh <- fmt.Errorf("recompute: %w", err)
			}
		}()
	}
	wg.Wait()
	close(errCh)
	close(reports)
	for err := range errCh {
		t.Fatalf("concurrent path error: %v", err)
	}

	// 预演报告内部自洽：计数一致、基准版本统一、候选版本为“发布时的下一版本号”。
	for rep := range reports {
		if rep.TotalEvents != len(rep.Items) {
			t.Fatalf("report TotalEvents=%d but items=%d", rep.TotalEvents, len(rep.Items))
		}
		changed := 0
		for _, it := range rep.Items {
			if it.BaseVersion != rep.BaseVersion {
				t.Fatalf("mixed base versions in one report: %+v vs %d", it, rep.BaseVersion)
			}
			if it.Changed {
				changed++
			}
		}
		if changed != rep.ChangedCount {
			t.Fatalf("ChangedCount=%d but counted %d", rep.ChangedCount, changed)
		}
		t.Logf("[concurrent-dryrun] scenario=%s base=v%d candidate=v%d events=%d changed=%d",
			rep.Scenario, rep.BaseVersion, rep.CandidateVersion, rep.TotalEvents, rep.ChangedCount)
	}

	// 最终全量重算后校验不变量。
	if _, err := svc.Recompute(ctx, admin, "t1"); err != nil {
		t.Fatal(err)
	}
	hist, _ := svc.RuleHistory(admin, "t1")
	wantDecision := func(version int, amount int64) model.Decision {
		threshold := int64(5000) // v1
		if version >= 2 {        // 后续版本阈值均为 3000
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
		seen := make(map[string]bool, len(rows))
		for _, row := range rows {
			if seen[row.EventKey] {
				t.Fatalf("duplicate slot for %s at v%d", row.EventKey, h.Version)
			}
			seen[row.EventKey] = true
			if want := wantDecision(h.Version, row.Event.AmountCents); row.Decision != want {
				t.Fatalf("key=%s v%d decision=%s want %s (basis=%v)",
					row.EventKey, h.Version, row.Decision, want, row.MatchedRules)
			}
		}
	}
	// 闭环不变量：当前查询覆盖全部事件，且每条的判定版本就是当前生效版本。
	curRows, err := svc.QueryResults(admin, "t1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(curRows) != unique {
		t.Fatalf("current query must cover all %d events, got %d", unique, len(curRows))
	}
	curRS, err := svc.EffectiveRulesAt(admin, "t1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range curRows {
		if row.RuleVersion != curRS.Version {
			t.Fatalf("current query row %s at v%d but current is v%d", row.EventKey, row.RuleVersion, curRS.Version)
		}
	}
	t.Logf("[concurrent-loop] versions=%d events=%d current=v%d: per-version decisions unique & stable, current query complete",
		len(hist), unique, curRS.Version)
}
