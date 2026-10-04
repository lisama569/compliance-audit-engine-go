package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/auth"
	"github.com/lisama569/compliance-audit-engine-go/pkg/ingest"
	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/rules"
)

// 预演发布候选规则集：能看清每条事件从什么变成什么、依据哪版规则；
// 且全程只读——生效版本、历史、结果槽位、隔离区一概不变。
func TestDryRunPublishDoesNotMutateState(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	admin := adminOf("t1")

	v1, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []model.Event{ev("a-small", 4000), ev("b-mid", 3500), ev("c-tiny", 1000)} {
		if _, err := svc.IngestEvent(ctx, admin, e); err != nil {
			t.Fatal(err)
		}
	}

	before, err := svc.QueryResults(admin, "t1", 0)
	if err != nil {
		t.Fatal(err)
	}
	histBefore, _ := svc.RuleHistory(admin, "t1")

	// 候选规则：阈值收紧到 3000（若发布将成为 v2）。
	report, err := svc.DryRunRules(admin, model.RuleSet{Note: "candidate", Rules: rulesV("3000")})
	if err != nil {
		t.Fatal(err)
	}
	if report.Scenario != model.DryRunPublish || report.BaseVersion != v1.Version || report.CandidateVersion != 2 {
		t.Fatalf("report basis wrong: %+v", report)
	}
	if report.TotalEvents != 3 || report.ChangedCount != 2 {
		t.Fatalf("want 3 events / 2 changed, got %+v", report)
	}
	for _, it := range report.Items {
		t.Logf("[dryrun:publish] input=%s amount=%d base=v%d:%s preview=v%d:%s changed=%t evidence=%v",
			it.EventKey, it.Event.AmountCents, it.BaseVersion, it.BaseDecision,
			report.CandidateVersion, it.PreviewDecision, it.Changed, it.MatchedRules)
		if it.BaseVersion != v1.Version {
			t.Fatalf("base version must be current v%d, got v%d", v1.Version, it.BaseVersion)
		}
	}
	// a-small(4000) 与 b-mid(3500) 都会从 ALLOW 翻成 DENY，c-tiny(1000) 不变。
	for _, it := range report.Items {
		switch it.EventKey {
		case "t1|payments|a-small", "t1|payments|b-mid":
			if !it.Changed || it.BaseDecision != model.DecisionAllow || it.PreviewDecision != model.DecisionDeny {
				t.Fatalf("%s must flip ALLOW->DENY, got %+v", it.EventKey, it)
			}
			if len(it.MatchedRules) == 0 || it.MatchedRules[0].RuleID != "r-large" {
				t.Fatalf("preview evidence must cite r-large, got %+v", it.MatchedRules)
			}
		default:
			if it.Changed {
				t.Fatalf("%s must be unchanged, got %+v", it.EventKey, it)
			}
		}
	}

	// 只读断言：当前版本、历史、结果、隔离区全部原样。
	cur, err := svc.EffectiveRulesAt(admin, "t1", time.Now().UTC())
	if err != nil || cur.Version != v1.Version {
		t.Fatalf("dry-run must not switch current version, got v%d err=%v", cur.Version, err)
	}
	histAfter, _ := svc.RuleHistory(admin, "t1")
	if len(histAfter) != len(histBefore) {
		t.Fatalf("dry-run must not publish a version, history %d -> %d", len(histBefore), len(histAfter))
	}
	after, _ := svc.QueryResults(admin, "t1", 0)
	if len(after) != len(before) {
		t.Fatalf("dry-run must not write result slots, rows %d -> %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Decision != after[i].Decision || before[i].RuleVersion != after[i].RuleVersion {
			t.Fatalf("result slot mutated by dry-run: %+v -> %+v", before[i], after[i])
		}
	}
	if rows, _ := svc.QueryResults(admin, "t1", report.CandidateVersion); len(rows) != 0 {
		t.Fatalf("preview conclusions must not leak into formal query, got %d rows at v%d",
			len(rows), report.CandidateVersion)
	}
	if q, _ := svc.QueryQuarantined(admin, "t1"); len(q) != 0 {
		t.Fatalf("dry-run must not touch quarantine, got %d", len(q))
	}
	t.Logf("[dryrun:publish] state intact: current=v%d history=%d resultRows=%d quarantined=0",
		cur.Version, len(histAfter), len(after))

	// 候选规则本身非法时，预演与发布同样拒绝。
	bad := model.RuleSet{TenantID: "t1", Rules: []model.Rule{{
		RuleID: "bad", Scope: "payments", Action: "transfer", Op: "BOGUS",
		Field: "amount_cents", Value: "1", Decision: model.DecisionAllow}}}
	if _, err := svc.DryRunRules(admin, bad); !errors.Is(err, rules.ErrInvalidRule) {
		t.Fatalf("invalid candidate must be rejected, got %v", err)
	}
	t.Log("[dryrun:publish] invalid candidate rejected with ErrInvalidRule, no state changed")
}

// 预演回滚：候选为回滚目标历史版本；无可回滚版本时明确失败且状态不变。
func TestDryRunRollbackPreview(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	admin := adminOf("t1")

	// 单版本租户：回滚预演必须明确失败，且状态不变。
	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DryRunRollback(admin); !errors.Is(err, rules.ErrNothingToRollback) {
		t.Fatalf("dry-run rollback with single version must fail, got %v", err)
	}
	cur, _ := svc.EffectiveRulesAt(admin, "t1", time.Now().UTC())
	if cur.Version != 1 {
		t.Fatalf("failed dry-run rollback must not change state, current=v%d", cur.Version)
	}
	t.Log("[dryrun:rollback] no earlier version -> ErrNothingToRollback, current stays v1")

	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestEvent(ctx, admin, ev("d1", 4000)); err != nil {
		t.Fatal(err)
	}
	report, err := svc.DryRunRollback(admin)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scenario != model.DryRunRollback || report.BaseVersion != 2 || report.CandidateVersion != 1 {
		t.Fatalf("rollback preview basis wrong: %+v", report)
	}
	for _, it := range report.Items {
		t.Logf("[dryrun:rollback] input=%s amount=%d base=v%d:%s preview=v%d:%s changed=%t",
			it.EventKey, it.Event.AmountCents, it.BaseVersion, it.BaseDecision,
			report.CandidateVersion, it.PreviewDecision, it.Changed)
	}
	// d1(4000)：v2 下 DENY，回滚到 v1 后应为 ALLOW。
	if report.ChangedCount != 1 || report.Items[0].PreviewDecision != model.DecisionAllow {
		t.Fatalf("rollback preview must show DENY->ALLOW, got %+v", report)
	}
	// 预演回滚同样只读：当前仍是 v2。
	cur, _ = svc.EffectiveRulesAt(admin, "t1", time.Now().UTC())
	if cur.Version != 2 {
		t.Fatalf("dry-run rollback must not move current pointer, current=v%d", cur.Version)
	}
	t.Log("[dryrun:rollback] preview only: current still v2, nothing rolled back")
}

// 新端点权限边界：预演/时间轴/按时刻追溯都是只读（reader 可用），
// 但跨租户一律拒绝；只读角色写入/重算依旧被拒。
func TestDryRunAndTimelineAuthorization(t *testing.T) {
	svc := newSvc()
	ctx := context.Background()
	admin := adminOf("t1")
	t2Admin := adminOf("t2")
	reader := auth.Principal{Name: "r1", TenantID: "t1", Roles: []auth.Role{auth.RoleTenantReader}}

	if _, err := svc.PublishRules(admin, model.RuleSet{Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.IngestEvent(ctx, admin, ev("z1", 4000)); err != nil {
		t.Fatal(err)
	}

	// 只读角色可预演/看时间轴（只读能力）。
	if _, err := svc.DryRunRules(reader, model.RuleSet{TenantID: "t1", Rules: rulesV("3000")}); err != nil {
		t.Fatalf("reader dry-run (read-only) must be allowed, got %v", err)
	}
	if _, err := svc.RuleTimeline(reader, "t1"); err != nil {
		t.Fatalf("reader timeline must be allowed, got %v", err)
	}
	if _, err := svc.EffectiveRulesAt(reader, "t1", time.Now().UTC()); err != nil {
		t.Fatalf("reader effective-at must be allowed, got %v", err)
	}
	t.Log("[authz] reader may dry-run / read timeline (read-only operations)")

	// 跨租户：他租户管理员预演/时间轴/按时刻追溯 t1 一律拒绝。
	if _, err := svc.DryRunRules(t2Admin, model.RuleSet{TenantID: "t1", Rules: rulesV("3000")}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant dry-run must be forbidden, got %v", err)
	}
	if _, err := svc.RuleTimeline(t2Admin, "t1"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant timeline must be forbidden, got %v", err)
	}
	if _, err := svc.EffectiveRulesAt(t2Admin, "t1", time.Now().UTC()); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("cross-tenant effective-at must be forbidden, got %v", err)
	}
	// 只读角色写入/发布/重算仍然被拒。
	if _, err := svc.IngestEvent(ctx, reader, ev("z2", 1)); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader ingest must be forbidden, got %v", err)
	}
	if _, err := svc.PublishRules(reader, model.RuleSet{TenantID: "t1", Rules: rulesV("1")}); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader publish must be forbidden, got %v", err)
	}
	if _, err := svc.Recompute(ctx, reader, "t1"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("reader recompute must be forbidden, got %v", err)
	}
	t.Log("[authz] cross-tenant dry-run/timeline rejected; reader write/publish/recompute still rejected")
}

// 服务层时间轴：发布与回滚都可见，且与按时刻追溯一致。
func TestServiceTimelineReflectsRollback(t *testing.T) {
	base := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	cur := base
	svc := New(ingest.Config{LateGrace: time.Minute, Clock: func() time.Time { return cur }})
	admin := adminOf("t1")

	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v1", Rules: rulesV("5000")}); err != nil {
		t.Fatal(err)
	}
	cur = base.Add(time.Hour)
	if _, err := svc.PublishRules(admin, model.RuleSet{Note: "v2", Rules: rulesV("3000")}); err != nil {
		t.Fatal(err)
	}
	cur = base.Add(2 * time.Hour)
	if _, err := svc.RollbackRules(admin); err != nil {
		t.Fatal(err)
	}

	tl, err := svc.RuleTimeline(admin, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tl) != 3 || tl[2].Cause != model.CauseRollback || tl[2].Version != 1 || !tl[2].Current {
		t.Fatalf("timeline must show rollback to v1 as current, got %+v", tl)
	}
	for _, e := range tl {
		t.Logf("[timeline] version=v%d window=[%s,%s) cause=%s current=%t",
			e.Version, e.EffectiveFrom, e.EffectiveTo, e.Cause, e.Current)
	}
	// 回滚时刻起生效的是 v1；回滚前一刻仍是 v2。
	rs, err := svc.EffectiveRulesAt(admin, "t1", base.Add(2*time.Hour))
	if err != nil || rs.Version != 1 {
		t.Fatalf("at rollback instant want v1, got v%d err=%v", rs.Version, err)
	}
	rs, _ = svc.EffectiveRulesAt(admin, "t1", base.Add(2*time.Hour).Add(-time.Nanosecond))
	if rs.Version != 2 {
		t.Fatalf("just before rollback want v2, got v%d", rs.Version)
	}
	t.Log("[timeline] rollback visible on timeline; effective-at agrees at the boundary")
}
