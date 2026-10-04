// Command audit-demo 在本地离线演示合规审计事件处理全流程：
// 规则发布、事件接入（含重复/乱序/迟到）、规则回滚与重算、越权拒绝。
//
// 运行： go run ./cmd/audit-demo
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/auth"
	"github.com/lisama569/compliance-audit-engine-go/pkg/ingest"
	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/service"
)

func mustPublish(svc *service.Service, p auth.Principal, note string, rs model.RuleSet) model.RuleSet {
	published, err := svc.PublishRules(p, rs)
	if err != nil {
		log.Fatalf("publish %s failed: %v", note, err)
	}
	log.Printf("[publish] tenant=%s version=%d note=%q rules=%d",
		published.TenantID, published.Version, note, len(published.Rules))
	return published
}

func main() {
	logger := log.Default()
	// 统一模拟时钟：v1 在 08:00 发布，演示从 10:00 开始。
	simClock := newSimClock(time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC))
	svc := service.New(ingest.Config{
		MaxInflight: 4,
		RatePerSec:  100,
		RateBurst:   10,
		LateGrace:   5 * time.Minute,
		Clock:       simClock.Now,
	})
	ctx := context.Background()

	admin := auth.Principal{Name: "t1-admin", TenantID: "tenant-1", Roles: []auth.Role{auth.RoleTenantAdmin}}
	reader := auth.Principal{Name: "t1-reader", TenantID: "tenant-1", Roles: []auth.Role{auth.RoleTenantReader}}
	other := auth.Principal{Name: "t2-admin", TenantID: "tenant-2", Roles: []auth.Role{auth.RoleTenantAdmin}}
	auditor := auth.Principal{Name: "global-auditor", Roles: []auth.Role{auth.RoleGlobalAuditor}}

	base := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	v1Publish := base.Add(-1 * time.Hour) // 08:00
	simClock.Set(v1Publish)

	// 规则 v1：大额转账 >= 500000 分直接 DENY。
	mustPublish(svc, admin, "v1 initial", model.RuleSet{Rules: []model.Rule{
		{RuleID: "r-large-amount", Scope: "payments", Action: "transfer",
			Op: model.OpGTE, Field: "amount_cents", Value: "500000",
			Decision: model.DecisionDeny, Reason: "transfer exceeds risk threshold v1"},
		{RuleID: "r-normal", Scope: "payments", Action: "transfer",
			Op: model.OpLTE, Field: "amount_cents", Value: "499999",
			Decision: model.DecisionAllow, Reason: "within normal range v1"},
	}})

	mk := func(id string, occ time.Time, amount int64) model.Event {
		return model.Event{
			TenantID: "tenant-1", Source: "payments", EventID: id,
			OccurredAt: occ, Action: "transfer", ResourceID: "acct-7",
			Actor: "alice", AmountCents: amount,
		}
	}
	ingestOne := func(tag string, ev model.Event) {
		res, err := svc.IngestEvent(ctx, admin, ev)
		if err != nil {
			logger.Printf("[ingest:%s] error: %v", tag, err)
			return
		}
		switch {
		case res.Duplicate:
			logger.Printf("[ingest:%s] duplicate key=%s decision=%s ruleVersion=v%d",
				tag, ev.Key(), res.Result.Decision, res.Result.RuleVersion)
		case res.Quarantine != nil:
			logger.Printf("[ingest:%s] quarantined key=%s reason=%s detail=%s",
				tag, ev.Key(), res.Quarantine.Reason, res.Quarantine.Detail)
		default:
			logger.Printf("[ingest:%s] accepted key=%s decision=%s ruleVersion=v%d evidence=%d",
				tag, ev.Key(), res.Result.Decision, res.Result.RuleVersion, len(res.Result.MatchedRules))
		}
	}

	// 按乱序顺序接入：先 09:03（随后被 09:30/10:00 越过但在 5 分钟窗口内，接受），
	// 再发正常事件与完全重复。
	ingestOne("out-of-order-in-window", mk("evt-3", base.Add(3*time.Minute), 200000))
	ingestOne("normal-400000", mk("evt-1", base.Add(30*time.Minute), 400000))
	ingestOne("duplicate", mk("evt-1", base.Add(30*time.Minute), 400000))
	ingestOne("large-600000", mk("evt-2", base.Add(60*time.Minute), 600000))

	// 乱序超出 5 分钟宽限窗口（08:50 落后已观测的 10:00）-> LATE 隔离。
	ingestOne("out-of-order-late", mk("evt-4", base.Add(-10*time.Minute), 100000))

	// 同键不同内容 -> CONFLICT 隔离。
	conflict := mk("evt-1", base.Add(30*time.Minute), 999999)
	conflict.Actor = "mallory"
	ingestOne("conflict", conflict)

	// 缺字段 -> INVALID 隔离。
	ingestOne("invalid", model.Event{TenantID: "tenant-1", Source: "payments"})

	// 规则 v2：阈值收紧到 300000；旧事件仍可按 v1 复现。
	simClock.Set(base.Add(2 * time.Hour)) // 11:00 发布 v2
	v2 := mustPublish(svc, admin, "v2 tighter threshold", model.RuleSet{Rules: []model.Rule{
		{RuleID: "r-large-amount", Scope: "payments", Action: "transfer",
			Op: model.OpGTE, Field: "amount_cents", Value: "300000",
			Decision: model.DecisionDeny, Reason: "transfer exceeds risk threshold v2"},
		{RuleID: "r-normal", Scope: "payments", Action: "transfer",
			Op: model.OpLTE, Field: "amount_cents", Value: "299999",
			Decision: model.DecisionAllow, Reason: "within normal range v2"},
	}})

	// v2 之后发生的新事件按 v2 判定。
	ingestOne("under-v2", mk("evt-5", v2.PublishedAt.Add(10*time.Minute), 250000))
	ingestOne("denied-v2", mk("evt-6", v2.PublishedAt.Add(20*time.Minute), 320000))

	// 预演发布 v3（阈值 400000）：只读报告，不发布、不写结果、不影响正式查询。
	preview, err := svc.PreviewPublish(admin, model.RuleSet{Rules: []model.Rule{
		{RuleID: "r-large-amount", Scope: "payments", Action: "transfer",
			Op: model.OpGTE, Field: "amount_cents", Value: "400000",
			Decision: model.DecisionDeny, Reason: "transfer exceeds risk threshold v3"},
		{RuleID: "r-normal", Scope: "payments", Action: "transfer",
			Op: model.OpLTE, Field: "amount_cents", Value: "399999",
			Decision: model.DecisionAllow, Reason: "within normal range v3"},
	}})
	if err != nil {
		log.Fatalf("preview publish failed: %v", err)
	}
	logger.Printf("[preview:publish] base=v%d candidate=v%d total=%d changed=%d",
		preview.BaseVersion, preview.CandidateVersion, preview.Total, preview.Changed)
	for _, c := range preview.Changes {
		if c.Changed {
			logger.Printf("[preview:publish] key=%s %s->%s (v%d->v%d)",
				c.EventKey, c.Before, c.After, c.BaseVersion, preview.CandidateVersion)
		}
	}

	// 预演回滚到 v1：只读，不执行回滚。
	repRb, err := svc.PreviewRollback(admin)
	if err != nil {
		log.Fatalf("preview rollback failed: %v", err)
	}
	logger.Printf("[preview:rollback] base=v%d candidate=v%d total=%d changed=%d",
		repRb.BaseVersion, repRb.CandidateVersion, repRb.Total, repRb.Changed)

	// 历史重算：为每个历史版本补齐结果槽位。
	n, err := svc.Recompute(ctx, admin, "tenant-1")
	if err != nil {
		log.Fatalf("recompute failed: %v", err)
	}
	logger.Printf("[recompute] tenant=tenant-1 slotsFilled=%d", n)

	// 回滚到 v1。
	simClock.Set(base.Add(3 * time.Hour)) // 12:00 回滚
	rb, err := svc.RollbackRules(admin)
	if err != nil {
		log.Fatalf("rollback failed: %v", err)
	}
	logger.Printf("[rollback] tenant=tenant-1 current=v%d", rb.Version)

	// 回滚闭环：回滚后新发生的事件按回滚后当前生效的 v1 判定，当前查询可见。
	ingestOne("post-rollback", mk("evt-7", base.Add(3*time.Hour+10*time.Minute), 320000))

	// 生效时间轴与按时刻追溯。
	tl, _ := svc.RuleTimeline(admin, "tenant-1")
	for _, iv := range tl {
		to := "open"
		if !iv.To.IsZero() {
			to = iv.To.Format(time.RFC3339)
		}
		logger.Printf("[timeline] v%d [%s, %s) cause=%s current=%t",
			iv.Version, iv.From.Format(time.RFC3339), to, iv.Cause, iv.Current)
	}
	if eff, err := svc.EffectiveVersionAt(admin, "tenant-1", base.Add(2*time.Hour+30*time.Minute)); err == nil {
		logger.Printf("[effective-at] 11:30 -> v%d", eff.Version)
	}
	if eff, err := svc.EffectiveVersionAt(admin, "tenant-1", base.Add(3*time.Hour+30*time.Minute)); err == nil {
		logger.Printf("[effective-at] 12:30 -> v%d (post-rollback)", eff.Version)
	}

	// 查询：当前版本（v1）、历史 v2、隔离区。
	show := func(tag string, p auth.Principal, tenant string, ver int) {
		results, err := svc.QueryResults(p, tenant, ver)
		if err != nil {
			logger.Printf("[query:%s] denied/error: %v", tag, err)
			return
		}
		for _, r := range results {
			logger.Printf("[query:%s] key=%s decision=%s ruleVersion=v%d recomputed=%t",
				tag, r.EventKey, r.Decision, r.RuleVersion, r.Recomputed)
		}
	}
	show("current-v1", admin, "tenant-1", 0)
	show("history-v2", admin, "tenant-1", 2)
	show("history-v1", admin, "tenant-1", 1)

	q, _ := svc.QueryQuarantined(admin, "tenant-1")
	for _, qe := range q {
		logger.Printf("[quarantine] key=%s reason=%s", qe.Event.Key(), qe.Reason)
	}
	hist, _ := svc.RuleHistory(admin, "tenant-1")
	for _, h := range hist {
		logger.Printf("[history] version=v%d publishedAt=%s", h.Version, h.PublishedAt.Format(time.RFC3339))
	}

	// 越权演示：他租户管理员访问 tenant-1；只读角色尝试写入；全局审计员尝试重算。
	if _, err := svc.QueryResults(other, "tenant-1", 0); err != nil {
		fmt.Printf("[authz] cross-tenant query rejected: %v\n", err)
	}
	if _, err := svc.IngestEvent(ctx, reader, mk("evt-x", base, 1)); err != nil {
		fmt.Printf("[authz] reader ingest rejected: %v\n", err)
	}
	if _, err := svc.Recompute(ctx, auditor, "tenant-1"); err != nil {
		fmt.Printf("[authz] auditor recompute rejected: %v\n", err)
	}
	// 全局审计员只读可跨租户查询，但结果内容只属于被显式指定的租户。
	results, err := svc.QueryResults(auditor, "tenant-1", 0)
	if err != nil {
		log.Fatalf("auditor query failed: %v", err)
	}
	fmt.Printf("[authz] global auditor read tenant-1 rows=%d\n", len(results))

	// 非法规则发布必须被拒绝且不污染生效状态。
	if _, err := svc.PublishRules(admin, model.RuleSet{Rules: []model.Rule{
		{RuleID: "bad", Scope: "payments", Action: "transfer", Op: "BOGUS",
			Field: "amount_cents", Value: "1", Decision: model.DecisionAllow},
	}}); err != nil {
		fmt.Printf("[rules] invalid publish rejected: %v\n", err)
	}
	cur, _ := svc.RuleHistory(admin, "tenant-1")
	fmt.Printf("[rules] history unchanged, versions=%d (invalid publish did not pollute)\n", len(cur))
}

// simClock 是演示用的可控时钟。
type simClock struct{ t time.Time }

func newSimClock(t time.Time) *simClock { return &simClock{t: t.UTC()} }
func (c *simClock) Now() time.Time      { return c.t }
func (c *simClock) Set(t time.Time)     { c.t = t.UTC() }
