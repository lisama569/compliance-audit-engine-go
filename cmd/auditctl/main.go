// Command auditctl is a local, fully offline CLI for the compliance audit
// engine. It keeps all state in memory and prints a structured audit trail.
//
// Usage:
//
//	auditctl demo                      # run the built-in end-to-end scenario
//	auditctl -h
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/auth"
	"github.com/lisama569/compliance-audit-engine-go/engine"
	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/store"
)

func main() {
	args := os.Args[1:]
	cmd := "demo"
	if len(args) > 0 {
		cmd = args[0]
	}
	switch cmd {
	case "demo", "-h", "--help", "help":
		if err := runDemo(); err != nil {
			fmt.Fprintln(os.Stderr, "demo failed:", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (try: auditctl demo)\n", cmd)
		os.Exit(2)
	}
}

func runDemo() error {
	cfg := engine.DefaultConfig()
	e := engine.New(cfg)
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	e.SetClock(func() time.Time { return base })

	const tenant = "tenant-a"
	e.RegisterTenant(tenant)

	admin := auth.Principal{ID: "admin@tenant-a", TenantID: tenant, Roles: []string{auth.RoleTenantAdmin}}
	reader := auth.Principal{ID: "reader@tenant-a", TenantID: tenant, Roles: []string{auth.RoleTenantReader}}
	writer := auth.Principal{ID: "writer@tenant-a", TenantID: tenant, Roles: []string{auth.RoleTenantWriter}}

	fmt.Println("== 1. publish rule set v1 ==")
	v1, err := e.PublishRules(admin, tenant, []model.Rule{
		{
			ID: "deny-root-prod", Name: "root login in prod denied",
			EventTypes: []string{"login"}, Priority: 100,
			Conditions: []model.Condition{
				{Field: "user", Operator: model.OpEq, Value: "root"},
				{Field: "env", Operator: model.OpEq, Value: "prod"},
			},
			Verdict: model.VerdictNonCompliant, Reason: "root login prohibited in prod",
		},
		{
			ID: "default-allow", Name: "other logins allowed",
			EventTypes: []string{"login"}, Priority: 1,
			Conditions: []model.Condition{
				{Field: "env", Operator: model.OpExists},
			},
			Verdict: model.VerdictCompliant, Reason: "normal login",
		},
	}, base.Add(-24*time.Hour))
	if err != nil {
		return err
	}
	fmt.Printf("published v%d checksum=%s\n", v1.Version, v1.Checksum)

	mkEvent := func(id string, occurred time.Time, typ string, payload map[string]any) *model.Event {
		return &model.Event{
			TenantID: tenant, EventID: id, Source: "idp", Type: typ,
			OccurredAt: occurred, ReceivedAt: base, Actor: "user", Payload: payload,
		}
	}

	fmt.Println("== 2. ingest events (one compliant, one non-compliant) ==")
	ev1 := mkEvent("evt-1", base.Add(-2*time.Hour), "login", map[string]any{"user": "alice", "env": "prod"})
	ev2 := mkEvent("evt-2", base.Add(-1*time.Hour), "login", map[string]any{"user": "root", "env": "prod"})
	for _, ev := range []*model.Event{ev1, ev2} {
		res, err := e.Ingest(writer, ev)
		if err != nil {
			return err
		}
		printResult(res)
	}

	fmt.Println("== 3. duplicate redelivery of evt-1 ==")
	res, err := e.Ingest(writer, mkEvent("evt-1", base.Add(-2*time.Hour), "login",
		map[string]any{"user": "alice", "env": "prod"}))
	if err != nil {
		return err
	}
	printResult(res)
	if !res.Duplicate {
		return fmt.Errorf("expected duplicate merge")
	}

	fmt.Println("== 4. conflicting redelivery of evt-1 (different user) ==")
	res, err = e.Ingest(writer, mkEvent("evt-1", base.Add(-2*time.Hour), "login",
		map[string]any{"user": "mallory", "env": "prod"}))
	if err != nil {
		return err
	}
	printResult(res)

	fmt.Println("== 5. late event within window, judged by rules at its time ==")
	res, err = e.Ingest(writer, mkEvent("evt-3", base.Add(-20*time.Hour), "login",
		map[string]any{"user": "root", "env": "prod"}))
	if err != nil {
		return err
	}
	printResult(res)

	fmt.Println("== 6. publish v2 (root logins now needs_review), effective now ==")
	v2, err := e.PublishRules(admin, tenant, []model.Rule{
		{
			ID: "review-root-prod", Name: "root login in prod review",
			EventTypes: []string{"login"}, Priority: 100,
			Conditions: []model.Condition{
				{Field: "user", Operator: model.OpEq, Value: "root"},
				{Field: "env", Operator: model.OpEq, Value: "prod"},
			},
			Verdict: model.VerdictNeedsReview, Reason: "root login requires review",
		},
		{
			ID: "default-allow", Name: "other logins allowed",
			EventTypes: []string{"login"}, Priority: 1,
			Conditions: []model.Condition{{Field: "env", Operator: model.OpExists}},
			Verdict:    model.VerdictCompliant, Reason: "normal login",
		},
	}, base)
	if err != nil {
		return err
	}
	fmt.Printf("published v%d checksum=%s\n", v2.Version, v2.Checksum)

	fmt.Println("== 7. recompute tenant: old root events reproduce v1 verdict ==")
	rep, err := e.RecomputeTenant(admin, tenant)
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))

	orig, hist, err := e.DecisionHistory(admin, tenant, "evt-2")
	if err != nil {
		return err
	}
	if len(hist) == 0 {
		return fmt.Errorf("expected recomputation history for evt-2")
	}
	fmt.Printf("evt-2 original: v%d verdict=%s ; recomputations=%d (latest v%d verdict=%s)\n",
		orig.RuleVersion, orig.Verdict, len(hist),
		hist[len(hist)-1].RuleVersion, hist[len(hist)-1].Verdict)

	fmt.Println("== 8. new event after v2 gets needs_review ==")
	res, err = e.Ingest(writer, mkEvent("evt-4", base.Add(30*time.Second), "login",
		map[string]any{"user": "root", "env": "prod"}))
	if err != nil {
		return err
	}
	printResult(res)

	fmt.Println("== 9. rollback to v1 ==")
	v3, err := e.RollbackRules(admin, tenant, v1.Version)
	if err != nil {
		return err
	}
	fmt.Printf("rollback published as v%d (%d rules)\n", v3.Version, len(v3.Rules))

	fmt.Println("== 10. reader attempts recompute -> forbidden ==")
	_, err = e.RecomputeTenant(reader, tenant)
	fmt.Println("error:", err)
	if err == nil {
		return fmt.Errorf("expected forbidden")
	}

	fmt.Println("== 11. cross-tenant access -> forbidden ==")
	other := auth.Principal{ID: "writer@tenant-b", TenantID: "tenant-b", Roles: []string{auth.RoleTenantWriter}}
	_, err = e.QueryDecisions(other, tenant, store.DecisionFilter{})
	fmt.Println("error:", err)

	fmt.Println("== quarantine list ==")
	qs, err := e.ListQuarantine(admin, tenant, "")
	if err != nil {
		return err
	}
	for _, q := range qs {
		fmt.Printf("quarantined event=%s status=%s reason=%s detail=%q\n",
			q.Event.EventID, q.Status, q.Reason, q.Detail)
	}

	fmt.Println("DEMO OK")
	return nil
}

func printResult(res *model.IngestResult) {
	if res.Quarantine != nil {
		fmt.Printf("event=%s -> QUARANTINED status=%s reason=%s detail=%q\n",
			res.EventID, res.Quarantine.Status, res.Quarantine.Reason, res.Quarantine.Detail)
		return
	}
	d := res.Decision
	flag := ""
	if res.Duplicate {
		flag = " [duplicate-merged]"
	}
	fmt.Printf("event=%s -> accepted%s verdict=%s rule=%s v%d basis=%v late=%v reordered=%v\n",
		res.EventID, flag, d.Verdict, d.RuleID, d.RuleVersion, d.Basis, d.Late, d.Reordered)
}
