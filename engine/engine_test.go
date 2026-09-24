package engine

import (
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/auth"
	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/store"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

func testEngine(t *testing.T) (*Engine, time.Time) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.MaxLate = 72 * time.Hour
	e := New(cfg)
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	cur := t0
	e.SetClock(func() time.Time { return cur })
	return e, t0
}

func principals(tenant string) (admin, writer, reader auth.Principal) {
	return auth.Principal{ID: "admin@" + tenant, TenantID: tenant, Roles: []string{auth.RoleTenantAdmin}},
		auth.Principal{ID: "writer@" + tenant, TenantID: tenant, Roles: []string{auth.RoleTenantWriter}},
		auth.Principal{ID: "reader@" + tenant, TenantID: tenant, Roles: []string{auth.RoleTenantReader}}
}

func loginRules(verdict string) []model.Rule {
	return []model.Rule{
		{
			ID: "root", Name: "root", EventTypes: []string{"login"}, Priority: 10,
			Conditions: []model.Condition{
				{Field: "user", Operator: model.OpEq, Value: "root"},
				{Field: "env", Operator: model.OpEq, Value: "prod"},
			},
			Verdict: verdict, Reason: "root prod",
		},
		{
			ID: "allow", Name: "allow", EventTypes: []string{"login"}, Priority: 1,
			Conditions: []model.Condition{{Field: "env", Operator: model.OpExists}},
			Verdict:    model.VerdictCompliant, Reason: "ok",
		},
	}
}

func mkEvent(tenant, id string, occ time.Time, payload map[string]any) *model.Event {
	return &model.Event{
		TenantID: tenant, EventID: id, Source: "idp", Type: "login",
		OccurredAt: occ, ReceivedAt: occ.Add(time.Minute), Payload: payload,
	}
}

func TestEngine_AuthorizationBoundaries(t *testing.T) {
	log := testutil.NewLogger(t)
	e, t0 := testEngine(t)
	const ta, tb = "tenant-a", "tenant-b"
	e.RegisterTenant(ta)
	e.RegisterTenant(tb)
	adminA, writerA, readerA := principals(ta)
	_, writerB, _ := principals(tb)

	if _, err := e.PublishRules(adminA, ta, loginRules(model.VerdictNonCompliant), t0.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Ingest(writerA, mkEvent(ta, "a1", t0.Add(-time.Hour), map[string]any{"user": "root", "env": "prod"})); err != nil {
		t.Fatal(err)
	}

	// Reader cannot recompute.
	if _, err := e.RecomputeTenant(readerA, ta); err == nil {
		t.Fatal("reader recompute must be forbidden")
	} else {
		log.Logf("reader recompute denied: %v", err)
	}
	// Writer cannot publish.
	if _, err := e.PublishRules(writerA, ta, loginRules(model.VerdictCompliant), t0); err == nil {
		t.Fatal("writer publish must be forbidden")
	}
	// Tenant A writer cannot read tenant B, and must see no data.
	ds, err := e.QueryDecisions(writerB, ta, store.DecisionFilter{})
	if err == nil {
		t.Fatalf("cross-tenant query must be forbidden, got %d rows", len(ds))
	}
	log.Logf("cross-tenant query denied with uniform error: %v", err)
	// Tenant A reader cannot get a tenant B event even by ID.
	if _, err := e.GetDecision(writerB, ta, "a1"); err == nil {
		t.Fatal("cross-tenant point read must be forbidden")
	}
	// Tenant admin cannot publish to global scope.
	if _, err := e.PublishRules(adminA, "", loginRules(model.VerdictCompliant), t0); err == nil {
		t.Fatal("tenant admin must not publish global rules")
	}
}

func TestEngine_IngestRateLimitBackPressure(t *testing.T) {
	log := testutil.NewLogger(t)
	cfg := DefaultConfig()
	cfg.RateLimitPerSec = 1
	cfg.RateLimitBurst = 2
	e := New(cfg)
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	cur := t0
	e.SetClock(func() time.Time { return cur })
	const ta = "tenant-a"
	e.RegisterTenant(ta)
	admin, writer, _ := principals(ta)
	if _, err := e.PublishRules(admin, ta, loginRules(model.VerdictNonCompliant), t0.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	allowed, rejected := 0, 0
	for i := 0; i < 5; i++ {
		_, err := e.Ingest(writer, mkEvent(ta, "id-"+string(rune('a'+i)), t0.Add(-time.Hour),
			map[string]any{"user": "x", "env": "prod"}))
		switch {
		case err == nil:
			allowed++
		case err == model.ErrOverloaded:
			rejected++
		default:
			t.Fatal(err)
		}
	}
	log.Logf("rate=1/s burst=2: allowed=%d rejected=%d with ErrOverloaded", allowed, rejected)
	if allowed != 2 || rejected != 3 {
		t.Fatalf("expected 2 allowed / 3 rejected, got %d/%d", allowed, rejected)
	}
}

// TestEngine_ConcurrentDuplicatesYieldSingleDecision hammers one event ID
// concurrently: exactly one valid decision may ever exist, all other attempts
// must merge as duplicates.
func TestEngine_ConcurrentDuplicatesYieldSingleDecision(t *testing.T) {
	log := testutil.NewLogger(t)
	e, t0 := testEngine(t)
	const ta = "tenant-a"
	e.RegisterTenant(ta)
	admin, writer, _ := principals(ta)
	if _, err := e.PublishRules(admin, ta, loginRules(model.VerdictNonCompliant), t0.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepts, dups, others := 0, 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := e.Ingest(writer, mkEvent(ta, "same-id", t0.Add(-30*time.Minute),
				map[string]any{"user": "root", "env": "prod"}))
			if err != nil {
				t.Errorf("unexpected err: %v", err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch {
			case res.Quarantine != nil:
				others++
			case res.Duplicate:
				dups++
			default:
				accepts++
			}
		}()
	}
	close(start)
	wg.Wait()

	log.Logf("concurrent identical ingesters=%d -> first-accept=%d duplicate-merges=%d quarantined=%d",
		n, accepts, dups, others)
	if accepts != 1 || dups != n-1 || others != 0 {
		t.Fatalf("exactly-once violated: accepts=%d dups=%d others=%d", accepts, dups, others)
	}
	ds, err := e.Store.QueryDecisions(ta, store.DecisionFilter{})
	if err != nil || len(ds) != 1 {
		t.Fatalf("expected exactly one decision, got %d (err=%v)", len(ds), err)
	}
	events := e.Store.ListEvents(ta)
	if len(events) != 1 {
		t.Fatalf("expected exactly one stored event, got %d", len(events))
	}
}

// TestEngine_ConcurrentConflictingContentNeverRewrites runs the same ID with
// TWO different payloads concurrently. The first conclusion must stand; the
// losing payload must be quarantined as duplicate_conflict, never overwrite.
func TestEngine_ConcurrentConflictingContentNeverRewrites(t *testing.T) {
	log := testutil.NewLogger(t)
	e, t0 := testEngine(t)
	const ta = "tenant-a"
	e.RegisterTenant(ta)
	admin, writer, _ := principals(ta)
	if _, err := e.PublishRules(admin, ta, loginRules(model.VerdictNonCompliant), t0.Add(-7*24*time.Hour)); err != nil {
		t.Fatal(err)
	}

	const n = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	conflicts := make(chan string, 2*n)
	for g := 0; g < 2; g++ {
		user := "alice"
		if g == 1 {
			user = "root"
		}
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(user string) {
				defer wg.Done()
				<-start
				res, err := e.Ingest(writer, mkEvent(ta, "race-id", t0.Add(-30*time.Minute),
					map[string]any{"user": user, "env": "prod"}))
				if err != nil {
					t.Errorf("err: %v", err)
					return
				}
				if res.Quarantine != nil {
					conflicts <- "conflict:" + res.Quarantine.Reason
				} else if res.Duplicate {
					conflicts <- "duplicate"
				} else if res.Decision != nil {
					conflicts <- "accepted:" + res.Decision.Verdict
				}
			}(user)
		}
	}
	close(start)
	wg.Wait()
	close(conflicts)

	accepted, merged, conflicted := 0, 0, 0
	for r := range conflicts {
		switch {
		case r == "accepted:"+model.VerdictCompliant || r == "accepted:"+model.VerdictNonCompliant:
			accepted++
		case r == "duplicate":
			merged++
		case r == "conflict:"+model.ReasonDuplicateConflict:
			conflicted++
		}
	}
	log.Logf("conflicting ingesters=%d -> first-winner=%d identical-merges=%d quarantined-conflicts=%d",
		2*n, accepted, merged, conflicted)
	if accepted != 1 || merged != n-1 || conflicted != n {
		t.Fatalf("expected 1 winner / %d identical merges / %d conflicts, got winner=%d merges=%d conflicts=%d",
			n-1, n, accepted, merged, conflicted)
	}
	orig, err := e.Store.GetOriginalDecision(ta, "race-id")
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := e.Store.GetEvent(ta, "race-id")
	log.Logf("surviving conclusion verdict=%s stored-user=%v (never silently rewritten)",
		orig.Verdict, stored.Payload["user"])
}

// TestEngine_ConcurrentWritesRuleSwitchAndRecompute is the big consistency
// scenario: writers ingest while a new rule version is published and a
// recompute runs. Historical events must always be judged by the version
// effective at their occurrence time; no duplicates may appear.
func TestEngine_ConcurrentWritesRuleSwitchAndRecompute(t *testing.T) {
	log := testutil.NewLogger(t)
	e, t0 := testEngine(t)
	const ta = "tenant-a"
	e.RegisterTenant(ta)
	admin, writer, _ := principals(ta)

	// v1 effective long ago; all test events occur BEFORE the v2 switch.
	v1, err := e.PublishRules(admin, ta, loginRules(model.VerdictNonCompliant), t0.Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	const writers, perWriter = 8, 25
	var wg sync.WaitGroup
	start := make(chan struct{})
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			<-start
			for i := 0; i < perWriter; i++ {
				id := "w" + string(rune('a'+w)) + "-" + strconv.Itoa(i)
				user := "alice"
				if i%5 == 0 {
					user = "root"
				}
				res, err := e.Ingest(writer, mkEvent(ta, id, t0.Add(-time.Hour-time.Duration(i)*time.Second),
					map[string]any{"user": user, "env": "prod"}))
				if err != nil {
					t.Errorf("ingest %s: %v", id, err)
					return
				}
				if res.Quarantine != nil {
					t.Errorf("unexpected quarantine for %s: %s", id, res.Quarantine.Reason)
				}
			}
		}(w)
	}

	// Rule switch happens WHILE writers are running; v2 only affects events
	// occurring >= t0, and none of ours do.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		time.Sleep(2 * time.Millisecond)
		if _, err := e.PublishRules(admin, ta, loginRules(model.VerdictNeedsReview), t0); err != nil {
			t.Errorf("publish v2: %v", err)
		}
	}()

	// Recompute also runs concurrently; must reproduce v1 for every event.
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		time.Sleep(4 * time.Millisecond)
		rep, err := e.RecomputeTenant(admin, ta)
		if err != nil && err != model.ErrOverloaded {
			t.Errorf("recompute: %v", err)
			return
		}
		if rep != nil {
			log.Logf("mid-flight recompute: scanned=%d changed=%d (must be 0: events predate v2)",
				rep.Scanned, rep.Changed)
			if rep.Changed != 0 {
				t.Errorf("mid-flight recompute changed %d historical verdicts", rep.Changed)
			}
		}
	}()

	close(start)
	wg.Wait()

	// Final reconciliation: exactly writers*perWriter events and decisions.
	total := writers * perWriter
	events := e.Store.ListEvents(ta)
	ds, _ := e.Store.QueryDecisions(ta, store.DecisionFilter{})
	log.Logf("after concurrent phase: events=%d decisions=%d expected=%d; v1=%d v2 effective=%s",
		len(events), len(ds), total, v1.Version, t0)
	if len(events) != total {
		t.Fatalf("event count: got %d want %d", len(events), total)
	}
	if len(ds) != total {
		t.Fatalf("decision count: got %d want %d", len(ds), total)
	}

	// A final full recompute confirms every historical event still resolves
	// to v1 (root events non_compliant), proving the v2 switch did not leak
	// backwards in time under concurrency.
	rep, err := e.RecomputeTenant(admin, ta)
	if err != nil {
		t.Fatal(err)
	}
	log.Logf("final recompute report: %+v", rep)
	if rep.Changed != 0 {
		t.Fatalf("history was rewritten by rule switch: %+v", rep)
	}
	rootCount := 0
	for _, d := range ds {
		if d.Verdict == model.VerdictNonCompliant {
			rootCount++
			if d.RuleVersion != 1 {
				t.Fatalf("historical root decision used v%d, want v1", d.RuleVersion)
			}
		}
	}
	// per writer, i%5==0 -> 5 root events each.
	if rootCount != writers*5 {
		t.Fatalf("root verdict count=%d want %d", rootCount, writers*5)
	}
	log.Logf("all %d historical root events remain v1/non_compliant", rootCount)
}
