package store

import (
	"sync"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

func TestClaimEvent_ConcurrentSameIDDifferentHash(t *testing.T) {
	log := testutil.NewLogger(t)
	s := New()
	s.RegisterTenant("t1")
	ev := model.Event{TenantID: "t1", EventID: "x", Source: "src", OccurredAt: time.Now()}

	const n = 100
	var wg sync.WaitGroup
	start := make(chan struct{})
	var mu sync.Mutex
	news, dups, conflicts := 0, 0, 0
	for i := 0; i < n; i++ {
		hash := "A"
		if i%2 == 0 {
			hash = "B"
		}
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			<-start
			res, err := s.ClaimEvent(ev, h)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			defer mu.Unlock()
			switch res.Outcome {
			case ClaimNew:
				news++
			case ClaimDuplicate:
				dups++
			case ClaimConflict:
				conflicts++
			}
		}(hash)
	}
	close(start)
	wg.Wait()

	log.Logf("claim contenders=%d -> new=%d same-hash-dups=%d diff-hash-conflicts=%d",
		n, news, dups, conflicts)
	if news != 1 {
		t.Fatalf("exactly one new claim allowed, got %d", news)
	}
	if dups+conflicts != n-1 {
		t.Fatalf("remaining contenders must be dup/conflict, got %d", dups+conflicts)
	}
	if dups == 0 || conflicts == 0 {
		t.Fatalf("expected both duplicate and conflict outcomes, got dups=%d conflicts=%d", dups, conflicts)
	}
}

func TestQuarantine_FirstReasonWins(t *testing.T) {
	log := testutil.NewLogger(t)
	s := New()
	ev := model.Event{TenantID: "t1", EventID: "q1", Source: "src"}
	q1 := s.SaveQuarantine(&model.QuarantineRecord{
		Event: ev, Reason: model.ReasonOutOfOrder, Status: model.StatusPending,
	})
	q2 := s.SaveQuarantine(&model.QuarantineRecord{
		Event: ev, Reason: model.ReasonTooLate, Status: model.StatusRejected,
	})
	if q1.Reason != model.ReasonOutOfOrder || q2.Reason != model.ReasonOutOfOrder {
		t.Fatal("first distinguished quarantine reason must never be overwritten")
	}
	if q2.SeenCount != 2 {
		t.Fatalf("seen count must increment, got %d", q2.SeenCount)
	}
	log.Logf("first reason preserved=%s seen=%d (later reason ignored)", q2.Reason, q2.SeenCount)
}

func TestSaveDecision_FirstWins(t *testing.T) {
	log := testutil.NewLogger(t)
	s := New()
	d1 := &model.Decision{TenantID: "t1", EventID: "d1", Verdict: model.VerdictCompliant, Outcome: "original"}
	d2 := &model.Decision{TenantID: "t1", EventID: "d1", Verdict: model.VerdictNonCompliant, Outcome: "recomputed"}
	ok1, _ := s.SaveDecision(d1)
	ok2, _ := s.SaveDecision(d2)
	if !ok1 || ok2 {
		t.Fatalf("first SaveDecision must win: %v %v", ok1, ok2)
	}
	got, _ := s.GetOriginalDecision("t1", "d1")
	if got.Verdict != model.VerdictCompliant {
		t.Fatalf("original decision was rewritten: %s", got.Verdict)
	}
	log.Logf("immutable original verdict=%s (later write ignored)", got.Verdict)
}

func TestQueryDecisions_TenantIsolation(t *testing.T) {
	log := testutil.NewLogger(t)
	s := New()
	_, _ = s.SaveDecision(&model.Decision{TenantID: "a", EventID: "1", Verdict: model.VerdictCompliant})
	_, _ = s.SaveDecision(&model.Decision{TenantID: "b", EventID: "1", Verdict: model.VerdictNonCompliant})
	a, _ := s.QueryDecisions("a", DecisionFilter{})
	b, _ := s.QueryDecisions("b", DecisionFilter{})
	if len(a) != 1 || a[0].TenantID != "a" || len(b) != 1 || b[0].TenantID != "b" {
		t.Fatal("tenant isolation broken")
	}
	log.Logf("tenant a sees=%d verdict=%s; tenant b sees=%d verdict=%s",
		len(a), a[0].Verdict, len(b), b[0].Verdict)
}
