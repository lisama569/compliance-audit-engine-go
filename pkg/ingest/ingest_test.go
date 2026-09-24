package ingest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/store"
)

// fakeEvaluator 直接产出固定版本结果，避免接入层测试依赖规则注册表。
type fakeEvaluator struct {
	mu       sync.Mutex
	calls    int
	decision model.Decision
}

func (f *fakeEvaluator) Evaluate(ev model.Event) (model.Result, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	return model.Result{
		TenantID: ev.TenantID, EventKey: ev.Key(), Event: ev,
		Decision: f.decision, RuleVersion: 1,
	}, nil
}

type harness struct {
	st  *store.Memory
	ev  *fakeEvaluator
	in  *Ingester
	now time.Time
}

func newHarness(t *testing.T, grace time.Duration, cfgExtra func(*Config)) *harness {
	t.Helper()
	now := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := store.NewMemory()
	fe := &fakeEvaluator{decision: model.DecisionAllow}
	cfg := Config{LateGrace: grace, Clock: clock}
	if cfgExtra != nil {
		cfgExtra(&cfg)
	}
	return &harness{st: st, ev: fe, in: New(st, fe, cfg), now: now}
}

func mk(id string, occ time.Time, amount int64) model.Event {
	return model.Event{
		TenantID: "t1", Source: "payments", EventID: id, OccurredAt: occ,
		Action: "transfer", Actor: "alice", AmountCents: amount,
	}
}

func TestDuplicateIsIdempotent(t *testing.T) {
	h := newHarness(t, time.Minute, nil)
	e := mk("e1", h.now.Add(-30*time.Second), 100)

	r1, err := h.in.Ingest(context.Background(), e)
	if err != nil || !r1.Accepted || r1.Result == nil {
		t.Fatalf("first ingest: %+v err=%v", r1, err)
	}
	t.Logf("input key=%s amount=%d ruleVersion=v%d basis=%v result=%s",
		e.Key(), e.AmountCents, r1.Result.RuleVersion, r1.Result.MatchedRules, r1.Result.Decision)

	// 完全重复（即使重放时系统时间更晚）幂等返回，不触发第二次有效判定。
	r2, err := h.in.Ingest(context.Background(), e)
	if err != nil || !r2.Duplicate || r2.Result == nil {
		t.Fatalf("duplicate ingest: %+v err=%v", r2, err)
	}
	events := h.st.ListEvents("t1")
	if len(events) != 1 {
		t.Fatalf("duplicate must not create a second valid record, got %d", len(events))
	}
	if q := h.st.ListQuarantined("t1"); len(q) != 0 {
		t.Fatalf("exact duplicate must not be quarantined, got %d", len(q))
	}
	t.Logf("replay key=%s duplicate=true finalDecision=%s validRecords=%d",
		e.Key(), r2.Result.Decision, len(events))
}

func TestOutOfOrderWithinGraceAccepted(t *testing.T) {
	h := newHarness(t, 5*time.Minute, nil)
	// 先接收 10:00 事件，再来 09:58 事件，落在 5 分钟窗口内。
	first := mk("e1", h.now, 100)
	second := mk("e2", h.now.Add(-2*time.Minute), 200)
	if r, err := h.in.Ingest(context.Background(), first); err != nil || !r.Accepted {
		t.Fatalf("first: %+v err=%v", r, err)
	}
	r, err := h.in.Ingest(context.Background(), second)
	if err != nil || !r.Accepted {
		t.Fatalf("in-window out-of-order must be accepted: %+v err=%v", r, err)
	}
	t.Logf("out-of-order key=%s lag=2m grace=5m result=%s", second.Key(), r.Result.Decision)
}

func TestLateBeyondGraceQuarantined(t *testing.T) {
	h := newHarness(t, 5*time.Minute, nil)
	first := mk("e1", h.now, 100)
	if _, err := h.in.Ingest(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	late := mk("e2", h.now.Add(-10*time.Minute), 100)
	r, err := h.in.Ingest(context.Background(), late)
	if err != nil {
		t.Fatal(err)
	}
	if r.Quarantine == nil || r.Quarantine.Reason != model.RejectLate {
		t.Fatalf("late event must be quarantined as LATE, got %+v", r.Quarantine)
	}
	if _, ok := h.st.GetEvent("t1", late.Key()); ok {
		t.Fatal("late event must not enter valid records")
	}
	t.Logf("late key=%s reason=%s detail=%s", late.Key(), r.Quarantine.Reason, r.Quarantine.Detail)
}

func TestConflictSameKeyDifferentPayload(t *testing.T) {
	h := newHarness(t, 5*time.Minute, nil)
	e := mk("e1", h.now, 100)
	if r, err := h.in.Ingest(context.Background(), e); err != nil || !r.Accepted {
		t.Fatalf("first: %+v err=%v", r, err)
	}
	tampered := mk("e1", h.now, 9999) // 同键、不同金额
	r, err := h.in.Ingest(context.Background(), tampered)
	if err != nil {
		t.Fatal(err)
	}
	if r.Quarantine == nil || r.Quarantine.Reason != model.RejectConflict {
		t.Fatalf("tampered replay must be CONFLICT, got %+v", r.Quarantine)
	}
	existing, _ := h.st.GetEvent("t1", e.Key())
	if existing.AmountCents != 100 {
		t.Fatal("conflicting replay must not rewrite existing record")
	}
	t.Logf("conflict key=%s reason=%s originalAmount=%d replayAmount=%d",
		e.Key(), r.Quarantine.Reason, existing.AmountCents, tampered.AmountCents)
}

func TestInvalidEventQuarantined(t *testing.T) {
	h := newHarness(t, time.Minute, nil)
	bad := model.Event{TenantID: "t1", Source: "payments"}
	r, err := h.in.Ingest(context.Background(), bad)
	if err != nil {
		t.Fatalf("invalid event is a structured result, not error: %v", err)
	}
	if r.Quarantine == nil || r.Quarantine.Reason != model.RejectInvalid {
		t.Fatalf("want INVALID quarantine, got %+v", r.Quarantine)
	}
	t.Logf("invalid reason=%s detail=%s", r.Quarantine.Reason, r.Quarantine.Detail)
}

func TestBackpressureAndRateLimit(t *testing.T) {
	// MaxInflight=1：第一个占用槽位的请求进行中时，第二个请求必须立即收到 ErrBusy。
	release := make(chan struct{})
	fe := &blockingEvaluator{release: release, started: make(chan struct{}), decision: model.DecisionAllow}
	st := store.NewMemory()
	in := New(st, fe, Config{MaxInflight: 1, LateGrace: time.Minute})

	done := make(chan struct{})
	go func() {
		_, _ = in.Ingest(context.Background(), mk("e1", time.Now().UTC(), 1))
		close(done)
	}()
	fe.waitStarted()

	if _, err := in.Ingest(context.Background(), mk("e2", time.Now().UTC(), 1)); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy under inflight saturation, got %v", err)
	}
	t.Logf("backpressure: second request rejected with ErrBusy while one in flight")
	close(release)
	<-done

	// 令牌桶限流：速率 1/s、突发 1，连发 3 个必有拒绝。
	st2 := store.NewMemory()
	in2 := New(st2, &fakeEvaluator{decision: model.DecisionAllow}, Config{
		RatePerSec: 1, RateBurst: 1, LateGrace: time.Minute,
		Clock: func() time.Time { return fixedTime },
	})
	busy := 0
	for i := 0; i < 3; i++ {
		_, err := in2.Ingest(context.Background(), mk(idN(i), fixedTime.Add(-time.Duration(i)*time.Second), 1))
		if errors.Is(err, ErrBusy) {
			busy++
		}
	}
	if busy == 0 {
		t.Fatal("rate limiter must reject at least one burst request")
	}
	t.Logf("rate limit: rejected=%d/3 under 1rps burst=1", busy)
}

var fixedTime = time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)

func idN(i int) string { return "e-rate-" + string(rune('a'+i)) }

// blockingEvaluator 用于稳定复现“槽位被占满”的背压时刻。
type blockingEvaluator struct {
	release  chan struct{}
	started  chan struct{}
	decision model.Decision
}

func (b *blockingEvaluator) waitStarted() {
	<-b.started
}

func (b *blockingEvaluator) Evaluate(ev model.Event) (model.Result, error) {
	close(b.started)
	<-b.release
	return model.Result{TenantID: ev.TenantID, EventKey: ev.Key(), Decision: b.decision, RuleVersion: 1}, nil
}
