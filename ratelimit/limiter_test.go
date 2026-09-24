package ratelimit

import (
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

func TestLimiter_BurstThenBackPressure(t *testing.T) {
	log := testutil.NewLogger(t)
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cur := base
	l := NewLimiter(10, 3)
	l.SetClock(func() time.Time { return cur })

	for i := 0; i < 3; i++ {
		if !l.Allow() {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	if l.Allow() {
		t.Fatal("4th request must be rejected (back-pressure)")
	}
	log.Logf("burst=3 exhausted; rejected=%v retry-in=%s", true, l.RetryIn())

	// After 100ms at 10 tokens/s, one token refills.
	cur = base.Add(100 * time.Millisecond)
	if !l.Allow() {
		t.Fatal("refilled token should be allowed")
	}
	if l.Allow() {
		t.Fatal("only one token should have refilled")
	}
	log.Logf("refill observed after 100ms at 10/s; overload error identity=%v", model.ErrOverloaded)
}

func TestLimiter_DisabledWhenRateZero(t *testing.T) {
	log := testutil.NewLogger(t)
	l := NewLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		if !l.Allow() {
			t.Fatal("rate<=0 must mean unlimited")
		}
	}
	log.Logf("unlimited limiter accepted 1000 requests")
}
