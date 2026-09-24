package ingest

import (
	"sync"
	"time"
)

// tokenBucket 是惰性补充令牌的令牌桶；rate<=0 时表示不限流。
type tokenBucket struct {
	mu         sync.Mutex
	rate       float64
	burst      float64
	tokens     float64
	lastRefill time.Time
	now        func() time.Time
}

// newTokenBucket 创建令牌桶限流器，初始令牌为满桶。
func newTokenBucket(rate float64, burst int, now func() time.Time) Limiter {
	if now == nil {
		now = time.Now
	}
	b := float64(burst)
	if rate <= 0 {
		b = 0 // 不限流标记
	}
	return &tokenBucket{rate: rate, burst: b, tokens: b, lastRefill: now(), now: now}
}

func (b *tokenBucket) Allow() bool {
	if b.rate <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	elapsed := now.Sub(b.lastRefill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.lastRefill = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
