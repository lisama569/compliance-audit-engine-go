// Package ratelimit provides local back-pressure via a thread-safe token bucket.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter.
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
	now    func() time.Time
}

// NewLimiter creates a limiter allowing rate tokens/sec with up to burst
// accumulated tokens. rate <= 0 disables limiting.
func NewLimiter(rate float64, burst int) *Limiter {
	return &Limiter{
		rate:   rate,
		burst:  float64(burst),
		tokens: float64(burst),
		last:   time.Now(),
		now:    time.Now,
	}
}

// SetClock overrides the clock (tests).
func (l *Limiter) SetClock(now func() time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.now = now
	l.last = now()
}

func (l *Limiter) refill() {
	now := l.now()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	if elapsed > 0 {
		l.tokens += elapsed * l.rate
		if l.tokens > l.burst {
			l.tokens = l.burst
		}
	}
}

// Allow reports whether one token is available now and, if so, consumes it.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 {
		return true
	}
	l.refill()
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// RetryIn returns how long until one token will be available.
func (l *Limiter) RetryIn() time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rate <= 0 {
		return 0
	}
	l.refill()
	if l.tokens >= 1 {
		return 0
	}
	need := 1 - l.tokens
	return time.Duration(float64(time.Second) * need / l.rate)
}
