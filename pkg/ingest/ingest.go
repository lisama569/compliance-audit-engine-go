// Package ingest 负责审计事件接入：字段校验、幂等归并、
// 乱序/迟到处理、隔离记录，以及过载时的信号量背压与令牌限流。
package ingest

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/store"
)

// ErrBusy 表示系统过载，请求被背压拒绝（调用方可退避重试）。
var ErrBusy = errors.New("ingest overloaded: backpressure applied, retry later")

// Evaluator 是接入后触发判定所需的最小引擎接口。
type Evaluator interface {
	Evaluate(ev model.Event) (model.Result, error)
}

// IngestResult 是单次接入的处理结论。
type IngestResult struct {
	Accepted   bool
	Duplicate  bool                    // 完全重复：幂等返回，不产生重复有效记录
	Quarantine *model.QuarantinedEvent // 被隔离事件（冲突/迟到/非法）
	Result     *model.Result           // 新判定或重复事件的既有判定
}

// Limiter 为令牌桶限流接口。
type Limiter interface {
	Allow() bool
}

// Ingester 归并接入事件。
type Ingester struct {
	mu         sync.Mutex
	events     store.EventStore
	quarantine store.QuarantineStore
	evaluator  Evaluator
	limiter    Limiter
	sem        chan struct{}
	lateGrace  time.Duration
	maxSeen    map[string]time.Time // 租户内已接收事件的最大发生时间
	now        func() time.Time
}

// Config 为接入层配置。
type Config struct {
	MaxInflight int              // 并发处理上限，超出立即触发背压；<=0 表示不限制
	RatePerSec  float64          // 每秒令牌数，<=0 表示不限流
	RateBurst   int              // 令牌桶容量
	LateGrace   time.Duration    // 迟到宽限窗口，超过则隔离为 LATE
	Clock       func() time.Time // 可选：系统时间来源（测试/演示注入）
}

// New 创建接入层。
func New(st *store.Memory, eval Evaluator, cfg Config) *Ingester {
	if cfg.RateBurst <= 0 && cfg.RatePerSec > 0 {
		cfg.RateBurst = int(cfg.RatePerSec)
		if cfg.RateBurst < 1 {
			cfg.RateBurst = 1
		}
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	return &Ingester{
		events:     st,
		quarantine: st,
		evaluator:  eval,
		limiter:    newTokenBucket(cfg.RatePerSec, cfg.RateBurst, clock),
		sem:        make(chan struct{}, cfg.MaxInflight),
		lateGrace:  cfg.LateGrace,
		maxSeen:    make(map[string]time.Time),
		now:        clock,
	}
}

func (in *Ingester) quarantineAndReturn(ev model.Event, reason model.RejectReason, detail string) IngestResult {
	q := model.QuarantinedEvent{Event: ev, Reason: reason, Detail: detail, ReceivedAt: in.now()}
	in.quarantine.PutQuarantined(q)
	return IngestResult{Quarantine: &q}
}

// Ingest 接入单条事件。context 取消或过载时返回错误；
// 重复、冲突、迟到、非法事件均返回结构化结果而非错误。
func (in *Ingester) Ingest(ctx context.Context, ev model.Event) (IngestResult, error) {
	// 1) 过载保护：先限流（快速失败），再尝试占用并发槽位（非阻塞背压）。
	if !in.limiter.Allow() {
		return IngestResult{}, ErrBusy
	}
	if cap(in.sem) > 0 {
		select {
		case in.sem <- struct{}{}:
			defer func() { <-in.sem }()
		case <-ctx.Done():
			return IngestResult{}, ctx.Err()
		default:
			return IngestResult{}, ErrBusy
		}
	}

	// 2) 关键字段校验：非法事件隔离，不得绕过校验进入有效记录。
	if err := ev.Validate(); err != nil {
		return in.quarantineAndReturn(ev, model.RejectInvalid, err.Error()), nil
	}
	receivedAt := in.now()
	if ev.ReceivedAt.IsZero() {
		ev.ReceivedAt = receivedAt
	}

	// 3) 完全重复优先幂等返回：重复投递即使伴随迟到，也不得产生隔离噪音或重复记录。
	if existing, ok := in.events.GetEvent(ev.TenantID, ev.Key()); ok {
		if existing.Fingerprint() == ev.Fingerprint() {
			res, _ := in.evaluator.Evaluate(existing)
			return IngestResult{Duplicate: true, Result: ptrResult(res)}, nil
		}
		detail := fmt.Sprintf("same idempotency key %s carries different payload (fingerprint mismatch)", ev.Key())
		return in.quarantineAndReturn(ev, model.RejectConflict, detail), nil
	}

	// 4) 迟到判定：发生时间落后于该租户已观测最大发生时间超过宽限窗口，
	//    视为不可信重放，隔离待人工处理（不静默改写既有结论）。
	in.mu.Lock()
	latest := in.maxSeen[ev.TenantID]
	late := in.lateGrace > 0 && !latest.IsZero() && latest.Sub(ev.OccurredAt) > in.lateGrace
	in.mu.Unlock()
	if late {
		detail := fmt.Sprintf("event occurred at %s lags max seen %s beyond grace %s",
			ev.OccurredAt.Format(time.RFC3339Nano), latest.Format(time.RFC3339Nano), in.lateGrace)
		return in.quarantineAndReturn(ev, model.RejectLate, detail), nil
	}

	// 5) 幂等归并落库：并发情况下另一写入者可能已抢先插入同键事件。
	outcome, existing, _ := in.events.PutEvent(ev)
	switch outcome {
	case store.PutDuplicated:
		res, _ := in.evaluator.Evaluate(existing)
		return IngestResult{Duplicate: true, Result: ptrResult(res)}, nil
	case store.PutConflict:
		detail := fmt.Sprintf("same idempotency key %s carries different payload (fingerprint mismatch)", ev.Key())
		return in.quarantineAndReturn(ev, model.RejectConflict, detail), nil
	}

	// 6) 首次接收：推进水位并执行判定。
	in.mu.Lock()
	if ev.OccurredAt.After(in.maxSeen[ev.TenantID]) {
		in.maxSeen[ev.TenantID] = ev.OccurredAt
	}
	in.mu.Unlock()

	res, err := in.evaluator.Evaluate(ev)
	if err != nil {
		return IngestResult{}, fmt.Errorf("evaluate event %s: %w", ev.Key(), err)
	}
	return IngestResult{Accepted: true, Result: ptrResult(res)}, nil
}

func ptrResult(r model.Result) *model.Result { return &r }
