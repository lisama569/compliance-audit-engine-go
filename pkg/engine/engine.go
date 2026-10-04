// Package engine 依据版本化规则集对事件进行确定性判定，
// 并支持按事件发生时的有效版本进行历史重算。
package engine

import (
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
	"github.com/lisama569/compliance-audit-engine-go/pkg/rules"
	"github.com/lisama569/compliance-audit-engine-go/pkg/store"
)

// Engine 对已归并事件执行规则判定。
type Engine struct {
	registry rules.Registry
	results  store.ResultStore
	events   store.EventStore
	clock    func() time.Time
}

// New 创建判定引擎；可传入可选时钟（结果评估时间），默认使用 UTC 当前时间。
func New(reg rules.Registry, st *store.Memory, clocks ...func() time.Time) *Engine {
	c := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		c = clocks[0]
	}
	return &Engine{
		registry: reg,
		results:  st,
		events:   st,
		clock:    c,
	}
}

// Evaluate 用事件发生时的有效规则版本判定单条事件，
// 并按 (事件, 规则版本) 维度持久化不可变结果。
// 同一 (事件,版本) 重复求值时返回既有结果，保证幂等。
//
// 闭环保证：若“发生时版本”与“当前生效版本”不同（例如回滚后接入了
// 回滚前发生的迟到事件），会为当前版本一并补齐结果槽位，使当前查询
// 始终能看到该事件在当前规则下的结论，不会出现“判定用一个版本、
// 当前查询却看不到”的断层。
func (e *Engine) Evaluate(ev model.Event) (model.Result, error) {
	rs, err := e.registry.EffectiveAt(ev.TenantID, ev.OccurredAt)
	if err != nil {
		return model.Result{}, err
	}
	if existing, ok := e.results.GetResult(ev.TenantID, ev.Key(), rs.Version); ok {
		return existing, nil
	}
	r, err := e.EvaluateWith(ev, rs, false)
	if err != nil {
		return model.Result{}, err
	}
	e.results.PutResult(r)
	if cur, err := e.registry.Current(ev.TenantID); err == nil && cur.Version != rs.Version {
		if _, ok := e.results.GetResult(ev.TenantID, ev.Key(), cur.Version); !ok {
			if _, err := e.EvaluateWith(ev, cur, false); err != nil {
				return r, err
			}
		}
	}
	return r, nil
}

// EvaluateWith 使用指定规则集判定事件（重算用）。
// 结果槽位已存在时保持原样：历史结论不可被静默改写。
func (e *Engine) EvaluateWith(ev model.Event, rs model.RuleSet, recomputed bool) (model.Result, error) {
	if rs.TenantID != "" && rs.TenantID != ev.TenantID {
		return model.Result{}, rules.ErrInvalidRule
	}
	decision, matched := applyRules(rs, ev)
	r := model.Result{
		TenantID:     ev.TenantID,
		EventKey:     ev.Key(),
		Event:        ev,
		Decision:     decision,
		RuleVersion:  rs.Version,
		MatchedRules: matched,
		EvaluatedAt:  e.clock(),
		Recomputed:   recomputed,
	}
	e.results.PutResult(r)
	return r, nil
}

// RefillCurrent 用“当前生效规则版本”为租户全部已有事件补齐结果槽位。
// 规则发布或回滚后由编排层调用，使当前版本查询始终反映当前规则；
// 已存在的 (事件,版本) 槽位严格不可变。返回新补齐条数。
func (e *Engine) RefillCurrent(tenantID string) (int, error) {
	rs, err := e.registry.Current(tenantID)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ev := range e.events.ListEvents(tenantID) {
		if _, ok := e.results.GetResult(tenantID, ev.Key(), rs.Version); ok {
			continue
		}
		if _, err := e.EvaluateWith(ev, rs, false); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// RecomputeTenant 用每条事件发生时的有效版本重算租户全部历史事件。
//
// 语义：
//   - (事件, 事件发生时版本) 槽位不可变，已存在则保留原结论（严格复现）；
//   - 其余历史版本槽位缺失时补齐，使任意历史版本都可被查询；
//   - 最后按“事件发生时的有效版本”回填当前版本槽位，保证当前查询与
//     “按发生时版本复现”的语义一致。
//
// 返回重新计算/补齐的结果条数。调用方需自行持有租户串行锁。
func (e *Engine) RecomputeTenant(tenantID string) (int, error) {
	events := e.events.ListEvents(tenantID)
	history := e.registry.History(tenantID)
	if len(history) == 0 {
		return 0, rules.ErrNoRuleSet
	}

	n := 0
	// 1) 为每条事件补齐其在各历史版本下的结果（缺失才写，严格不可变）。
	for _, ev := range events {
		for _, rs := range history {
			if _, ok := e.results.GetResult(tenantID, ev.Key(), rs.Version); ok {
				continue
			}
			if _, err := e.EvaluateWith(ev, rs, true); err != nil {
				return n, err
			}
			n++
		}
	}
	// 2) 以事件发生时的有效版本作为该事件当前可复现结论（槽位不可变原则同样适用）。
	for _, ev := range events {
		rs, err := e.registry.EffectiveAt(tenantID, ev.OccurredAt)
		if err != nil {
			return n, err
		}
		if _, ok := e.results.GetResult(tenantID, ev.Key(), rs.Version); ok {
			continue
		}
		if _, err := e.EvaluateWith(ev, rs, true); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
