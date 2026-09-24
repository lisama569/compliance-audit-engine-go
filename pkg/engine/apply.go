package engine

import (
	"strconv"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// matches 判断事件是否落在规则作用域内并满足条件。
func matches(r model.Rule, ev model.Event) bool {
	// Scope 与 Action 决定规则作用域；"*" 为通配。
	if r.Scope != "*" && r.Scope != ev.Source {
		return false
	}
	if r.Action != "*" && r.Action != ev.Action {
		return false
	}
	switch r.Op {
	case model.OpGTE, model.OpLTE:
		threshold, err := strconv.ParseInt(r.Value, 10, 64)
		if err != nil {
			return false
		}
		if r.Op == model.OpGTE {
			return ev.AmountCents >= threshold
		}
		return ev.AmountCents <= threshold
	case model.OpEQ:
		switch r.Field {
		case "action":
			return ev.Action == r.Value
		case "resource_id":
			return ev.ResourceID == r.Value
		case "actor":
			return ev.Actor == r.Value
		}
	}
	return false
}

// applyRules 是确定性纯函数：按规则集固定顺序求值，
// 判定优先级 DENY > REVIEW > ALLOW，命中规则全部作为判定依据记录。
// 没有任何规则命中时默认 REVIEW（证据不足，交人工处理）。
func applyRules(rs model.RuleSet, ev model.Event) (model.Decision, []model.Evidence) {
	var hit []model.Evidence
	hasAllow, hasReview, hasDeny := false, false, false
	for _, r := range rs.Rules {
		if !matches(r, ev) {
			continue
		}
		hit = append(hit, model.Evidence{
			RuleID: r.RuleID,
			Scope:  r.Scope,
			Op:     r.Op,
			Field:  r.Field,
			Value:  r.Value,
			Reason: r.Reason,
		})
		switch r.Decision {
		case model.DecisionDeny:
			hasDeny = true
		case model.DecisionReview:
			hasReview = true
		case model.DecisionAllow:
			hasAllow = true
		}
	}
	switch {
	case hasDeny:
		return model.DecisionDeny, hit
	case hasReview:
		return model.DecisionReview, hit
	case hasAllow:
		return model.DecisionAllow, hit
	default:
		return model.DecisionReview, hit
	}
}
