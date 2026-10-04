package rules

import (
	"fmt"
	"strconv"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// 合法字段/操作符组合：
//
//	amount_cents : GTE / LTE，值必须为 int64
//	action / resource_id / actor : EQ，值为任意非空字符串
func validFieldForOp(field string, op model.RuleOp, value string) error {
	switch op {
	case model.OpGTE, model.OpLTE:
		if field != "amount_cents" {
			return fmt.Errorf("%w: rule op %s only supports field amount_cents, got %q", ErrInvalidRule, op, field)
		}
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return fmt.Errorf("%w: rule value %q is not an integer amount", ErrInvalidRule, value)
		}
	case model.OpEQ:
		switch field {
		case "action", "resource_id", "actor":
		default:
			return fmt.Errorf("%w: rule op EQ does not support field %q", ErrInvalidRule, field)
		}
		if value == "" {
			return fmt.Errorf("%w: rule value must not be empty", ErrInvalidRule)
		}
	default:
		return fmt.Errorf("%w: unsupported operator %q", ErrInvalidRule, op)
	}
	return nil
}

// ValidateRuleSet 对规则集做严格校验：
// 关键字段缺失、非法操作符/字段/判定、重复规则 ID 以及作用域冲突
// （同一 Scope+Action 下条件完全相同却给出不同判定）都会被拒绝。
func ValidateRuleSet(rs model.RuleSet) error {
	if rs.TenantID == "" {
		return fmt.Errorf("%w: tenant_id", ErrMissingField)
	}
	if len(rs.Rules) == 0 {
		return fmt.Errorf("%w: rules", ErrMissingField)
	}
	seen := make(map[string]bool, len(rs.Rules))
	type cond struct {
		scope, action, field, op, value string
	}
	decisionByCond := make(map[cond]model.Decision)
	for _, r := range rs.Rules {
		switch {
		case r.RuleID == "":
			return fmt.Errorf("%w: rule_id", ErrMissingField)
		case r.Scope == "":
			return fmt.Errorf("%w: rule %s scope", ErrMissingField, r.RuleID)
		case r.Action == "":
			return fmt.Errorf("%w: rule %s action", ErrMissingField, r.RuleID)
		}
		switch r.Decision {
		case model.DecisionAllow, model.DecisionDeny, model.DecisionReview:
		default:
			return fmt.Errorf("%w: rule %s decision %q", ErrInvalidRule, r.RuleID, r.Decision)
		}
		if err := validFieldForOp(r.Field, r.Op, r.Value); err != nil {
			return fmt.Errorf("rule %s: %w", r.RuleID, err)
		}
		if seen[r.RuleID] {
			return fmt.Errorf("%w: duplicated rule_id %q", ErrScopeConflict, r.RuleID)
		}
		seen[r.RuleID] = true

		c := cond{r.Scope, r.Action, r.Field, string(r.Op), r.Value}
		if prev, ok := decisionByCond[c]; ok && prev != r.Decision {
			return fmt.Errorf("%w: scope=%s action=%s condition (%s %s %s) maps to both %s and %s",
				ErrScopeConflict, r.Scope, r.Action, r.Field, r.Op, r.Value, prev, r.Decision)
		}
		decisionByCond[c] = r.Decision
	}
	return nil
}
