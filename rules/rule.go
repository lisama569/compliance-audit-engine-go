// Package rules implements rule-set validation, checksums and evaluation.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/lisama569/compliance-audit-engine-go/model"
)

// ChecksumRuleSet computes a stable SHA-256 over the rule-set content.
// The checksum covers scope, version, effective time and every rule, with
// rules sorted by ID so it is independent of declaration order.
func ChecksumRuleSet(rs *model.RuleSet) string {
	type condDTO struct {
		Field    string `json:"field"`
		Operator string `json:"operator"`
		Value    any    `json:"value"`
	}
	type ruleDTO struct {
		ID         string    `json:"id"`
		Name       string    `json:"name"`
		EventTypes []string  `json:"event_types"`
		Priority   int       `json:"priority"`
		Verdict    string    `json:"verdict"`
		Reason     string    `json:"reason"`
		Conditions []condDTO `json:"conditions"`
	}
	type dto struct {
		TenantID      string    `json:"tenant_id"`
		Version       int       `json:"version"`
		EffectiveFrom string    `json:"effective_from"`
		Rules         []ruleDTO `json:"rules"`
	}

	d := dto{
		TenantID:      rs.TenantID,
		Version:       rs.Version,
		EffectiveFrom: rs.EffectiveFrom.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	}
	ruleCopies := append([]model.Rule(nil), rs.Rules...)
	sort.Slice(ruleCopies, func(i, j int) bool { return ruleCopies[i].ID < ruleCopies[j].ID })
	for _, r := range ruleCopies {
		rc := ruleDTO{
			ID: r.ID, Name: r.Name, EventTypes: append([]string(nil), r.EventTypes...),
			Priority: r.Priority, Verdict: r.Verdict, Reason: r.Reason,
		}
		for _, c := range r.Conditions {
			rc.Conditions = append(rc.Conditions, condDTO{Field: c.Field, Operator: c.Operator, Value: c.Value})
		}
		d.Rules = append(d.Rules, rc)
	}
	b, _ := json.Marshal(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// RulesContentChecksum hashes just the rule bodies (no versioning metadata),
// so publishing the same rules with a different effective time is detected as
// identical content.
func RulesContentChecksum(rs []model.Rule) string {
	return ChecksumRuleSet(&model.RuleSet{Version: 1, Rules: rs})
}

// ValidateRuleSet validates a rule set, rejecting malformed rules, scope
// conflicts and missing key fields. It never mutates the rule set.
func ValidateRuleSet(rs *model.RuleSet) error {
	if rs == nil {
		return fmt.Errorf("%w: nil rule set", model.ErrInvalidRule)
	}
	if rs.Version < 1 {
		return fmt.Errorf("%w: version must be >= 1", model.ErrInvalidRule)
	}
	if rs.EffectiveFrom.IsZero() {
		return fmt.Errorf("%w: effective_from is required", model.ErrInvalidRule)
	}
	if len(rs.Rules) == 0 {
		return fmt.Errorf("%w: rule set must contain at least one rule", model.ErrInvalidRule)
	}

	seen := map[string]bool{}
	for i := range rs.Rules {
		r := &rs.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("%w: rule at index %d is missing id", model.ErrInvalidRule, i)
		}
		if seen[r.ID] {
			return fmt.Errorf("%w: duplicate rule id %q", model.ErrInvalidRule, r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("%w: rule %q is missing name", model.ErrInvalidRule, r.ID)
		}
		if len(r.EventTypes) == 0 {
			return fmt.Errorf("%w: rule %q must declare at least one event type", model.ErrInvalidRule, r.ID)
		}
		if !validVerdict(r.Verdict) {
			return fmt.Errorf("%w: rule %q has unknown verdict %q", model.ErrInvalidRule, r.ID, r.Verdict)
		}
		if len(r.Conditions) == 0 {
			return fmt.Errorf("%w: rule %q must declare at least one condition", model.ErrInvalidRule, r.ID)
		}
		for j, c := range r.Conditions {
			if err := validateCondition(r.ID, j, c); err != nil {
				return err
			}
		}
	}

	// Scope conflict: rules with overlapping event types at the same priority
	// but different verdicts are ambiguous and must not be published.
	for i := 0; i < len(rs.Rules); i++ {
		for j := i + 1; j < len(rs.Rules); j++ {
			a, b := rs.Rules[i], rs.Rules[j]
			if a.Priority != b.Priority || a.Verdict == b.Verdict {
				continue
			}
			if eventTypesOverlap(a.EventTypes, b.EventTypes) {
				return fmt.Errorf("%w: rules %q and %q overlap at priority %d with conflicting verdicts",
					model.ErrInvalidRule, a.ID, b.ID, a.Priority)
			}
		}
	}
	return nil
}

func validVerdict(v string) bool {
	switch v {
	case model.VerdictCompliant, model.VerdictNonCompliant, model.VerdictNeedsReview:
		return true
	}
	return false
}

func validateCondition(ruleID string, idx int, c model.Condition) error {
	if strings.TrimSpace(c.Field) == "" {
		return fmt.Errorf("%w: rule %q condition %d is missing field", model.ErrInvalidRule, ruleID, idx)
	}
	switch c.Operator {
	case model.OpExists, model.OpNotExists:
		return nil
	case model.OpEq, model.OpNe, model.OpIn, model.OpNotIn,
		model.OpGt, model.OpGte, model.OpLt, model.OpLte, model.OpContains:
	default:
		return fmt.Errorf("%w: rule %q condition %d has unknown operator %q",
			model.ErrInvalidRule, ruleID, idx, c.Operator)
	}
	if c.Value == nil {
		return fmt.Errorf("%w: rule %q condition %d on %q requires a value",
			model.ErrInvalidRule, ruleID, idx, c.Field)
	}
	switch c.Operator {
	case model.OpIn, model.OpNotIn:
		if reflect.ValueOf(c.Value).Kind() != reflect.Slice {
			return fmt.Errorf("%w: rule %q condition %d %q requires a list value",
				model.ErrInvalidRule, ruleID, idx, c.Operator)
		}
	case model.OpGt, model.OpGte, model.OpLt, model.OpLte:
		if !isNumber(c.Value) {
			return fmt.Errorf("%w: rule %q condition %d %q requires a numeric value",
				model.ErrInvalidRule, ruleID, idx, c.Operator)
		}
	}
	return nil
}

func eventTypesOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y || x == "*" || y == "*" {
				return true
			}
		}
	}
	return false
}

// Evaluate evaluates an event against a rule set. Rules whose declared event
// types include the event type ("*" matches all) are candidates; among them,
// the highest-priority rule whose conditions ALL match wins. If no rule
// matches, the result is needs_review.
func Evaluate(rs *model.RuleSet, ev *model.Event) *model.Decision {
	d := &model.Decision{
		RuleSetID:   rs.ID,
		RuleVersion: rs.Version,
		Verdict:     model.VerdictNeedsReview,
		Reason:      "no_matching_rule",
	}

	candidates := make([]model.Rule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		for _, et := range r.EventTypes {
			if et == "*" || et == ev.Type {
				candidates = append(candidates, r)
				break
			}
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority != candidates[j].Priority {
			return candidates[i].Priority > candidates[j].Priority
		}
		return candidates[i].ID < candidates[j].ID
	})

	for _, r := range candidates {
		matched := true
		basis := make([]string, 0, len(r.Conditions))
		for _, c := range r.Conditions {
			ok, desc := evalCondition(ev, c)
			if !ok {
				matched = false
				break
			}
			basis = append(basis, desc)
		}
		if matched {
			d.RuleID = r.ID
			d.Verdict = r.Verdict
			d.Reason = r.Reason
			d.Basis = basis
			return d
		}
	}
	d.Basis = []string{fmt.Sprintf("no rule matched event type %q", ev.Type)}
	return d
}

// evalCondition returns whether the condition holds and a human-readable
// description of the evaluated fact (the decision basis).
func evalCondition(ev *model.Event, c model.Condition) (bool, string) {
	got, present := lookupPath(ev.Payload, c.Field)
	desc := func(ok bool, detail string) (bool, string) {
		return ok, fmt.Sprintf("%s %v: %s", c.Field, got, detail)
	}
	switch c.Operator {
	case model.OpExists:
		return present, fmt.Sprintf("field %s present=%v", c.Field, present)
	case model.OpNotExists:
		return !present, fmt.Sprintf("field %s present=%v", c.Field, present)
	case model.OpEq:
		ok := present && equalValues(got, c.Value)
		return desc(ok, fmt.Sprintf("== %v -> %v", c.Value, ok))
	case model.OpNe:
		ok := present && !equalValues(got, c.Value)
		return desc(ok, fmt.Sprintf("!= %v -> %v", c.Value, ok))
	case model.OpIn:
		ok := present && valueInList(got, c.Value)
		return desc(ok, fmt.Sprintf("in %v -> %v", c.Value, ok))
	case model.OpNotIn:
		ok := present && !valueInList(got, c.Value)
		return desc(ok, fmt.Sprintf("not_in %v -> %v", c.Value, ok))
	case model.OpContains:
		ok := present && valueContains(got, c.Value)
		return desc(ok, fmt.Sprintf("contains %v -> %v", c.Value, ok))
	case model.OpGt, model.OpGte, model.OpLt, model.OpLte:
		gn, gOK := toFloat(got)
		wn, wOK := toFloat(c.Value)
		ok := present && gOK && wOK && cmpNums(gn, wn, c.Operator)
		return desc(ok, fmt.Sprintf("%s %v -> %v", c.Operator, c.Value, ok))
	}
	return false, fmt.Sprintf("field %s: unknown operator %q", c.Field, c.Operator)
}

func lookupPath(payload map[string]any, path string) (any, bool) {
	parts := strings.Split(path, ".")
	var cur any = payload
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func equalValues(a, b any) bool {
	if af, ok1 := toFloat(a); ok1 {
		if bf, ok2 := toFloat(b); ok2 {
			return af == bf
		}
	}
	return reflect.DeepEqual(a, b)
}

func valueInList(v, list any) bool {
	lv := reflect.ValueOf(list)
	if lv.Kind() != reflect.Slice {
		return false
	}
	for i := 0; i < lv.Len(); i++ {
		if equalValues(v, lv.Index(i).Interface()) {
			return true
		}
	}
	return false
}

func valueContains(haystack, needle any) bool {
	if hs, ok := haystack.(string); ok {
		if ns, ok := needle.(string); ok {
			return strings.Contains(hs, ns)
		}
	}
	return valueInList(needle, haystack)
}

func cmpNums(a, b float64, op string) bool {
	switch op {
	case model.OpGt:
		return a > b
	case model.OpGte:
		return a >= b
	case model.OpLt:
		return a < b
	case model.OpLte:
		return a <= b
	}
	return false
}

func isNumber(v any) bool {
	_, ok := toFloat(v)
	return ok
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	}
	return 0, false
}
