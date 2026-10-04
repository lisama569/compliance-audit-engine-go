package engine

import (
	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// Preview 用候选规则集对单条事件做纯预演判定：
// 只调用确定性纯函数，不读写任何结果槽位，不产生任何副作用。
func (e *Engine) Preview(ev model.Event, rs model.RuleSet) model.Result {
	decision, matched := applyRules(rs, ev)
	return model.Result{
		TenantID:     ev.TenantID,
		EventKey:     ev.Key(),
		Event:        ev,
		Decision:     decision,
		RuleVersion:  rs.Version,
		MatchedRules: matched,
		EvaluatedAt:  e.clock(),
	}
}

// DryRun 用候选规则集对租户全部已归并事件做只读预演：
// 每条事件给出“当前生效版本下的结论 -> 候选规则下的结论”对比及命中依据。
//
// 预演不修改生效规则、不写入任何结果槽位，临时结论不会混入正式查询。
// 调用方（编排层）需持有租户串行锁，保证预演期间事件集合与生效版本
// 不被并发写入/切换改变，从而拿到前后一致的快照。
func (e *Engine) DryRun(tenantID string, candidate model.RuleSet) (model.DryRunReport, error) {
	base, err := e.registry.Current(tenantID)
	if err != nil {
		return model.DryRunReport{}, err
	}
	report := model.DryRunReport{
		TenantID:         tenantID,
		BaseVersion:      base.Version,
		CandidateVersion: candidate.Version,
	}
	for _, ev := range e.events.ListEvents(tenantID) {
		// 基准结论：优先取当前版本已落库的既有结论，缺失时按当前规则纯演算。
		baseDecision := model.Decision("")
		if existing, ok := e.results.GetResult(tenantID, ev.Key(), base.Version); ok {
			baseDecision = existing.Decision
		} else {
			baseDecision = e.Preview(ev, base).Decision
		}
		preview := e.Preview(ev, candidate)
		item := model.DryRunItem{
			EventKey:        ev.Key(),
			Event:           ev,
			BaseVersion:     base.Version,
			BaseDecision:    baseDecision,
			PreviewDecision: preview.Decision,
			Changed:         preview.Decision != baseDecision,
			MatchedRules:    preview.MatchedRules,
		}
		if item.Changed {
			report.ChangedCount++
		}
		report.Items = append(report.Items, item)
	}
	report.TotalEvents = len(report.Items)
	return report, nil
}
