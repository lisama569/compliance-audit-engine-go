package engine

import (
	"sort"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// PreviewTenant 用候选规则集对租户全部已有事件做规则变更预演。
//
// kind 为 "publish"（候选是待发布的新规则集）或 "rollback"（候选是回滚目标版本）。
// candidate.Version 为 0 表示尚未发布，报告中按“发布后将分配的下一个版本号”展示。
//
// 预演严格只读：不修改当前生效规则、不写入/覆盖任何判定结果槽位、
// 不触碰隔离区，报告也不会混入正式查询。对照组取当前生效版本：
// 该版本槽位已有结论时直接引用（与正式查询一致），缺失时纯函数现算但不落库。
// 调用方需自行持有租户串行锁，保证预演期间无并发写入/规则切换。
func (e *Engine) PreviewTenant(tenantID string, candidate model.RuleSet, kind string) (model.PreviewReport, error) {
	base, err := e.registry.Current(tenantID)
	if err != nil {
		return model.PreviewReport{}, err
	}
	candidateVersion := candidate.Version
	if candidateVersion <= 0 {
		candidateVersion = len(e.registry.History(tenantID)) + 1
	}

	report := model.PreviewReport{
		TenantID:         tenantID,
		Kind:             kind,
		CandidateVersion: candidateVersion,
		BaseVersion:      base.Version,
		EvaluatedAt:      e.clock(),
	}
	for _, ev := range e.events.ListEvents(tenantID) {
		beforeDecision := e.baseDecision(tenantID, ev, base)
		afterDecision, matched := applyRules(candidate, ev)
		change := model.PreviewChange{
			EventKey:     ev.Key(),
			Event:        ev,
			BaseVersion:  base.Version,
			Before:       beforeDecision,
			After:        afterDecision,
			Changed:      beforeDecision != afterDecision,
			MatchedRules: matched,
		}
		if change.Changed {
			report.Changed++
		}
		report.Total++
		report.Changes = append(report.Changes, change)
	}
	// 输出按事件幂等键排序，保证同一状态下预演报告确定可复现。
	sort.Slice(report.Changes, func(i, j int) bool { return report.Changes[i].EventKey < report.Changes[j].EventKey })
	return report, nil
}

// baseDecision 返回事件在当前生效版本下的对照结论：
// 优先引用已持久化的槽位结果（与正式查询逐字一致），缺失时纯函数现算（不落库）。
func (e *Engine) baseDecision(tenantID string, ev model.Event, base model.RuleSet) model.Decision {
	if r, ok := e.results.GetResult(tenantID, ev.Key(), base.Version); ok {
		return r.Decision
	}
	d, _ := applyRules(base, ev)
	return d
}
