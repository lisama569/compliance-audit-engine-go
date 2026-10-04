// Package rules 管理按租户隔离的版本化规则集：
// 发布（含严格校验）、回滚，以及按事件发生时间选择生效版本。
package rules

import (
	"errors"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

var (
	// ErrInvalidRule 非法规则：操作符/字段/判定不支持等。
	ErrInvalidRule = errors.New("invalid rule")
	// ErrScopeConflict 同一规则集内存在作用域冲突的重叠规则。
	ErrScopeConflict = errors.New("scope conflict")
	// ErrMissingField 规则关键字段缺失。
	ErrMissingField = errors.New("missing required field")
	// ErrNoRuleSet 租户尚无已发布规则集。
	ErrNoRuleSet = errors.New("no published rule set for tenant")
	// ErrNothingToRollback 没有可回滚的版本。
	ErrNothingToRollback = errors.New("nothing to roll back")
)

// Registry 是版本化规则集注册表。
type Registry interface {
	// Publish 校验并发布新不可变版本，版本号单调递增并使其立即生效。
	Publish(tenantID string, rs model.RuleSet) (model.RuleSet, error)
	// Rollback 将当前生效版本回退到上一版本（历史版本不删除）。
	Rollback(tenantID string) (model.RuleSet, error)
	// RollbackTarget 返回“若现在回滚”将生效的历史版本，不修改任何状态。
	RollbackTarget(tenantID string) (model.RuleSet, error)
	// EffectiveAt 返回时刻 t 真正生效的规则集（含回滚生效段，历史重算用）。
	EffectiveAt(tenantID string, t time.Time) (model.RuleSet, error)
	// Current 返回当前生效规则集。
	Current(tenantID string) (model.RuleSet, error)
	// History 返回按版本号排序的全部已发布版本（含已回滚版本）。
	History(tenantID string) []model.RuleSet
	// Timeline 返回生效时间轴：每段为半开区间 [EffectiveFrom, EffectiveTo)，
	// 任意时刻至多命中一个版本；回滚以 CauseRollback 段体现。
	Timeline(tenantID string) []model.TimelineEntry
}
