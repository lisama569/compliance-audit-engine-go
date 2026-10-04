package model

import "time"

// 规则变更预演与生效时间轴的只读视图类型。
// 预演报告与时间都只用于查询展示，不会被写入任何结果存储。

// VersionInterval 描述一个规则版本在生效时间轴上的区间 [From, To)。
//
// 边界约定：From 闭、To 开——任意时刻至多命中一个区间，
// 不会出现同一时刻命中两个互相矛盾版本的情况。
// To 为零值表示该版本至今仍生效（区间右端开放）。
type VersionInterval struct {
	TenantID string    `json:"tenant_id"`
	Version  int       `json:"version"`
	From     time.Time `json:"from"`
	To       time.Time `json:"to,omitempty"`
	// Cause 记录该区间的由来："publish"（发布生效）或 "rollback"（回滚生效）。
	Cause string `json:"cause"`
	// Current 标记该区间是否为当前生效区间。
	Current bool `json:"current"`
}

// PreviewChange 是单条事件在候选规则集下的结论对比（只读，不落库）。
type PreviewChange struct {
	EventKey string `json:"event_key"`
	Event    Event  `json:"event"`
	// BaseVersion 是 Before 结论所依据的（当前生效）规则版本。
	BaseVersion int `json:"base_version"`
	// Before 是当前生效版本下的结论；After 是候选规则集下的结论。
	Before  Decision `json:"before"`
	After   Decision `json:"after"`
	Changed bool     `json:"changed"`
	// MatchedRules 是候选规则集下的命中依据。
	MatchedRules []Evidence `json:"matched_rules,omitempty"`
}

// PreviewReport 是一次规则变更预演的只读报告。
//
// 预演不产生任何副作用：不修改当前生效规则、不写入/覆盖任何判定结果、
// 报告内容也不会混入正式查询。
type PreviewReport struct {
	TenantID string `json:"tenant_id"`
	// Kind 是预演类型："publish"（预演发布新规则集）或 "rollback"（预演回滚）。
	Kind string `json:"kind"`
	// CandidateVersion 是候选规则集的版本号：
	// 预演回滚时为目标历史版本；预演发布时为发布后将分配的下一个版本号。
	CandidateVersion int `json:"candidate_version"`
	// BaseVersion 是对照组（当前生效版本）的版本号。
	BaseVersion int             `json:"base_version"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
	Total       int             `json:"total"`
	Changed     int             `json:"changed"`
	Changes     []PreviewChange `json:"changes"`
}
