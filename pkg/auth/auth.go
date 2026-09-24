// Package auth 提供基于租户与角色的查询/重算授权。
package auth

import "errors"

// Role 标识调用方角色。
type Role string

const (
	// RoleTenantReader 租户只读角色：可查询本租户数据。
	RoleTenantReader Role = "tenant_reader"
	// RoleTenantAdmin 租户管理员：可查询、提交事件并触发本租户重算。
	RoleTenantAdmin Role = "tenant_admin"
	// RoleGlobalAuditor 全局审计员：可查询所有租户，但不可写入/重算。
	RoleGlobalAuditor Role = "global_auditor"
)

// Action 是需要授权的操作。
type Action string

const (
	ActionQuery     Action = "query"
	ActionIngest    Action = "ingest"
	ActionRecompute Action = "recompute"
	ActionPublish   Action = "publish"
)

// Principal 是调用方身份。
type Principal struct {
	Name     string
	TenantID string // 租户角色必须归属某租户；全局角色为空
	Roles    []Role
}

// ErrForbidden 表示越权访问；错误信息不得携带其他租户数据。
var ErrForbidden = errors.New("forbidden: principal lacks permission for this tenant/action")

// Authorizer 校验调用方是否能以 action 访问 tenantID 资源。
type Authorizer interface {
	Authorize(p Principal, action Action, tenantID string) error
}

// staticAuthorizer 为基于固定角色矩阵的内存授权器（空实现）。
type staticAuthorizer struct{}

// NewStaticAuthorizer 创建基于固定角色矩阵的授权器。
func NewStaticAuthorizer() Authorizer { return &staticAuthorizer{} }

// 角色权限矩阵：
//
//	tenant_reader   : query            仅本租户
//	tenant_admin    : query/ingest/recompute/publish 仅本租户
//	global_auditor  : query            所有租户（只读，禁止任何写操作）
func (a *staticAuthorizer) Authorize(p Principal, action Action, tenantID string) error {
	if len(p.Roles) == 0 {
		return ErrForbidden
	}
	for _, role := range p.Roles {
		switch role {
		case RoleGlobalAuditor:
			// 全局审计员只读，且目标租户必须非空。
			if action == ActionQuery && tenantID != "" {
				return nil
			}
		case RoleTenantReader, RoleTenantAdmin:
			// 租户角色只能访问本租户。
			if p.TenantID == "" || tenantID == "" || p.TenantID != tenantID {
				continue
			}
			if role == RoleTenantReader {
				if action == ActionQuery {
					return nil
				}
				continue
			}
			// tenant_admin 拥有本租户全部动作权限。
			return nil
		}
	}
	return ErrForbidden
}
