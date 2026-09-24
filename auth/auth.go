// Package auth provides tenant- and role-based authorization.
package auth

import (
	"github.com/lisama569/compliance-audit-engine-go/model"
)

// Role constants.
const (
	RoleTenantReader  = "tenant_reader"
	RoleTenantWriter  = "tenant_writer"
	RoleTenantAdmin   = "tenant_admin"
	RolePlatformAdmin = "platform_admin"
)

// Action constants.
const (
	ActionIngest        = "ingest"
	ActionQuery         = "query"
	ActionQueryHistory  = "query_history"
	ActionRecompute     = "recompute"
	ActionPublishRules  = "publish_rules"
	ActionRollbackRules = "rollback_rules"
	ActionResolve       = "resolve_quarantine"
	ActionListTenants   = "list_tenants"
)

// Principal is an authenticated caller.
type Principal struct {
	ID       string   `json:"id"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

func (p Principal) hasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// roleActions maps each role to the set of actions it may perform on its own
// tenant scope.
var roleActions = map[string]map[string]bool{
	RoleTenantReader: {
		ActionQuery:        true,
		ActionQueryHistory: true,
	},
	RoleTenantWriter: {
		ActionIngest:       true,
		ActionQuery:        true,
		ActionQueryHistory: true,
	},
	RoleTenantAdmin: {
		ActionIngest:        true,
		ActionQuery:         true,
		ActionQueryHistory:  true,
		ActionRecompute:     true,
		ActionPublishRules:  true,
		ActionRollbackRules: true,
		ActionResolve:       true,
	},
	RolePlatformAdmin: {
		ActionIngest:        true,
		ActionQuery:         true,
		ActionQueryHistory:  true,
		ActionRecompute:     true,
		ActionPublishRules:  true,
		ActionRollbackRules: true,
		ActionResolve:       true,
		ActionListTenants:   true,
	},
}

// Authorizer checks principals against actions and tenant boundaries.
type Authorizer struct{}

// NewAuthorizer creates an Authorizer.
func NewAuthorizer() *Authorizer { return &Authorizer{} }

// Can returns nil when the principal may perform action on targetTenant.
// Cross-tenant access is always forbidden, including for platform admins;
// platform admins act on the global scope ("") or after assuming a tenant.
func (a *Authorizer) Can(p Principal, action, targetTenant string) error {
	for _, role := range p.Roles {
		actions, known := roleActions[role]
		if !known || !actions[action] {
			continue
		}
		switch role {
		case RolePlatformAdmin:
			// Platform admin may touch the global scope and may act within a
			// tenant only when explicitly assuming it (target == own tenant).
			if targetTenant == "" || targetTenant == p.TenantID {
				return nil
			}
		default:
			// Tenant-scoped roles can only ever touch their own tenant.
			if targetTenant == p.TenantID {
				return nil
			}
		}
	}
	// Uniform, identifier-free error: principal and tenant IDs must not leak
	// (even back to an unauthorized caller) through differing messages.
	return model.ErrForbidden
}
