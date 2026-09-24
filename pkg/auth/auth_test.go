package auth

import (
	"errors"
	"testing"
)

func TestAuthorizeMatrix(t *testing.T) {
	a := NewStaticAuthorizer()
	admin := Principal{Name: "a", TenantID: "t1", Roles: []Role{RoleTenantAdmin}}
	reader := Principal{Name: "r", TenantID: "t1", Roles: []Role{RoleTenantReader}}
	other := Principal{Name: "o", TenantID: "t2", Roles: []Role{RoleTenantAdmin}}
	auditor := Principal{Name: "g", Roles: []Role{RoleGlobalAuditor}}
	noRole := Principal{Name: "x", TenantID: "t1"}

	cases := []struct {
		name    string
		p       Principal
		action  Action
		tenant  string
		allowed bool
	}{
		{"admin query own", admin, ActionQuery, "t1", true},
		{"admin ingest own", admin, ActionIngest, "t1", true},
		{"admin recompute own", admin, ActionRecompute, "t1", true},
		{"admin publish own", admin, ActionPublish, "t1", true},
		{"admin cross tenant", admin, ActionQuery, "t2", false},
		{"other admin cross tenant", other, ActionRecompute, "t1", false},
		{"reader query own", reader, ActionQuery, "t1", true},
		{"reader ingest denied", reader, ActionIngest, "t1", false},
		{"reader publish denied", reader, ActionPublish, "t1", false},
		{"reader cross tenant", reader, ActionQuery, "t2", false},
		{"auditor query any tenant", auditor, ActionQuery, "t1", true},
		{"auditor ingest denied", auditor, ActionIngest, "t1", false},
		{"auditor recompute denied", auditor, ActionRecompute, "t1", false},
		{"auditor publish denied", auditor, ActionPublish, "t1", false},
		{"no roles denied", noRole, ActionQuery, "t1", false},
		{"empty target tenant denied", admin, ActionQuery, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := a.Authorize(tc.p, tc.action, tc.tenant)
			if tc.allowed && err != nil {
				t.Fatalf("expected allowed, got %v", err)
			}
			if !tc.allowed && !errors.Is(err, ErrForbidden) {
				t.Fatalf("expected ErrForbidden, got %v", err)
			}
		})
	}
}
