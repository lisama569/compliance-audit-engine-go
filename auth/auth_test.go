package auth

import (
	"errors"
	"testing"

	"github.com/lisama569/compliance-audit-engine-go/model"
	"github.com/lisama569/compliance-audit-engine-go/testutil"
)

func TestAuthorizer_RoleMatrix(t *testing.T) {
	log := testutil.NewLogger(t)
	a := NewAuthorizer()
	const t1 = "tenant-1"

	cases := []struct {
		name   string
		p      Principal
		act    string
		tenant string
		allow  bool
	}{
		{"reader query own", Principal{ID: "r", TenantID: t1, Roles: []string{RoleTenantReader}}, ActionQuery, t1, true},
		{"reader cannot ingest", Principal{ID: "r", TenantID: t1, Roles: []string{RoleTenantReader}}, ActionIngest, t1, false},
		{"reader cannot recompute", Principal{ID: "r", TenantID: t1, Roles: []string{RoleTenantReader}}, ActionRecompute, t1, false},
		{"writer ingest own", Principal{ID: "w", TenantID: t1, Roles: []string{RoleTenantWriter}}, ActionIngest, t1, true},
		{"writer cannot publish", Principal{ID: "w", TenantID: t1, Roles: []string{RoleTenantWriter}}, ActionPublishRules, t1, false},
		{"writer cannot rollback", Principal{ID: "w", TenantID: t1, Roles: []string{RoleTenantWriter}}, ActionRollbackRules, t1, false},
		{"tenant admin publish own", Principal{ID: "a", TenantID: t1, Roles: []string{RoleTenantAdmin}}, ActionPublishRules, t1, true},
		{"tenant admin recompute own", Principal{ID: "a", TenantID: t1, Roles: []string{RoleTenantAdmin}}, ActionRecompute, t1, true},
		{"admin cannot touch other tenant", Principal{ID: "a", TenantID: t1, Roles: []string{RoleTenantAdmin}}, ActionQuery, "tenant-2", false},
		{"platform admin global scope", Principal{ID: "p", TenantID: "", Roles: []string{RolePlatformAdmin}}, ActionPublishRules, "", true},
		{"platform admin cannot read arbitrary tenant", Principal{ID: "p", TenantID: "", Roles: []string{RolePlatformAdmin}}, ActionQuery, "tenant-2", false},
		{"platform admin can act in assumed tenant", Principal{ID: "p", TenantID: t1, Roles: []string{RolePlatformAdmin}}, ActionQuery, t1, true},
		{"unknown role denied", Principal{ID: "x", TenantID: t1, Roles: []string{"ghost"}}, ActionQuery, t1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := a.Can(tc.p, tc.act, tc.tenant)
			got := err == nil
			if got != tc.allow {
				t.Fatalf("allow=%v want %v (err=%v)", got, tc.allow, err)
			}
			if !got && !errors.Is(err, model.ErrForbidden) {
				t.Fatalf("denials must be ErrForbidden, got %v", err)
			}
			log.Logf("principal=%s roles=%v action=%-16s target=%s -> allowed=%v",
				tc.p.ID, tc.p.Roles, tc.act, tc.tenant, got)
		})
	}
}

func TestAuthorizer_DenialMessageDoesNotLeak(t *testing.T) {
	log := testutil.NewLogger(t)
	a := NewAuthorizer()
	p := Principal{ID: "w", TenantID: "tenant-1", Roles: []string{RoleTenantWriter}}
	err := a.Can(p, ActionQuery, "tenant-2")
	if err == nil {
		t.Fatal("expected denial")
	}
	msg := err.Error()
	for _, leak := range []string{"tenant-1", "tenant-2", "w", "principal"} {
		if bytesContains(msg, leak) {
			t.Fatalf("denial message leaks identifier %q: %s", leak, msg)
		}
	}
	log.Logf("uniform denial message (no identifiers): %s", msg)
}

func bytesContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
