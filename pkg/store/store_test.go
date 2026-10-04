package store

import (
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

func mkEvent(tenant, id string, amount int64) model.Event {
	return model.Event{
		TenantID: tenant, Source: "payments", EventID: id,
		OccurredAt: time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC),
		Action:     "transfer", AmountCents: amount,
	}
}

func TestPutEventDedupAndConflict(t *testing.T) {
	m := NewMemory()
	e := mkEvent("t1", "e1", 100)

	out, _, existed := m.PutEvent(e)
	if out != PutAccepted || existed {
		t.Fatalf("first put want accepted, got %v existed=%v", out, existed)
	}
	out, existing, existed := m.PutEvent(e)
	if out != PutDuplicated || !existed || existing.AmountCents != 100 {
		t.Fatalf("identical put want duplicate, got %v", out)
	}

	tampered := e
	tampered.AmountCents = 999
	out, existing, existed = m.PutEvent(tampered)
	if out != PutConflict || !existed {
		t.Fatalf("tampered put want conflict, got %v", out)
	}
	// 既有记录必须保持原样。
	got, _ := m.GetEvent("t1", e.Key())
	if got.AmountCents != 100 {
		t.Fatalf("existing event silently rewritten: %d", got.AmountCents)
	}
}

func TestEventTenantIsolation(t *testing.T) {
	m := NewMemory()
	m.PutEvent(mkEvent("t1", "e1", 1))
	m.PutEvent(mkEvent("t2", "e1", 2))
	if a := m.ListEvents("t1"); len(a) != 1 || a[0].TenantID != "t1" {
		t.Fatalf("t1 isolation broken: %+v", a)
	}
	if _, ok := m.GetEvent("t2", "t1|payments|e1"); ok {
		t.Fatal("cross-tenant key lookup must miss")
	}
}

func TestResultSlotsImmutable(t *testing.T) {
	m := NewMemory()
	r := model.Result{TenantID: "t1", EventKey: "k", RuleVersion: 1, Decision: model.DecisionAllow}
	if overwrote := m.PutResult(r); overwrote {
		t.Fatal("first put must not be an overwrite")
	}
	r2 := r
	r2.Decision = model.DecisionDeny // 同槽位重写尝试
	if overwrote := m.PutResult(r2); !overwrote {
		t.Fatal("second put into same (key,version) must report overwrite")
	}
	got, ok := m.GetResult("t1", "k", 1)
	if !ok || got.Decision != model.DecisionAllow {
		t.Fatalf("historical result must remain immutable, got %+v ok=%v", got, ok)
	}
	// 新版本槽位可独立写入。
	r3 := r
	r3.RuleVersion = 2
	r3.Decision = model.DecisionDeny
	if overwrote := m.PutResult(r3); overwrote {
		t.Fatal("new version slot should be accepted")
	}
	if v1 := m.ListResults("t1", 1); len(v1) != 1 || v1[0].Decision != model.DecisionAllow {
		t.Fatalf("v1 slot corrupted: %+v", v1)
	}
	if v2 := m.ListResults("t1", 2); len(v2) != 1 || v2[0].Decision != model.DecisionDeny {
		t.Fatalf("v2 slot wrong: %+v", v2)
	}
}

func TestQuarantineAppend(t *testing.T) {
	m := NewMemory()
	q := model.QuarantinedEvent{Event: mkEvent("t1", "e1", 1), Reason: model.RejectLate}
	m.PutQuarantined(q)
	m.PutQuarantined(q)
	if got := m.ListQuarantined("t1"); len(got) != 2 {
		t.Fatalf("want 2 quarantine records (replay trail), got %d", len(got))
	}
	if got := m.ListQuarantined("t2"); len(got) != 0 {
		t.Fatalf("tenant isolation for quarantine broken: %d", len(got))
	}
}
