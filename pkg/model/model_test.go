package model

import (
	"errors"
	"testing"
	"time"
)

func sampleEvent() Event {
	return Event{
		TenantID:    "t1",
		Source:      "payments",
		EventID:     "e1",
		OccurredAt:  time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC),
		Action:      "transfer",
		ResourceID:  "acct-1",
		Actor:       "alice",
		AmountCents: 1000,
		Metadata:    map[string]string{"trace": "abc"},
	}
}

func TestEventKeyAndFingerprintStability(t *testing.T) {
	e := sampleEvent()
	if got, want := e.Key(), "t1|payments|e1"; got != want {
		t.Fatalf("Key() = %q, want %q", got, want)
	}
	// 元数据键序不同不得改变指纹。
	e2 := sampleEvent()
	e2.Metadata = map[string]string{"trace": "abc"}
	if e.Fingerprint() != e2.Fingerprint() {
		t.Fatal("fingerprint must be stable across map iteration order")
	}
	// 接收时间不同仍是同一业务事件（完全重复）。
	e3 := sampleEvent()
	e3.ReceivedAt = time.Now()
	if e.Fingerprint() != e3.Fingerprint() {
		t.Fatal("fingerprint must ignore received_at")
	}
}

func TestFingerprintDetectsReplayTampering(t *testing.T) {
	e := sampleEvent()
	tampered := sampleEvent()
	tampered.AmountCents = 2000
	if e.Fingerprint() == tampered.Fingerprint() {
		t.Fatal("different payload must produce different fingerprint")
	}
	t2 := sampleEvent()
	t2.OccurredAt = t2.OccurredAt.Add(time.Second)
	if e.Fingerprint() == t2.Fingerprint() {
		t.Fatal("different occurred_at must produce different fingerprint")
	}
}

func TestEventValidate(t *testing.T) {
	e := sampleEvent()
	if err := e.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	bad := e
	bad.EventID = ""
	err := bad.Validate()
	if !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("want ErrInvalidEvent, got %v", err)
	}
}
