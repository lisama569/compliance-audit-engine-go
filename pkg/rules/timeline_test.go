package rules

import (
	"errors"
	"testing"
	"time"

	"github.com/lisama569/compliance-audit-engine-go/pkg/model"
)

// 生效时间轴边界：发布/回滚都落在时间轴上，区间半开 [from,to)，
// 任意时刻至多命中一个版本；按时刻追溯返回该时刻真正生效的版本。
func TestTimelineBoundariesAndEffectiveAt(t *testing.T) {
	t0 := time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)
	cur := t0
	reg := NewMemoryRegistry(func() time.Time { return cur })

	if _, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()}); err != nil { // v1 @08:00
		t.Fatal(err)
	}
	cur = t0.Add(time.Hour)
	if _, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()}); err != nil { // v2 @09:00
		t.Fatal(err)
	}
	cur = t0.Add(2 * time.Hour)
	if _, err := reg.Rollback("t1"); err != nil { // 回滚到 v1 @10:00
		t.Fatal(err)
	}
	cur = t0.Add(3 * time.Hour)
	if _, err := reg.Publish("t1", model.RuleSet{Rules: goodRules()}); err != nil { // v3 @11:00
		t.Fatal(err)
	}

	tl := reg.Timeline("t1")
	if len(tl) != 4 {
		t.Fatalf("timeline entries=%d want 4 (publish/publish/rollback/publish)", len(tl))
	}
	want := []struct {
		version int
		from    time.Time
		to      time.Time // 零值表示至今生效
		cause   model.ActivationCause
		current bool
	}{
		{1, t0, t0.Add(time.Hour), model.CausePublish, false},
		{2, t0.Add(time.Hour), t0.Add(2 * time.Hour), model.CausePublish, false},
		{1, t0.Add(2 * time.Hour), t0.Add(3 * time.Hour), model.CauseRollback, false},
		{3, t0.Add(3 * time.Hour), time.Time{}, model.CausePublish, true},
	}
	for i, w := range want {
		got := tl[i]
		if got.Version != w.version || !got.EffectiveFrom.Equal(w.from) ||
			!got.EffectiveTo.Equal(w.to) || got.Cause != w.cause || got.Current != w.current {
			t.Fatalf("entry[%d]=%+v want version=%d from=%s to=%s cause=%s current=%t",
				i, got, w.version, w.from, w.to, w.cause, w.current)
		}
		t.Logf("[timeline] entry=%d version=v%d window=[%s,%s) cause=%s current=%t",
			i, got.Version, got.EffectiveFrom, got.EffectiveTo, got.Cause, got.Current)
	}

	// 边界时刻：恰好落在边界上的时刻只属于右侧区间（半开），不产生双命中。
	at := func(tt time.Time, wantV int, wantErr error) {
		t.Helper()
		rs, err := reg.EffectiveAt("t1", tt)
		if wantErr != nil {
			if !errors.Is(err, wantErr) {
				t.Fatalf("EffectiveAt(%s) want err=%v, got %v", tt, wantErr, err)
			}
			return
		}
		if err != nil || rs.Version != wantV {
			t.Fatalf("EffectiveAt(%s) want v%d, got v%d err=%v", tt, wantV, rs.Version, err)
		}
		t.Logf("[effective-at] t=%s -> ruleVersion=v%d", tt, rs.Version)
	}
	at(t0.Add(-time.Second), 0, ErrNoRuleSet) // 首次生效前无版本
	at(t0, 1, nil)                            // 左闭：发布瞬间即生效
	at(t0.Add(time.Hour).Add(-time.Nanosecond), 1, nil)
	at(t0.Add(time.Hour), 2, nil) // v2 发布瞬间切换
	at(t0.Add(2*time.Hour).Add(-time.Nanosecond), 2, nil)
	at(t0.Add(2*time.Hour), 1, nil) // 回滚瞬间起 v1 重新生效
	at(t0.Add(3*time.Hour).Add(-time.Nanosecond), 1, nil)
	at(t0.Add(3*time.Hour), 3, nil)

	// 任意采样时刻命中条目数必须恰好为 1（首次生效前为 0），不允许矛盾双版本。
	for _, tt := range []time.Time{
		t0.Add(-time.Second), t0, t0.Add(30 * time.Minute),
		t0.Add(time.Hour), t0.Add(90 * time.Minute),
		t0.Add(2 * time.Hour), t0.Add(150 * time.Minute),
		t0.Add(3 * time.Hour), t0.Add(24 * time.Hour),
	} {
		hits := 0
		for _, e := range tl {
			if !tt.Before(e.EffectiveFrom) && (e.EffectiveTo.IsZero() || tt.Before(e.EffectiveTo)) {
				hits++
			}
		}
		wantHits := 1
		if tt.Before(t0) {
			wantHits = 0
		}
		if hits != wantHits {
			t.Fatalf("t=%s hits=%d want %d (timeline must never self-conflict)", tt, hits, wantHits)
		}
	}
	t.Log("[timeline] no instant matches two entries; boundaries are half-open and unambiguous")
}
