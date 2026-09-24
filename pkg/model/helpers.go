package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ErrInvalidEvent 表示事件缺少关键字段。
var ErrInvalidEvent = errors.New("invalid event: missing required field")

// Validate 校验事件关键字段；返回的错误指明具体缺失项。
func (e Event) Validate() error {
	var missing []string
	switch {
	case e.TenantID == "":
		missing = append(missing, "tenant_id")
	case e.Source == "":
		missing = append(missing, "source")
	case e.EventID == "":
		missing = append(missing, "event_id")
	case e.OccurredAt.IsZero():
		missing = append(missing, "occurred_at")
	case e.Action == "":
		missing = append(missing, "action")
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalidEvent, strings.Join(missing, ","))
	}
	return nil
}

// Fingerprint 返回事件业务内容的稳定指纹（不含接收时间）。
//
// 同一幂等键下指纹一致即“完全重复”；指纹不同视为潜在重放改写（冲突），
// 从而避免迟到/乱序消息静默改写既有结论。
func (e Event) Fingerprint() string {
	var b strings.Builder
	b.WriteString(e.TenantID)
	b.WriteByte('|')
	b.WriteString(e.Source)
	b.WriteByte('|')
	b.WriteString(e.EventID)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(e.OccurredAt.UnixNano(), 10))
	b.WriteByte('|')
	b.WriteString(e.Action)
	b.WriteByte('|')
	b.WriteString(e.ResourceID)
	b.WriteByte('|')
	b.WriteString(e.Actor)
	b.WriteByte('|')
	b.WriteString(strconv.FormatInt(e.AmountCents, 10))
	keys := make([]string, 0, len(e.Metadata))
	for k := range e.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteByte('|')
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(e.Metadata[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
