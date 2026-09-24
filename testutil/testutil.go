// Package testutil contains shared test helpers.
package testutil

import (
	"encoding/json"
	"testing"
)

// Logger prints structured audit context during tests: key inputs, the rule
// version applied, the decision basis (which conditions matched) and the
// final result.
type Logger struct {
	t *testing.T
}

// NewLogger creates a Logger bound to a test.
func NewLogger(t *testing.T) *Logger { return &Logger{t: t} }

// Logf records one audit step.
func (l *Logger) Logf(format string, args ...any) {
	l.t.Helper()
	l.t.Logf(format, args...)
}

// JSON renders a value as compact JSON for readable assertions/logs.
func JSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<json-error: " + err.Error() + ">"
	}
	return string(b)
}
