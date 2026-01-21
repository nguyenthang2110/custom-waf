package api

import (
	"testing"
	"waf-project/internal/audit"
)

func TestClearLogBuffer(t *testing.T) {
	// Setup
	ClearLogBuffer()
	if len(logBuffer) != 0 {
		t.Errorf("Expected buffer to be empty initially, got %d", len(logBuffer))
	}

	// Add logs
	entry := &audit.AuditEntry{
		RequestID: "test-1",
	}
	AddToLogBuffer(entry)

	if len(logBuffer) != 1 {
		t.Errorf("Expected buffer to have 1 entry, got %d", len(logBuffer))
	}

	// Clear logs
	ClearLogBuffer()

	if len(logBuffer) != 0 {
		t.Errorf("Expected buffer to be empty after clear, got %d", len(logBuffer))
	}

	// Verify we can add again
	AddToLogBuffer(entry)
	if len(logBuffer) != 1 {
		t.Errorf("Expected buffer to have 1 entry after re-add, got %d", len(logBuffer))
	}
}
