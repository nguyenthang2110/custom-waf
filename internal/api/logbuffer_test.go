package api

import (
	"testing"
	"waf-project/internal/audit"
)

func TestClearAccessBuffer(t *testing.T) {
	// Setup
	ClearAccessBuffer()
	if len(GetAccessBuffer()) != 0 {
		t.Errorf("Expected buffer to be empty initially, got %d", len(GetAccessBuffer()))
	}

	// Add logs
	entry := &audit.AuditEntry{
		RequestID: "test-1",
	}
	AddToAccessBuffer(entry)

	if len(GetAccessBuffer()) != 1 {
		t.Errorf("Expected buffer to have 1 entry, got %d", len(GetAccessBuffer()))
	}

	// Clear logs
	ClearAccessBuffer()

	if len(GetAccessBuffer()) != 0 {
		t.Errorf("Expected buffer to be empty after clear, got %d", len(GetAccessBuffer()))
	}

	// Verify we can add again
	AddToAccessBuffer(entry)
	if len(GetAccessBuffer()) != 1 {
		t.Errorf("Expected buffer to have 1 entry after re-add, got %d", len(GetAccessBuffer()))
	}
}
