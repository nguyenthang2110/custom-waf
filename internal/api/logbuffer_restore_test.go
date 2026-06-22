package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"waf-project/internal/audit"
)

// TestRestoreAccessBufferFromFile — writing N JSON lines and then calling
// RestoreAccessBufferFromFile must populate the in-memory ring with those
// entries (up to the cap) in arrival order.
func TestRestoreAccessBufferFromFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.log")
	f, err := os.Create(tmp)
	if err != nil {
		t.Fatal(err)
	}

	const total = 1200 // exceeds logBufferCapacity (1000)
	for i := 0; i < total; i++ {
		entry := &audit.AuditEntry{
			Timestamp: time.Now(),
			RequestID: fmt.Sprintf("req-%04d", i),
			ClientIP:  "10.0.0.1",
			Decision:  "ALLOW",
		}
		b, _ := json.Marshal(entry)
		f.Write(b)
		f.Write([]byte("\n"))
	}
	f.Close()

	ClearAccessBuffer()
	n, err := RestoreAccessBufferFromFile(tmp)
	if err != nil {
		t.Fatalf("RestoreAccessBufferFromFile: %v", err)
	}
	if n != logBufferCapacity {
		t.Errorf("restored %d entries, want %d (cap)", n, logBufferCapacity)
	}

	got := GetAccessBuffer()
	if len(got) != logBufferCapacity {
		t.Fatalf("buffer length: %d want %d", len(got), logBufferCapacity)
	}

	// Should hold the LAST 1000 entries (req-0200 ... req-1199).
	first := got[0]
	last := got[len(got)-1]
	if first.RequestID != "req-0200" {
		t.Errorf("first entry: got %q want req-0200", first.RequestID)
	}
	if last.RequestID != "req-1199" {
		t.Errorf("last entry: got %q want req-1199", last.RequestID)
	}
}

func TestRestoreAccessBufferFromFile_Missing(t *testing.T) {
	ClearAccessBuffer()
	n, err := RestoreAccessBufferFromFile("/nonexistent/path")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if n != 0 {
		t.Errorf("count on missing file: got %d want 0", n)
	}
}

func TestRestoreAccessBufferFromFile_SkipsBadLines(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "audit.log")
	f, _ := os.Create(tmp)
	// One good line, one corrupt, one good
	good1 := &audit.AuditEntry{RequestID: "ok-1"}
	good2 := &audit.AuditEntry{RequestID: "ok-2"}
	b1, _ := json.Marshal(good1)
	b2, _ := json.Marshal(good2)
	f.Write(b1)
	f.Write([]byte("\n"))
	f.Write([]byte("not-valid-json{{\n"))
	f.Write(b2)
	f.Write([]byte("\n"))
	f.Close()

	ClearAccessBuffer()
	n, err := RestoreAccessBufferFromFile(tmp)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != 2 {
		t.Errorf("got %d want 2 (skipping corrupt line)", n)
	}
	got := GetAccessBuffer()
	if got[0].RequestID != "ok-1" || got[1].RequestID != "ok-2" {
		t.Errorf("entries wrong: %v", got)
	}
}
