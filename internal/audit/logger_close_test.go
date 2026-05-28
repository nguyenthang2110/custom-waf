package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCloseDrainsBuffer — the deterministic shutdown drain (added in
// statestore work) must write every buffered entry to disk instead of
// sleeping 100ms and risking drops on busy WAFs.
func TestCloseDrainsBuffer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := NewLogger(AuditConfig{
		LogPath:    path,
		AsyncWrite: true,
		BufferSize: 5000,
		LogFormat:  "JSON",
	})

	const N = 4000
	for i := 0; i < N; i++ {
		l.Log(&AuditEntry{RequestID: "r", Decision: "ALLOW"})
	}
	l.Close()

	// Count lines on disk — should be at least N minus any drops
	// (BufferSize == 5000 > N, so drops are 0).
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	count := 0
	for s := bufio.NewScanner(f); s.Scan(); {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		var e AuditEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("malformed JSON line: %v", err)
		}
		count++
	}
	stats := l.GetStats()
	if stats.DroppedEntries != 0 {
		t.Logf("dropped: %d (buffer was sized to avoid drops)", stats.DroppedEntries)
	}
	if int64(count) < int64(N)-stats.DroppedEntries {
		t.Errorf("close lost entries: file=%d N=%d dropped=%d", count, N, stats.DroppedEntries)
	}
}

// TestCloseIdempotent — multiple Close calls must not panic or
// double-close the channel.
func TestCloseIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l := NewLogger(AuditConfig{
		LogPath:    path,
		AsyncWrite: true,
		BufferSize: 16,
	})
	l.Log(&AuditEntry{RequestID: "a"})
	l.Close()
	l.Close() // must not panic
	l.Close()
}
