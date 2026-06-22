package api

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"sync"

	"waf-project/internal/audit"
)

// Capacity of each in-memory ring shown on the dashboard. Anything older
// is still on disk in the corresponding log file — this is the live view.
const logBufferCapacity = 1000

// logRing is a fixed-capacity, concurrency-safe ring of log entries backing
// one dashboard view. The WAF keeps two independent rings:
//
//   - accessRing — every HTTP request + WAF verdict (the access log).
//   - auditRing  — admin / security events only (the audit log).
//
// They are separate so the high-volume request traffic never evicts the
// low-volume accountability events (and vice-versa) from the live view.
type logRing struct {
	mu  sync.RWMutex
	buf []*audit.AuditEntry
}

func newLogRing() *logRing {
	return &logRing{buf: make([]*audit.AuditEntry, 0, logBufferCapacity)}
}

func (r *logRing) add(entry *audit.AuditEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, entry)
	if len(r.buf) > logBufferCapacity {
		r.buf = r.buf[1:]
	}
}

// snapshot returns a copy of the ring in arrival order (oldest first).
func (r *logRing) snapshot() []*audit.AuditEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*audit.AuditEntry, len(r.buf))
	copy(result, r.buf)
	return result
}

func (r *logRing) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = make([]*audit.AuditEntry, 0, logBufferCapacity)
}

// restoreFromFile rebuilds the ring from a JSON-lines log file. Called once
// at boot so the dashboard isn't empty after a restart. We tail the last
// logBufferCapacity lines; malformed lines (truncated writes, partial
// rotations) are skipped silently rather than aborting the whole restore.
func (r *logRing) restoreFromFile(path string) (int, error) {
	if path == "" {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	// Ring populated by streaming through the file. Avoids loading the
	// whole log into memory just to keep the last logBufferCapacity entries.
	ring := make([]*audit.AuditEntry, logBufferCapacity)
	head, count := 0, 0

	scanner := bufio.NewScanner(f)
	// JSON entries can include long bodies/headers; bump the line size
	// well above the default 64 KB to avoid scanner errors on edge cases.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		entry := &audit.AuditEntry{}
		if err := json.Unmarshal(raw, entry); err != nil {
			continue // partial/corrupt line — skip
		}
		ring[head] = entry
		head = (head + 1) % logBufferCapacity
		if count < logBufferCapacity {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("logbuffer: scan error: %v", err)
	}

	// Flatten ring → slice in arrival order
	out := make([]*audit.AuditEntry, 0, count)
	start := (head - count + logBufferCapacity) % logBufferCapacity
	for i := 0; i < count; i++ {
		out = append(out, ring[(start+i)%logBufferCapacity])
	}

	r.mu.Lock()
	r.buf = out
	r.mu.Unlock()

	return count, nil
}

// The two live rings backing the dashboard.
var (
	accessRing = newLogRing() // every request + verdict
	auditRing  = newLogRing() // admin / security events
)

// --- Access log (per-request) buffer ---------------------------------------

// AddToAccessBuffer records one request entry in the access-log ring.
func AddToAccessBuffer(entry *audit.AuditEntry) { accessRing.add(entry) }

// GetAccessBuffer returns a copy of the access-log ring (oldest first).
func GetAccessBuffer() []*audit.AuditEntry { return accessRing.snapshot() }

// ClearAccessBuffer empties the access-log ring.
func ClearAccessBuffer() { accessRing.clear() }

// RestoreAccessBufferFromFile reloads the access-log ring from disk at boot.
func RestoreAccessBufferFromFile(path string) (int, error) { return accessRing.restoreFromFile(path) }

// --- Audit log (admin/security events) buffer ------------------------------

// AddToAuditBuffer records one admin/security event in the audit-log ring.
func AddToAuditBuffer(entry *audit.AuditEntry) { auditRing.add(entry) }

// GetAuditBuffer returns a copy of the audit-log ring (oldest first).
func GetAuditBuffer() []*audit.AuditEntry { return auditRing.snapshot() }

// ClearAuditBuffer empties the audit-log ring.
func ClearAuditBuffer() { auditRing.clear() }

// RestoreAuditBufferFromFile reloads the audit-log ring from disk at boot.
func RestoreAuditBufferFromFile(path string) (int, error) { return auditRing.restoreFromFile(path) }
