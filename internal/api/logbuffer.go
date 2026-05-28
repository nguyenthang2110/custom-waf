package api

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"sync"

	"waf-project/internal/audit"
)

// Capacity of the in-memory ring shown on the dashboard. Anything older
// is still on disk in the audit log file — this is the live view.
const logBufferCapacity = 1000

// In-memory log buffer (last 1000 entries)
var logBuffer = make([]*audit.AuditEntry, 0, logBufferCapacity)
var logMutex sync.RWMutex

// AddToLogBuffer adds entry to buffer
func AddToLogBuffer(entry *audit.AuditEntry) {
	logMutex.Lock()
	defer logMutex.Unlock()

	logBuffer = append(logBuffer, entry)
	if len(logBuffer) > logBufferCapacity {
		logBuffer = logBuffer[1:]
	}
}

// GetLogBuffer returns all logs
func GetLogBuffer() []*audit.AuditEntry {
	logMutex.RLock()
	defer logMutex.RUnlock()

	// Return copy
	result := make([]*audit.AuditEntry, len(logBuffer))
	copy(result, logBuffer)
	return result
}

// ClearLogBuffer clears all logs from the buffer
func ClearLogBuffer() {
	logMutex.Lock()
	defer logMutex.Unlock()

	logBuffer = make([]*audit.AuditEntry, 0, logBufferCapacity)
}

// RestoreLogBufferFromFile rebuilds the in-memory dashboard buffer from
// the audit log file. Called once at boot so the "recent events" widget
// isn't empty after every restart. We tail the last logBufferCapacity
// JSON lines; malformed lines (truncated writes, partial rotations)
// are skipped silently rather than aborting the whole restore.
func RestoreLogBufferFromFile(path string) (int, error) {
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

	// Ring of size logBufferCapacity, populated by streaming through
	// the file. Avoids loading the whole audit log into memory just
	// to keep the last 1000 entries.
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

	logMutex.Lock()
	logBuffer = out
	logMutex.Unlock()

	return count, nil
}
