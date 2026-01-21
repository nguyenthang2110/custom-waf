package api

import (
	"sync"
	"waf-project/internal/audit"
)

// In-memory log buffer (last 1000 entries)
var logBuffer = make([]*audit.AuditEntry, 0, 1000)
var logMutex sync.RWMutex

// AddToLogBuffer adds entry to buffer
func AddToLogBuffer(entry *audit.AuditEntry) {
	logMutex.Lock()
	defer logMutex.Unlock()

	logBuffer = append(logBuffer, entry)
	if len(logBuffer) > 1000 {
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

	logBuffer = make([]*audit.AuditEntry, 0, 1000)
}
