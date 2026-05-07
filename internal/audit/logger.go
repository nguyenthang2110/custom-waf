// internal/audit/logger.go
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"waf-project/internal/engine"
)

// Logger handles audit logging for WAF events
type Logger struct {
	file          *os.File
	writer        io.Writer
	mu            sync.Mutex
	config        AuditConfig
	rotationTimer *time.Timer
	stopRotation  chan bool
	buffer        chan *AuditEntry
	stats         *LoggerStats
}

// AuditConfig defines audit logging configuration
type AuditConfig struct {
	LogPath          string        // Path to log file
	RotationEnabled  bool          // Enable log rotation
	RotationSize     int64         // Rotate when file reaches this size (bytes)
	RotationInterval time.Duration // Rotate after this time period
	MaxBackups       int           // Number of backup files to keep
	Compress         bool          // Compress rotated logs
	BufferSize       int           // Number of entries to buffer
	AsyncWrite       bool          // Write logs asynchronously
	IncludeDebug     bool          // Include debug information
	LogFormat        string        // JSON or TEXT
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	// Basic request info
	Timestamp time.Time `json:"timestamp"`
	RequestID string    `json:"request_id"`
	ClientIP  string    `json:"client_ip"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Query     string    `json:"query,omitempty"`

	// Request details
	UserAgent   string `json:"user_agent"`
	Referer     string `json:"referer,omitempty"`
	Protocol    string `json:"protocol"`
	Host        string `json:"host"`
	ContentType string `json:"content_type,omitempty"`
	BodySize    int    `json:"body_size"`

	// WAF decision
	Decision      string  `json:"decision"`
	TotalScore    float64 `json:"total_score"`
	RuleScore     float64 `json:"rule_score"`
	BehaviorScore float64 `json:"behavior_score,omitempty"`

	// Matched rules
	MatchedRules []RuleMatch `json:"matched_rules,omitempty"`
	RuleCount    int         `json:"rule_count"`

	// Categories
	Categories []string `json:"categories,omitempty"`

	// Behavior threats
	BehaviorThreats []string `json:"behavior_threats,omitempty"`

	// Response info
	ResponseStatus int           `json:"response_status"`
	ResponseSize   int           `json:"response_size,omitempty"`
	Latency        time.Duration `json:"latency"`
	LatencyMs      float64       `json:"latency_ms"`

	// Rate limiting
	RateLimited     bool `json:"rate_limited"`
	RemainingTokens int  `json:"remaining_tokens,omitempty"`

	// Blocking info
	BlockDuration time.Duration `json:"block_duration,omitempty"`
	BlockReason   string        `json:"block_reason,omitempty"`

	// GeoIP info (if available)
	Country string `json:"country,omitempty"`
	ASN     string `json:"asn,omitempty"`

	// Additional metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// RuleMatch represents a matched rule in audit log
type RuleMatch struct {
	RuleID    string  `json:"rule_id"`
	Category  string  `json:"category"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	MatchedOn string  `json:"matched_on"`
	Pattern   string  `json:"pattern,omitempty"`
	Payload   string  `json:"payload,omitempty"`
}

// LoggerStats tracks logger statistics
type LoggerStats struct {
	TotalEntries   int64
	DroppedEntries int64
	BytesWritten   int64
	RotationCount  int64
	LastRotation   time.Time
	mu             sync.RWMutex
}

// NewLogger creates a new audit logger
func NewLogger(config AuditConfig) *Logger {
	// Set defaults
	if config.LogPath == "" {
		config.LogPath = "/var/log/waf/audit.log"
	}
	if config.RotationSize == 0 {
		config.RotationSize = 100 * 1024 * 1024 // 100MB
	}
	if config.RotationInterval == 0 {
		config.RotationInterval = 24 * time.Hour
	}
	if config.MaxBackups == 0 {
		config.MaxBackups = 7
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.LogFormat == "" {
		config.LogFormat = "JSON"
	}

	// Create log directory if it doesn't exist
	logDir := filepath.Dir(config.LogPath)
	os.MkdirAll(logDir, 0755)

	// Open log file
	file, err := os.OpenFile(config.LogPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		file = nil
	}

	logger := &Logger{
		file:         file,
		writer:       file,
		config:       config,
		stopRotation: make(chan bool),
		buffer:       make(chan *AuditEntry, config.BufferSize),
		stats:        &LoggerStats{},
	}

	// Start async writer if enabled
	if config.AsyncWrite {
		go logger.asyncWriter()
	}

	// Start rotation timer if enabled
	if config.RotationEnabled && config.RotationInterval > 0 {
		logger.startRotationTimer()
	}

	return logger
}

// Log writes an audit entry
func (l *Logger) Log(entry *AuditEntry) {
	if l.config.AsyncWrite {
		// Non-blocking write to buffer
		select {
		case l.buffer <- entry:
			// Successfully buffered
		default:
			// Buffer full, drop entry
			l.updateStats(func() {
				l.stats.DroppedEntries++
			})
		}
	} else {
		// Synchronous write
		l.writeEntry(entry)
	}
}

// writeEntry writes a single entry to log
func (l *Logger) writeEntry(entry *AuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.writer == nil {
		return
	}

	var data []byte
	var err error

	// Format based on configuration
	if l.config.LogFormat == "JSON" {
		data, err = json.Marshal(entry)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to marshal log entry: %v\n", err)
			return
		}
		data = append(data, '\n')
	} else {
		// Plain text format
		data = []byte(l.formatTextEntry(entry))
	}

	// Write to file
	n, err := l.writer.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write log entry: %v\n", err)
		return
	}

	// Update stats
	l.updateStats(func() {
		l.stats.TotalEntries++
		l.stats.BytesWritten += int64(n)
	})

	// Check if rotation needed
	if l.config.RotationEnabled && l.shouldRotate() {
		l.rotate()
	}
}

// formatTextEntry formats entry as plain text
func (l *Logger) formatTextEntry(entry *AuditEntry) string {
	return fmt.Sprintf(
		"[%s] %s %s %s %s -> %s (Score: %.2f, Decision: %s, Latency: %dms)\n",
		entry.Timestamp.Format(time.RFC3339),
		entry.RequestID,
		entry.ClientIP,
		entry.Method,
		entry.Path,
		entry.UserAgent,
		entry.TotalScore,
		entry.Decision,
		int(entry.LatencyMs),
	)
}

// asyncWriter processes buffered entries asynchronously
func (l *Logger) asyncWriter() {
	for entry := range l.buffer {
		l.writeEntry(entry)
	}
}

// shouldRotate checks if log rotation is needed
func (l *Logger) shouldRotate() bool {
	if l.file == nil {
		return false
	}

	// Check file size
	if l.config.RotationSize > 0 {
		info, err := l.file.Stat()
		if err == nil && info.Size() >= l.config.RotationSize {
			return true
		}
	}

	return false
}

// rotate performs log rotation
func (l *Logger) rotate() {
	// Close current file
	if l.file != nil {
		l.file.Close()
	}

	// Generate backup filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	backupPath := fmt.Sprintf("%s.%s", l.config.LogPath, timestamp)

	// Rename current log to backup
	if err := os.Rename(l.config.LogPath, backupPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to rotate log: %v\n", err)
		return
	}

	// Compress if enabled
	if l.config.Compress {
		go l.compressLog(backupPath)
	}

	// Open new log file
	file, err := os.OpenFile(l.config.LogPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open new log file: %v\n", err)
		return
	}

	l.file = file
	l.writer = file

	// Update stats
	l.updateStats(func() {
		l.stats.RotationCount++
		l.stats.LastRotation = time.Now()
	})

	// Cleanup old backups
	go l.cleanupOldBackups()
}

// compressLog compresses a log file
func (l *Logger) compressLog(path string) {
	// TODO: Implement gzip compression
	// This is a placeholder for compression logic
}

// cleanupOldBackups removes old backup files
func (l *Logger) cleanupOldBackups() {
	logDir := filepath.Dir(l.config.LogPath)
	logBase := filepath.Base(l.config.LogPath)

	files, err := filepath.Glob(filepath.Join(logDir, logBase+".*"))
	if err != nil {
		return
	}

	// If we have more than MaxBackups, delete oldest
	if len(files) > l.config.MaxBackups {
		// Sort by modification time (oldest first)
		// For simplicity, just delete excess files
		for i := 0; i < len(files)-l.config.MaxBackups; i++ {
			os.Remove(files[i])
		}
	}
}

// startRotationTimer starts periodic rotation
func (l *Logger) startRotationTimer() {
	l.rotationTimer = time.NewTimer(l.config.RotationInterval)

	go func() {
		for {
			select {
			case <-l.rotationTimer.C:
				l.rotate()
				l.rotationTimer.Reset(l.config.RotationInterval)
			case <-l.stopRotation:
				l.rotationTimer.Stop()
				return
			}
		}
	}()
}

// LogRequest is a convenience method to log from parsed request and eval result
func (l *Logger) LogRequest(
	req *engine.ParsedRequest,
	evalResult *engine.EvaluationResult,
	decision string,
	responseStatus int,
	latency time.Duration,
) {
	// Build rule matches
	matches := make([]RuleMatch, 0, len(evalResult.MatchedRules))
	categories := make([]string, 0)
	categoryMap := make(map[string]bool)

	for _, match := range evalResult.MatchedRules {
		matches = append(matches, RuleMatch{
			RuleID:    match.RuleID,
			Category:  match.Category,
			Severity:  match.Severity,
			Score:     match.Score,
			MatchedOn: match.MatchedOn,
			Pattern:   match.Pattern,
			Payload:   match.Value,
		})

		// Collect unique categories
		if !categoryMap[match.Category] {
			categories = append(categories, match.Category)
			categoryMap[match.Category] = true
		}
	}

	// Create audit entry
	entry := &AuditEntry{
		Timestamp:      req.Timestamp,
		RequestID:      req.RequestID,
		ClientIP:       req.ClientIP,
		Method:         req.Method,
		Path:           req.NormalizedPath,
		Query:          req.NormalizedQuery,
		UserAgent:      req.UserAgent,
		Protocol:       req.Protocol,
		Host:           req.Host,
		ContentType:    req.ContentType,
		BodySize:       req.BodySize,
		Decision:       decision,
		TotalScore:     evalResult.TotalScore,
		RuleScore:      evalResult.TotalScore,
		MatchedRules:   matches,
		RuleCount:      len(matches),
		Categories:     categories,
		ResponseStatus: responseStatus,
		Latency:        latency,
		LatencyMs:      float64(latency.Microseconds()) / 1000.0,
		Metadata:       make(map[string]interface{}),
	}

	l.Log(entry)
}

// GetStats returns logger statistics
func (l *Logger) GetStats() *LoggerStats {
	l.stats.mu.RLock()
	defer l.stats.mu.RUnlock()

	return &LoggerStats{
		TotalEntries:   l.stats.TotalEntries,
		DroppedEntries: l.stats.DroppedEntries,
		BytesWritten:   l.stats.BytesWritten,
		RotationCount:  l.stats.RotationCount,
		LastRotation:   l.stats.LastRotation,
	}
}

// updateStats safely updates statistics
func (l *Logger) updateStats(fn func()) {
	l.stats.mu.Lock()
	defer l.stats.mu.Unlock()
	fn()
}

// Flush flushes any buffered entries
func (l *Logger) Flush() {
	if l.config.AsyncWrite {
		// Wait for buffer to drain
		for len(l.buffer) > 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Sync()
	}
}

// Close closes the logger and flushes remaining entries
func (l *Logger) Close() {
	// Stop rotation timer
	if l.rotationTimer != nil {
		l.stopRotation <- true
	}

	// Flush remaining entries
	l.Flush()

	// Close buffer channel
	if l.config.AsyncWrite {
		close(l.buffer)
		time.Sleep(100 * time.Millisecond) // Give writer time to finish
	}

	// Close file
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

// SetLogLevel sets the log level (for future filtering)
func (l *Logger) SetLogLevel(level string) {
	// TODO: Implement log level filtering
}

// GetLogPath returns the current log file path
func (l *Logger) GetLogPath() string {
	return l.config.LogPath
}

// GetBufferSize returns current buffer size
func (l *Logger) GetBufferSize() int {
	if !l.config.AsyncWrite {
		return 0
	}
	return len(l.buffer)
}

// IsBufferFull checks if buffer is full
func (l *Logger) IsBufferFull() bool {
	if !l.config.AsyncWrite {
		return false
	}
	return len(l.buffer) >= l.config.BufferSize
}

// ============================================================================
// Query Functions (for log analysis)
// ============================================================================

// QueryLogs searches logs for specific criteria (placeholder)
func (l *Logger) QueryLogs(criteria map[string]interface{}) ([]*AuditEntry, error) {
	// TODO: Implement log querying
	// This would parse the log file and filter entries
	return nil, fmt.Errorf("not implemented")
}

// GetRecentBlocks returns recent blocked requests (placeholder)
func (l *Logger) GetRecentBlocks(limit int) ([]*AuditEntry, error) {
	// TODO: Implement reading and filtering logs
	return nil, fmt.Errorf("not implemented")
}

// ============================================================================
// Helper Functions
// ============================================================================

// FormatJSON formats entry as JSON string
func FormatJSON(entry *AuditEntry) string {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return ""
	}
	return string(data)
}

// ParseLogLine parses a JSON log line
func ParseLogLine(line string) (*AuditEntry, error) {
	var entry AuditEntry
	err := json.Unmarshal([]byte(line), &entry)
	if err != nil {
		return nil, err
	}
	return &entry, nil
}

// ============================================================================
// Structured Logging Helpers
// ============================================================================

// LogSecurityEvent logs a security event with context
func (l *Logger) LogSecurityEvent(
	eventType string,
	severity string,
	clientIP string,
	description string,
	metadata map[string]interface{},
) {
	entry := &AuditEntry{
		Timestamp:      time.Now(),
		RequestID:      fmt.Sprintf("SEC-%d", time.Now().Unix()),
		ClientIP:       clientIP,
		Decision:       eventType,
		BlockReason:    description,
		Metadata:       metadata,
		ResponseStatus: 0, // Not a request
	}

	if metadata == nil {
		entry.Metadata = make(map[string]interface{})
	}
	entry.Metadata["event_type"] = eventType
	entry.Metadata["severity"] = severity

	l.Log(entry)
}

// LogSystemEvent logs a system-level event
func (l *Logger) LogSystemEvent(eventType string, message string) {
	entry := &AuditEntry{
		Timestamp:   time.Now(),
		RequestID:   fmt.Sprintf("SYS-%d", time.Now().Unix()),
		Decision:    "SYSTEM",
		BlockReason: message,
		Metadata: map[string]interface{}{
			"event_type": eventType,
			"message":    message,
		},
	}

	l.Log(entry)
}
