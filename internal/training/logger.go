package training

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"waf-project/internal/engine"
)

// Record is one JSONL line. Field order is intentionally stable so diff-style
// tooling on the training file stays readable. The "text" field is byte-equal
// to what BuildMLText would send to the live ML service.
type Record struct {
	Ts                time.Time         `json:"ts"`
	RequestID         string            `json:"request_id"`
	Text              string            `json:"text"`
	Label             string            `json:"label"` // "block" | "allow" — weak label from rule decision
	Method            string            `json:"method"`
	Path              string            `json:"path"`
	QueryLen          int               `json:"query_len"`
	BodyLen           int               `json:"body_len"`
	ContentType       string            `json:"content_type,omitempty"`
	UserAgent         string            `json:"user_agent,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	ClientIP          string            `json:"client_ip"`
	Decision          string            `json:"decision"` // BLOCK | ALLOW | CHALLENGE | LOG (full granularity)
	RuleScore         float64           `json:"rule_score"`
	MatchedRuleIDs    []string          `json:"matched_rule_ids,omitempty"`
	MatchedCategories []string          `json:"matched_categories,omitempty"`
	ResponseStatus    int               `json:"response_status"`
	LatencyUs         int64             `json:"latency_us"`
}

// Logger streams Record lines to a JSONL file that rotates daily — actual
// files land at "<base>-YYYY-MM-DD<ext>" so a long-running WAF doesn't end
// up with a single multi-GB file. Rotation is checked per record by the
// writer goroutine; no separate timer or lock is needed.
type Logger struct {
	enabled    atomic.Bool
	maxTextLen int
	basePath   string // e.g. "./logs/waf/training.jsonl"

	extraSkipPrefixes []string

	mu          sync.Mutex
	file        *os.File
	currentDate string // YYYY-MM-DD of the open file

	buf    chan *Record
	wg     sync.WaitGroup
	closed atomic.Bool

	dropped uint64
	written uint64
}

// Config is the logger's runtime knobs.
type Config struct {
	Enabled          bool
	LogPath          string   // base path; date is inserted before ext
	MaxTextLen       int      // <=0 means default (1000)
	BufferSize       int      // <=0 means default (4096)
	SkipPathPrefixes []string // user-supplied skip list, on top of built-ins
}

// NewLogger returns a started, file-opened Logger — or a disabled-but-safe
// stub if anything goes wrong (so the WAF keeps serving traffic).
func NewLogger(cfg Config) *Logger {
	l := &Logger{
		maxTextLen:        cfg.MaxTextLen,
		basePath:          cfg.LogPath,
		extraSkipPrefixes: append([]string(nil), cfg.SkipPathPrefixes...),
	}
	if l.maxTextLen <= 0 {
		l.maxTextLen = MaxTextLenDefault
	}

	if !cfg.Enabled || cfg.LogPath == "" {
		return l // disabled — Log() becomes a no-op
	}

	if err := os.MkdirAll(filepath.Dir(cfg.LogPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "training: mkdir failed: %v\n", err)
		return l
	}
	if err := l.openForToday(); err != nil {
		fmt.Fprintf(os.Stderr, "training: open failed: %v\n", err)
		return l
	}

	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = 4096
	}
	l.buf = make(chan *Record, bufSize)
	l.enabled.Store(true)

	l.wg.Add(1)
	go l.run()
	return l
}

// Enabled reports whether records will actually hit disk.
func (l *Logger) Enabled() bool { return l.enabled.Load() }

// Log captures one request. Caller passes the parsed request, the rule
// engine's evaluation result, the final decision string and response details.
// All redaction, text building, and label derivation happen here so callers
// don't have to know about training-specific concerns.
func (l *Logger) Log(
	req *engine.ParsedRequest,
	evalResult *engine.EvaluationResult,
	decision string,
	responseStatus int,
	latency time.Duration,
) {
	if !l.enabled.Load() || req == nil {
		return
	}

	// Canonical full-request format — matches what the inference path sends
	// to /predict so the training jsonl ⇄ /predict text are byte-identical.
	text := Redact(BuildCanonicalText(req, evalResult, l.maxTextLen))
	if text == "" {
		// Nothing to learn from — skip empty bodies on bypass paths.
		return
	}

	rec := &Record{
		Ts:             req.Timestamp,
		RequestID:      req.RequestID,
		Text:           text,
		Label:          deriveLabel(decision),
		Method:         req.Method,
		Path:           req.NormalizedPath,
		QueryLen:       len(req.NormalizedQuery),
		BodyLen:        req.BodySize,
		ContentType:    req.ContentType,
		UserAgent:      truncate(Redact(req.UserAgent), 256),
		Headers:        CaptureHeaders(req),
		ClientIP:       req.ClientIP,
		Decision:       decision,
		ResponseStatus: responseStatus,
		LatencyUs:      latency.Microseconds(),
	}
	if rec.Ts.IsZero() {
		rec.Ts = time.Now()
	}

	if evalResult != nil {
		rec.RuleScore = evalResult.TotalScore
		seenRule := make(map[string]bool, len(evalResult.MatchedRules))
		seenCat := make(map[string]bool, len(evalResult.MatchedRules))
		for _, m := range evalResult.MatchedRules {
			if m.RuleID != "" && !seenRule[m.RuleID] {
				seenRule[m.RuleID] = true
				rec.MatchedRuleIDs = append(rec.MatchedRuleIDs, m.RuleID)
			}
			if m.Category != "" && !seenCat[m.Category] {
				seenCat[m.Category] = true
				rec.MatchedCategories = append(rec.MatchedCategories, m.Category)
			}
		}
	}

	select {
	case l.buf <- rec:
	default:
		atomic.AddUint64(&l.dropped, 1)
	}
}

// deriveLabel collapses the WAF decision down to the binary label most
// classifiers want. CHALLENGE counts as block — the engine wasn't sure
// it was clean. LOG and ALLOW are treated as allow.
func deriveLabel(decision string) string {
	switch strings.ToUpper(decision) {
	case "BLOCK", "CHALLENGE":
		return "block"
	default:
		return "allow"
	}
}

// ShouldSkip reports whether a request to the given path should NOT be logged.
// The check combines the built-in skip list with any user-supplied prefixes
// from training.skip_path_prefixes in the YAML config.
func (l *Logger) ShouldSkip(path string) bool {
	if shouldSkipBuiltin(path) {
		return true
	}
	for _, p := range l.extraSkipPrefixes {
		if p != "" && strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ShouldSkipPath is the package-level helper used by call sites that don't
// hold a Logger. Built-in list only — for user prefixes use Logger.ShouldSkip.
func ShouldSkipPath(path string) bool {
	return shouldSkipBuiltin(path)
}

func shouldSkipBuiltin(path string) bool {
	if path == "" {
		return true
	}
	// Static assets — no attacker-controlled payload of interest.
	staticSuffix := []string{
		".js", ".mjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp3", ".mp4", ".wav", ".webm", ".ogg",
		".pdf",
	}
	lower := strings.ToLower(path)
	for _, s := range staticSuffix {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	// WAF infrastructure / realtime transports / common bot polls.
	infraPrefix := []string{
		"/health", "/healthz", "/ping", "/status", "/metrics",
		"/dashboard", "/waf-api/",
		"/login.html", "/register.html",
		"/socket.io/", "/sockjs-node/", "/_ws/", "/ws/",
		"/assets/", "/public/", "/static/",
		"/robots.txt", "/favicon.ico", "/sitemap.xml", "/.well-known/",
	}
	for _, p := range infraPrefix {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// run is the writer goroutine: encode + rotate per record.
func (l *Logger) run() {
	defer l.wg.Done()
	for rec := range l.buf {
		l.mu.Lock()
		if err := l.rotateIfNeeded(); err != nil {
			fmt.Fprintf(os.Stderr, "training: rotate failed: %v\n", err)
			l.mu.Unlock()
			continue
		}
		enc := json.NewEncoder(l.file)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "training: encode failed: %v\n", err)
		} else {
			atomic.AddUint64(&l.written, 1)
		}
		l.mu.Unlock()
	}
}

// pathForDate returns the filename to use for date d.
// "./logs/waf/training.jsonl" + 2026-05-07 → "./logs/waf/training-2026-05-07.jsonl".
func (l *Logger) pathForDate(d time.Time) string {
	ext := filepath.Ext(l.basePath)
	stem := strings.TrimSuffix(l.basePath, ext)
	return fmt.Sprintf("%s-%s%s", stem, d.UTC().Format("2006-01-02"), ext)
}

func (l *Logger) openForToday() error {
	today := time.Now().UTC().Format("2006-01-02")
	path := l.pathForDate(time.Now())
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	l.file = f
	l.currentDate = today
	return nil
}

// rotateIfNeeded swaps to a new file when UTC date changes.
// Caller must hold l.mu.
func (l *Logger) rotateIfNeeded() error {
	today := time.Now().UTC().Format("2006-01-02")
	if today == l.currentDate && l.file != nil {
		return nil
	}
	if l.file != nil {
		_ = l.file.Sync()
		_ = l.file.Close()
		l.file = nil
	}
	return l.openForToday()
}

// Stats returns counters and current path.
type Stats struct {
	Enabled bool   `json:"enabled"`
	Written uint64 `json:"written"`
	Dropped uint64 `json:"dropped"`
	Path    string `json:"path,omitempty"`
}

// Stats returns counters and current file.
func (l *Logger) Stats() Stats {
	s := Stats{
		Enabled: l.enabled.Load(),
		Written: atomic.LoadUint64(&l.written),
		Dropped: atomic.LoadUint64(&l.dropped),
	}
	l.mu.Lock()
	if l.file != nil {
		s.Path = l.file.Name()
	}
	l.mu.Unlock()
	return s
}

// Close drains the buffer and closes the file. Safe to call on a disabled logger.
func (l *Logger) Close() error {
	if !l.enabled.Load() {
		return nil
	}
	if l.closed.Swap(true) {
		return nil
	}
	close(l.buf)
	l.wg.Wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}
