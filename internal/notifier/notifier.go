// Package notifier dispatches WAF security events to external channels
// (Slack, generic webhook, email).
//
// Design notes
//
//   - All sends are async — Notifier.Send() returns immediately and a worker
//     goroutine fans out to enabled channels. The hot WAF path never blocks
//     on a remote endpoint.
//
//   - Per-channel timeout (default 5s) protects against slow webhooks
//     hanging the worker.
//
//   - Throttling: an in-memory dedup map keyed by (channel, IP, ruleID)
//     drops duplicates inside a configurable window (default 5 min). Stops
//     a single attacker flood from filling the recipient inbox.
//
//   - Severity filter: events below the configured minimum severity are
//     dropped before the worker fanout.
package notifier

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Severity ordering for the MinSeverity filter.
var sevRank = map[string]int{
	"INFO":     0,
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

func sevOK(s, min string) bool {
	rs, ok1 := sevRank[strings.ToUpper(s)]
	rm, ok2 := sevRank[strings.ToUpper(min)]
	if !ok1 {
		rs = 2
	} // unknown = MEDIUM
	if !ok2 {
		rm = 2
	}
	return rs >= rm
}

// Event describes a single WAF security event worth alerting on.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Decision  string    `json:"decision"`   // BLOCK / CHALLENGE / LOG
	Severity  string    `json:"severity"`   // INFO/LOW/MEDIUM/HIGH/CRITICAL
	ClientIP  string    `json:"client_ip"`
	Method    string    `json:"method"`
	Host      string    `json:"host"`
	Path      string    `json:"path"`
	Reason    string    `json:"reason"`
	RuleID    string    `json:"rule_id,omitempty"`
	Score     float64   `json:"score"`
	UserAgent string    `json:"user_agent,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
}

// Config is the user-facing notifier configuration. Mutate via SetConfig.
//
// Each channel type holds a *list* of destinations rather than a single
// config. Operators can register multiple Slack workspaces, multiple email
// recipient groups, or multiple webhook receivers — each with its own
// enabled flag, name, and per-destination templates. An event fans out to
// every enabled destination across every channel type.
type Config struct {
	Enabled         bool          `json:"enabled"           yaml:"enabled"`
	MinSeverity     string        `json:"min_severity"      yaml:"min_severity"`     // INFO..CRITICAL; default HIGH
	ThrottleSeconds int           `json:"throttle_seconds"  yaml:"throttle_seconds"` // dedup window; default 300
	Timeout         time.Duration `json:"-"                 yaml:"timeout"`          // per channel send; default 5s

	Slack   []SlackDestination   `json:"slack"   yaml:"slack"`
	Email   []EmailDestination   `json:"email"   yaml:"email"`
	Webhook []WebhookDestination `json:"webhook" yaml:"webhook"`
}

// DestStats are tiny per-destination counters surfaced to the dashboard.
type DestStats struct {
	Sent           uint64 `json:"sent_count"`
	Failed         uint64 `json:"failed_count"`
	LastTestResult string `json:"last_test_result,omitempty"`
	LastTestAt     string `json:"last_test_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	LastSentAt     string `json:"last_sent_at,omitempty"`
}

// SlackDestination is one Slack incoming-webhook target.
// MessageTemplate uses {placeholder} substitution against the Event fields
// (see TemplatePlaceholders). Empty = use the built-in default formatter.
type SlackDestination struct {
	ID              string `json:"id"               yaml:"id"`
	Name            string `json:"name"             yaml:"name"`
	Enabled         bool   `json:"enabled"          yaml:"enabled"`
	WebhookURL      string `json:"webhook_url"      yaml:"webhook_url"`
	Channel         string `json:"channel"          yaml:"channel"`
	Username        string `json:"username"         yaml:"username"`
	MessageTemplate string `json:"message_template" yaml:"message_template"`

	Stats DestStats `json:"stats,omitempty" yaml:"-"`
}

// EmailDestination is one SMTP target (one set of recipients).
type EmailDestination struct {
	ID              string   `json:"id"               yaml:"id"`
	Name            string   `json:"name"             yaml:"name"`
	Enabled         bool     `json:"enabled"          yaml:"enabled"`
	Host            string   `json:"host"             yaml:"host"`
	Port            int      `json:"port"             yaml:"port"`
	Username        string   `json:"username"         yaml:"username"`
	Password        string   `json:"password"         yaml:"password"`
	From            string   `json:"from"             yaml:"from"`
	To              []string `json:"to"               yaml:"to"`
	UseTLS          bool     `json:"use_tls"          yaml:"use_tls"`
	SubjectTemplate string   `json:"subject_template" yaml:"subject_template"`
	BodyTemplate    string   `json:"body_template"    yaml:"body_template"`

	Stats DestStats `json:"stats,omitempty" yaml:"-"`
}

// WebhookDestination is one generic HTTP POST sink. When PayloadTemplate is
// empty the body is the default Event JSON; otherwise the rendered template
// is sent as-is.
type WebhookDestination struct {
	ID              string            `json:"id"               yaml:"id"`
	Name            string            `json:"name"             yaml:"name"`
	Enabled         bool              `json:"enabled"          yaml:"enabled"`
	URL             string            `json:"url"              yaml:"url"`
	Method          string            `json:"method"           yaml:"method"` // default POST
	Headers         map[string]string `json:"headers"          yaml:"headers"`
	PayloadTemplate string            `json:"payload_template" yaml:"payload_template"`

	Stats DestStats `json:"stats,omitempty" yaml:"-"`
}

// newDestID generates a stable, URL-safe ID like "slack_a1b2c3d4".
func newDestID(prefix string) string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		// Fallback — extremely unlikely.
		return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	}
	return prefix + "_" + hex.EncodeToString(b)
}

// TemplatePlaceholders lists the substitution tokens accepted by every
// template field (Slack message, email subject/body, webhook payload).
// The dashboard surfaces this list to users.
var TemplatePlaceholders = []string{
	"{timestamp}", "{decision}", "{severity}", "{client_ip}", "{method}",
	"{host}", "{path}", "{reason}", "{rule_id}", "{score}",
	"{user_agent}", "{request_id}",
}

// renderTemplate performs simple {field} substitution on the template.
// Unknown placeholders are left untouched so users can spot typos.
func renderTemplate(tpl string, e Event) string {
	if tpl == "" {
		return ""
	}
	r := strings.NewReplacer(
		"{timestamp}",  e.Timestamp.Format(time.RFC3339),
		"{decision}",   e.Decision,
		"{severity}",   e.Severity,
		"{client_ip}",  e.ClientIP,
		"{method}",     e.Method,
		"{host}",       e.Host,
		"{path}",       e.Path,
		"{reason}",     e.Reason,
		"{rule_id}",    e.RuleID,
		"{score}",      fmt.Sprintf("%.2f", e.Score),
		"{user_agent}", e.UserAgent,
		"{request_id}", e.RequestID,
	)
	return r.Replace(tpl)
}

// Stats tracks lifetime counters per channel.
type Stats struct {
	Queued     uint64 `json:"queued"`
	Sent       uint64 `json:"sent"`
	Failed     uint64 `json:"failed"`
	Throttled  uint64 `json:"throttled"`
	BelowSev   uint64 `json:"below_severity"`
	SlackSent  uint64 `json:"slack_sent"`
	EmailSent  uint64 `json:"email_sent"`
	WebhookOK  uint64 `json:"webhook_sent"`
	LastError  string `json:"last_error,omitempty"`
	LastSentAt string `json:"last_sent_at,omitempty"`
}

// Notifier owns the worker goroutine and channel state.
type Notifier struct {
	mu        sync.RWMutex
	cfg       Config
	httpc     *http.Client
	queue     chan Event
	stop      chan struct{}
	dedup     map[string]time.Time
	dedupMu   sync.Mutex
	stats     atomicStats
}

// New constructs a Notifier with sane defaults and starts the worker.
// Caller must call Close on shutdown.
func New(cfg Config) *Notifier {
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "HIGH"
	}
	if cfg.ThrottleSeconds <= 0 {
		cfg.ThrottleSeconds = 300
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	n := &Notifier{
		cfg:   cfg,
		httpc: &http.Client{Timeout: cfg.Timeout},
		queue: make(chan Event, 256),
		stop:  make(chan struct{}),
		dedup: make(map[string]time.Time),
	}
	go n.worker()
	go n.dedupSweeper()
	return n
}

// SetConfig hot-swaps configuration. Worker keeps running. Any destination
// missing an ID gets one assigned in-place so subsequent GET shows stable IDs.
func (n *Notifier) SetConfig(cfg Config) {
	if cfg.MinSeverity == "" {
		cfg.MinSeverity = "HIGH"
	}
	if cfg.ThrottleSeconds <= 0 {
		cfg.ThrottleSeconds = 300
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	for i := range cfg.Slack {
		if cfg.Slack[i].ID == "" {
			cfg.Slack[i].ID = newDestID("slack")
		}
	}
	for i := range cfg.Email {
		if cfg.Email[i].ID == "" {
			cfg.Email[i].ID = newDestID("email")
		}
	}
	for i := range cfg.Webhook {
		if cfg.Webhook[i].ID == "" {
			cfg.Webhook[i].ID = newDestID("webhook")
		}
	}
	n.mu.Lock()
	// Preserve in-memory Stats from previous run when destination ID matches.
	cfg = preserveStats(n.cfg, cfg)
	n.cfg = cfg
	n.httpc.Timeout = cfg.Timeout
	n.mu.Unlock()
}

// preserveStats copies per-destination Stats from old → new whenever IDs match.
// New destinations start fresh; deleted ones are dropped with their stats.
func preserveStats(old, fresh Config) Config {
	stash := map[string]DestStats{}
	for _, d := range old.Slack {
		stash[d.ID] = d.Stats
	}
	for _, d := range old.Email {
		stash[d.ID] = d.Stats
	}
	for _, d := range old.Webhook {
		stash[d.ID] = d.Stats
	}
	for i := range fresh.Slack {
		if s, ok := stash[fresh.Slack[i].ID]; ok {
			fresh.Slack[i].Stats = s
		}
	}
	for i := range fresh.Email {
		if s, ok := stash[fresh.Email[i].ID]; ok {
			fresh.Email[i].Stats = s
		}
	}
	for i := range fresh.Webhook {
		if s, ok := stash[fresh.Webhook[i].ID]; ok {
			fresh.Webhook[i].Stats = s
		}
	}
	return fresh
}

// GetConfig returns a copy of the current config (passwords redacted is the
// caller's responsibility).
func (n *Notifier) GetConfig() Config {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.cfg
}

// GetStats returns a snapshot of lifetime counters.
func (n *Notifier) GetStats() Stats {
	return n.stats.snapshot()
}

// Send enqueues an event for async fanout. Never blocks; if the queue is
// full the event is dropped (and counted as failed).
func (n *Notifier) Send(e Event) {
	n.mu.RLock()
	enabled := n.cfg.Enabled
	min := n.cfg.MinSeverity
	n.mu.RUnlock()
	if !enabled {
		return
	}
	if !sevOK(e.Severity, min) {
		n.stats.incBelowSev()
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	select {
	case n.queue <- e:
		n.stats.incQueued()
	default:
		n.stats.incFailed("queue full")
	}
}

// syntheticTestEvent is the canned alert payload used by all test paths.
func syntheticTestEvent() Event {
	return Event{
		Timestamp: time.Now(),
		Decision:  "TEST",
		Severity:  "HIGH",
		ClientIP:  "127.0.0.1",
		Method:    "GET",
		Host:      "waf.local",
		Path:      "/__test",
		Reason:    "Manual alert test from dashboard",
		RuleID:    "WAF-TEST-0001",
		Score:     7.5,
		UserAgent: "WAF/test",
		RequestID: "test-" + time.Now().Format("150405"),
	}
}

// TestSlack fires a synthetic event to the given Slack destination, bypassing
// severity filter / throttle / enabled flag. Used by the dashboard test button.
// The destination object passed in may be unsaved.
func (n *Notifier) TestSlack(d SlackDestination) string {
	if d.WebhookURL == "" {
		return "Slack webhook URL is empty"
	}
	ctx, cancel := context.WithTimeout(context.Background(), n.GetConfig().Timeout+1*time.Second)
	defer cancel()
	if err := n.sendSlack(ctx, d, syntheticTestEvent()); err != nil {
		n.stats.incFailed(err.Error())
		n.recordDestTest(d.ID, "FAIL: "+err.Error())
		return err.Error()
	}
	n.stats.incSlackSent()
	n.recordDestTest(d.ID, "OK")
	return "OK"
}

// TestEmail mirrors TestSlack for the SMTP channel.
func (n *Notifier) TestEmail(d EmailDestination) string {
	if d.Host == "" || len(d.To) == 0 {
		return "Email destination needs at least a host and one recipient"
	}
	if err := n.sendEmail(d, syntheticTestEvent()); err != nil {
		n.stats.incFailed(err.Error())
		n.recordDestTest(d.ID, "FAIL: "+err.Error())
		return err.Error()
	}
	n.stats.incEmailSent()
	n.recordDestTest(d.ID, "OK")
	return "OK"
}

// TestWebhook mirrors TestSlack for the generic webhook channel.
func (n *Notifier) TestWebhook(d WebhookDestination) string {
	if d.URL == "" {
		return "Webhook URL is empty"
	}
	ctx, cancel := context.WithTimeout(context.Background(), n.GetConfig().Timeout+1*time.Second)
	defer cancel()
	if err := n.sendWebhook(ctx, d, syntheticTestEvent()); err != nil {
		n.stats.incFailed(err.Error())
		n.recordDestTest(d.ID, "FAIL: "+err.Error())
		return err.Error()
	}
	n.stats.incWebhookOK()
	n.recordDestTest(d.ID, "OK")
	return "OK"
}

// recordDestTest stamps a destination's LastTestResult / LastTestAt under
// the config mutex so the dashboard can show what happened most recently.
// Lookup is by ID across all three arrays.
func (n *Notifier) recordDestTest(id, result string) {
	if id == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now().Format(time.RFC3339)
	for i := range n.cfg.Slack {
		if n.cfg.Slack[i].ID == id {
			n.cfg.Slack[i].Stats.LastTestResult = result
			n.cfg.Slack[i].Stats.LastTestAt = now
			return
		}
	}
	for i := range n.cfg.Email {
		if n.cfg.Email[i].ID == id {
			n.cfg.Email[i].Stats.LastTestResult = result
			n.cfg.Email[i].Stats.LastTestAt = now
			return
		}
	}
	for i := range n.cfg.Webhook {
		if n.cfg.Webhook[i].ID == id {
			n.cfg.Webhook[i].Stats.LastTestResult = result
			n.cfg.Webhook[i].Stats.LastTestAt = now
			return
		}
	}
}

// Close stops the worker goroutine. Safe to call multiple times.
func (n *Notifier) Close() {
	select {
	case <-n.stop:
		// already closed
	default:
		close(n.stop)
	}
}

// =============================================================================
// Worker / dispatch
// =============================================================================

func (n *Notifier) worker() {
	for {
		select {
		case <-n.stop:
			return
		case e := <-n.queue:
			cfg := n.GetConfig()
			if n.throttle(e) {
				n.stats.incThrottled()
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout+1*time.Second)
			n.dispatch(ctx, cfg, e)
			cancel()
		}
	}
}

func (n *Notifier) dispatch(ctx context.Context, cfg Config, e Event) {
	delivered := false
	// Slack — fan out to every enabled destination.
	for _, d := range cfg.Slack {
		if !d.Enabled || d.WebhookURL == "" {
			continue
		}
		if err := n.sendSlack(ctx, d, e); err != nil {
			log.Printf("[notifier] slack[%s] send failed: %v", d.Name, err)
			n.stats.incFailed(err.Error())
			n.recordDestSend(d.ID, false, err.Error())
		} else {
			n.stats.incSlackSent()
			n.recordDestSend(d.ID, true, "")
			delivered = true
		}
	}
	// Email
	for _, d := range cfg.Email {
		if !d.Enabled || d.Host == "" || len(d.To) == 0 {
			continue
		}
		if err := n.sendEmail(d, e); err != nil {
			log.Printf("[notifier] email[%s] send failed: %v", d.Name, err)
			n.stats.incFailed(err.Error())
			n.recordDestSend(d.ID, false, err.Error())
		} else {
			n.stats.incEmailSent()
			n.recordDestSend(d.ID, true, "")
			delivered = true
		}
	}
	// Webhook
	for _, d := range cfg.Webhook {
		if !d.Enabled || d.URL == "" {
			continue
		}
		if err := n.sendWebhook(ctx, d, e); err != nil {
			log.Printf("[notifier] webhook[%s] send failed: %v", d.Name, err)
			n.stats.incFailed(err.Error())
			n.recordDestSend(d.ID, false, err.Error())
		} else {
			n.stats.incWebhookOK()
			n.recordDestSend(d.ID, true, "")
			delivered = true
		}
	}
	if delivered {
		n.stats.markSent()
	}
}

// recordDestSend updates per-destination counters under the config mutex.
func (n *Notifier) recordDestSend(id string, ok bool, errMsg string) {
	if id == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now().Format(time.RFC3339)
	update := func(s *DestStats) {
		if ok {
			s.Sent++
			s.LastSentAt = now
			s.LastError = ""
		} else {
			s.Failed++
			s.LastError = errMsg
		}
	}
	for i := range n.cfg.Slack {
		if n.cfg.Slack[i].ID == id {
			update(&n.cfg.Slack[i].Stats)
			return
		}
	}
	for i := range n.cfg.Email {
		if n.cfg.Email[i].ID == id {
			update(&n.cfg.Email[i].Stats)
			return
		}
	}
	for i := range n.cfg.Webhook {
		if n.cfg.Webhook[i].ID == id {
			update(&n.cfg.Webhook[i].Stats)
			return
		}
	}
}

// =============================================================================
// Throttle
// =============================================================================

func (n *Notifier) throttle(e Event) bool {
	n.mu.RLock()
	window := time.Duration(n.cfg.ThrottleSeconds) * time.Second
	n.mu.RUnlock()
	if window <= 0 {
		return false
	}
	key := e.ClientIP + "|" + e.RuleID + "|" + e.Decision
	now := time.Now()

	n.dedupMu.Lock()
	defer n.dedupMu.Unlock()
	last, ok := n.dedup[key]
	if ok && now.Sub(last) < window {
		return true
	}
	n.dedup[key] = now
	return false
}

func (n *Notifier) dedupSweeper() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-n.stop:
			return
		case now := <-t.C:
			n.mu.RLock()
			window := 2 * time.Duration(n.cfg.ThrottleSeconds) * time.Second
			n.mu.RUnlock()
			n.dedupMu.Lock()
			for k, v := range n.dedup {
				if now.Sub(v) > window {
					delete(n.dedup, k)
				}
			}
			n.dedupMu.Unlock()
		}
	}
}

// =============================================================================
// Channel implementations
// =============================================================================

func (n *Notifier) sendSlack(ctx context.Context, c SlackDestination, e Event) error {
	var text string
	if c.MessageTemplate != "" {
		text = renderTemplate(c.MessageTemplate, e)
	} else {
		emoji := "⚠️"
		if strings.EqualFold(e.Severity, "CRITICAL") {
			emoji = "🚨"
		}
		text = fmt.Sprintf("%s *WAF %s* — %s\n• rule: `%s` (score %.1f, %s)\n• ip: `%s`  ua: `%s`\n• req: `%s %s%s`\n• reason: %s",
			emoji, strings.ToUpper(e.Decision), e.Severity,
			safe(e.RuleID), e.Score, e.Severity,
			safe(e.ClientIP), truncate(e.UserAgent, 60),
			safe(e.Method), safe(e.Host), safe(e.Path),
			safe(e.Reason),
		)
	}
	payload := map[string]interface{}{
		"text": text,
	}
	if c.Channel != "" {
		payload["channel"] = c.Channel
	}
	if c.Username != "" {
		payload["username"] = c.Username
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, "POST", c.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Slack returns plain text like "no_service" / "invalid_token" —
		// surface it so dashboard users can self-diagnose.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		txt := strings.TrimSpace(string(body))
		if txt == "" {
			return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("slack returned HTTP %d: %s", resp.StatusCode, txt)
	}
	return nil
}

func (n *Notifier) sendWebhook(ctx context.Context, c WebhookDestination, e Event) error {
	var body []byte
	contentType := "application/json"
	if c.PayloadTemplate != "" {
		body = []byte(renderTemplate(c.PayloadTemplate, e))
		// If the rendered template doesn't parse as JSON, fall back to text/plain
		// so the receiving server doesn't 400 on a malformed Content-Type pairing.
		var probe interface{}
		if json.Unmarshal(body, &probe) != nil {
			contentType = "text/plain; charset=utf-8"
		}
	} else {
		b, err := json.Marshal(e)
		if err != nil {
			return err
		}
		body = b
	}
	method := strings.ToUpper(strings.TrimSpace(c.Method))
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequestWithContext(ctx, method, c.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := n.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		txt := strings.TrimSpace(string(body))
		if txt == "" {
			return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
		}
		return fmt.Errorf("webhook returned HTTP %d: %s", resp.StatusCode, txt)
	}
	return nil
}

func (n *Notifier) sendEmail(c EmailDestination, e Event) error {
	if c.Port == 0 {
		c.Port = 587
	}
	addr := fmt.Sprintf("%s:%d", c.Host, c.Port)
	from := c.From
	if from == "" {
		from = c.Username
	}
	var subject, bodyText string
	if c.SubjectTemplate != "" {
		subject = renderTemplate(c.SubjectTemplate, e)
	} else {
		subject = fmt.Sprintf("[WAF %s] %s %s%s — rule %s", strings.ToUpper(e.Decision),
			safe(e.Method), safe(e.Host), safe(e.Path), safe(e.RuleID))
	}
	if c.BodyTemplate != "" {
		bodyText = renderTemplate(c.BodyTemplate, e)
	} else {
		bodyText = fmt.Sprintf(
			"WAF Alert\n\n"+
				"Time: %s\nDecision: %s\nSeverity: %s\nReason: %s\nScore: %.2f\n\n"+
				"Rule:   %s\nIP:     %s\nMethod: %s\nHost:   %s\nPath:   %s\nUA:     %s\nReq-ID: %s\n",
			e.Timestamp.Format(time.RFC3339),
			e.Decision, e.Severity, e.Reason, e.Score,
			safe(e.RuleID), safe(e.ClientIP), safe(e.Method), safe(e.Host), safe(e.Path),
			safe(e.UserAgent), safe(e.RequestID),
		)
	}
	headers := []string{
		"From: " + from,
		"To: " + strings.Join(c.To, ", "),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
	}
	msg := []byte(strings.Join(headers, "\r\n") + "\r\n\r\n" + bodyText)

	var auth smtp.Auth
	if c.Username != "" && c.Password != "" {
		auth = smtp.PlainAuth("", c.Username, c.Password, c.Host)
	}

	if c.UseTLS {
		// Implicit TLS (typically port 465)
		dialer := &net.Dialer{Timeout: 10 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: c.Host})
		if err != nil {
			return err
		}
		client, err := smtp.NewClient(conn, c.Host)
		if err != nil {
			return err
		}
		defer client.Close()
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}
		if err := client.Mail(from); err != nil {
			return err
		}
		for _, t := range c.To {
			if err := client.Rcpt(t); err != nil {
				return err
			}
		}
		wc, err := client.Data()
		if err != nil {
			return err
		}
		if _, err := wc.Write(msg); err != nil {
			return err
		}
		if err := wc.Close(); err != nil {
			return err
		}
		return client.Quit()
	}

	// STARTTLS / plain
	return smtp.SendMail(addr, auth, from, c.To, msg)
}

// =============================================================================
// Helpers + stats
// =============================================================================

func safe(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// RedactConfig returns a copy of Config safe to send to the dashboard
// (every email destination's password is replaced with a fixed placeholder
// when non-empty so the UI can show "already set" without leaking the secret).
func RedactConfig(c Config) Config {
	out := c
	// Slice header copy isn't enough — we need new backing arrays so caller
	// mutations don't leak back to the live config. Each destination is a
	// value type, so the copy is shallow-safe (maps inside webhook headers
	// are shared, but we don't mutate them).
	if len(c.Email) > 0 {
		out.Email = make([]EmailDestination, len(c.Email))
		copy(out.Email, c.Email)
		for i := range out.Email {
			if out.Email[i].Password != "" {
				out.Email[i].Password = "********"
			}
		}
	}
	return out
}

// atomicStats: race-safe counters without taking the main mutex.
type atomicStats struct {
	queued     atomic.Uint64
	sent       atomic.Uint64
	failed     atomic.Uint64
	throttled  atomic.Uint64
	belowSev   atomic.Uint64
	slackSent  atomic.Uint64
	emailSent  atomic.Uint64
	webhookOK  atomic.Uint64
	lastErr    atomic.Value // string
	lastSentAt atomic.Value // string
}

func (s *atomicStats) incQueued()      { s.queued.Add(1) }
func (s *atomicStats) incFailed(msg string) {
	s.failed.Add(1)
	s.lastErr.Store(msg)
}
func (s *atomicStats) incThrottled()   { s.throttled.Add(1) }
func (s *atomicStats) incBelowSev()    { s.belowSev.Add(1) }
func (s *atomicStats) incSlackSent()   { s.slackSent.Add(1) }
func (s *atomicStats) incEmailSent()   { s.emailSent.Add(1) }
func (s *atomicStats) incWebhookOK()   { s.webhookOK.Add(1) }
func (s *atomicStats) markSent() {
	s.sent.Add(1)
	s.lastSentAt.Store(time.Now().Format(time.RFC3339))
}

func (s *atomicStats) snapshot() Stats {
	st := Stats{
		Queued:    s.queued.Load(),
		Sent:      s.sent.Load(),
		Failed:    s.failed.Load(),
		Throttled: s.throttled.Load(),
		BelowSev:  s.belowSev.Load(),
		SlackSent: s.slackSent.Load(),
		EmailSent: s.emailSent.Load(),
		WebhookOK: s.webhookOK.Load(),
	}
	if v := s.lastErr.Load(); v != nil {
		st.LastError = v.(string)
	}
	if v := s.lastSentAt.Load(); v != nil {
		st.LastSentAt = v.(string)
	}
	return st
}
