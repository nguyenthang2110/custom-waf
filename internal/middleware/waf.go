// internal/middleware/waf.go
package middleware

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"waf-project/internal/api"
	"waf-project/internal/audit"
	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/ml"
	"waf-project/internal/normalizer"
	"waf-project/internal/notifier"
	"waf-project/internal/parser"
	"waf-project/internal/ratelimit"
	"waf-project/internal/training"
)

// WAFConfig holds configuration for WAF middleware
type WAFConfig struct {
	Parser           *parser.HTTPParser
	Normalizer       *normalizer.Normalizer
	RuleEngine       *engine.RuleEngine
	RateLimiter      *ratelimit.RateLimiter
	BehaviorDetector *behavior.Detector
	DecisionEngine   *decision.DecisionEngine
	// AccessLogger records every HTTP request + WAF verdict (the access log).
	AccessLogger *audit.Logger
	// AuditLogger records admin / security events only (the audit log):
	// rate-limit trips, proxy errors, etc. fire here, NOT per-request rows.
	AuditLogger      *audit.Logger
	TrainingLogger   *training.Logger // optional — nil disables training capture
	Notifier         *notifier.Notifier // optional — nil disables alert fanout
	Metrics          *metrics.Collector
	Upstream         string

	// ML inference bridge. nil or disabled client → ML step is skipped.
	MLClient            *ml.Client
	MLGrayLower         float64 // rule score lower bound to consult ML (inclusive)
	MLGrayUpper         float64 // rule score upper bound to consult ML (exclusive)
	MLAttackBump        float64 // score added on confident attack verdict
	MLNormalPenalty     float64 // score subtracted on confident normal verdict
	MLConfidenceMinimum float64 // verdict ignored below this confidence
	MLMaxTextLen        int     // text builder truncation budget

	// Optional settings
	EnableDebugHeaders bool
	DryRun             bool // Log only, don't block
	CustomBlockPage    string
}

// WAFMiddleware is the main WAF HTTP middleware
type WAFMiddleware struct {
	config     *WAFConfig
	proxy      *httputil.ReverseProxy
	backendURL string
	mu         sync.RWMutex // Protects proxy and backendURL
}

// responseWriter wraps http.ResponseWriter to capture response details
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(data)
	rw.bytesWritten += n
	return n, err
}

// NewWAF creates a new WAF middleware
func NewWAF(config *WAFConfig) *WAFMiddleware {
	// Parse upstream URL
	upstreamURL, err := url.Parse(config.Upstream)
	if err != nil {
		panic(fmt.Sprintf("Invalid upstream URL: %v", err))
	}

	// Back-compat / safety: callers (and tests) that only wire AuditLogger
	// still get request logging — the access path falls back to it.
	if config.AccessLogger == nil {
		config.AccessLogger = config.AuditLogger
	}

	waf := &WAFMiddleware{
		config:     config,
		proxy:      httputil.NewSingleHostReverseProxy(upstreamURL),
		backendURL: config.Upstream,
	}

	// Customize proxy error handler
	waf.proxy.ErrorHandler = waf.proxyErrorHandler

	return waf
}

// ServeHTTP implements http.Handler interface
func (w *WAFMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	// Add security headers
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("X-XSS-Protection", "1; mode=block")

	// Add HSTS header if TLS is being used
	if r.TLS != nil {
		// HSTS: Force HTTPS for 1 year, include subdomains
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// Wrap response writer to capture details
	wrappedRW := &responseWriter{
		ResponseWriter: rw,
		statusCode:     200, // Default
	}

	// ========================================================================
	// STEP 1: Parse Request
	// ========================================================================
	parseStart := time.Now()
	parsed, err := w.config.Parser.Parse(r)
	if err != nil {
		w.handleError(wrappedRW, r, "Failed to parse request", http.StatusBadRequest)
		return
	}
	w.config.Metrics.RecordLatency("parser", time.Since(parseStart))

	// ========================================================================
	// STEP 2: Normalize Request
	// ========================================================================
	// Must run before ShouldBypassWAF — the bypass check inspects
	// NormalizedPath, which the parser leaves blank.
	normStart := time.Now()
	if err := w.config.Normalizer.Normalize(parsed); err != nil {
		w.handleError(wrappedRW, r, "Failed to normalize request", http.StatusBadRequest)
		return
	}
	w.config.Metrics.RecordLatency("normalizer", time.Since(normStart))

	// Bypass = silent skip. Health checks, websocket transports, and
	// user-configured bypass prefixes all flow straight through the proxy
	// without rule evaluation, rate limiting, OR audit logging — they're
	// pure noise the operator explicitly opted out of seeing.
	if w.config.DecisionEngine.ShouldBypassWAF(parsed) {
		w.config.Metrics.RecordRequest("BYPASS", 0)
		w.mu.RLock()
		proxy := w.proxy
		w.mu.RUnlock()
		proxy.ServeHTTP(wrappedRW, r)
		return
	}

	// Whitelist = trusted IP. Auto-allow (skip rate limit + rule eval) but
	// still log so operators can see which IPs are riding the allow-list.
	if w.config.DecisionEngine.IsWhitelistedIP(parsed.ClientIP) {
		w.config.Metrics.RecordRequest("ALLOW", 0)
		whitelistStart := time.Now()
		w.mu.RLock()
		proxy := w.proxy
		w.mu.RUnlock()
		proxy.ServeHTTP(wrappedRW, r)
		w.logWhitelistEntry(parsed, wrappedRW, time.Since(whitelistStart))
		return
	}

	// ========================================================================
	// STEP 3: Rate Limiting Check
	// ========================================================================
	// Rate limiting is opt-in per path: only routes configured in
	// rate_limit.endpoint_limits engage the token bucket. An empty map =
	// no rate limiting anywhere. The static-asset shortcut below stays as
	// a perf optimization — it skips the endpoint-match map lookup for
	// the high-volume CSS/JS/image traffic that operators almost never
	// want to throttle anyway.
	isStaticAsset := strings.HasPrefix(parsed.NormalizedPath, "/assets/") ||
		strings.HasPrefix(parsed.NormalizedPath, "/public/") ||
		strings.HasSuffix(parsed.NormalizedPath, ".jpg") ||
		strings.HasSuffix(parsed.NormalizedPath, ".jpeg") ||
		strings.HasSuffix(parsed.NormalizedPath, ".png") ||
		strings.HasSuffix(parsed.NormalizedPath, ".gif") ||
		strings.HasSuffix(parsed.NormalizedPath, ".webp") ||
		strings.HasSuffix(parsed.NormalizedPath, ".svg") ||
		strings.HasSuffix(parsed.NormalizedPath, ".css") ||
		strings.HasSuffix(parsed.NormalizedPath, ".js") ||
		strings.HasSuffix(parsed.NormalizedPath, ".woff") ||
		strings.HasSuffix(parsed.NormalizedPath, ".woff2") ||
		strings.HasSuffix(parsed.NormalizedPath, ".ttf") ||
		strings.HasSuffix(parsed.NormalizedPath, ".ico")

	if !isStaticAsset && w.config.RateLimiter.IsRateLimitedWithRoute(parsed.ClientIP, parsed.NormalizedPath) {
		w.config.Metrics.RecordRateLimitHit(parsed.ClientIP)

		// Create audit entry for rate limit
		entry := &audit.AuditEntry{
			Timestamp:      parsed.Timestamp,
			RequestID:      parsed.RequestID,
			ClientIP:       parsed.ClientIP,
			Method:         parsed.Method,
			Path:           parsed.NormalizedPath,
			UserAgent:      parsed.UserAgent,
			Protocol:       parsed.Protocol,
			Host:           parsed.Host,
			Decision:       "BLOCK",
			BlockReason:    "Rate limit exceeded",
			ResponseStatus: 429,
			RateLimited:    true,
			Metadata: map[string]interface{}{
				"reason": "rate_limit_exceeded",
			},
		}

		// Log rate limit event
		w.config.AuditLogger.LogSecurityEvent(
			"RATE_LIMIT",
			"MEDIUM",
			parsed.ClientIP,
			fmt.Sprintf("Rate limit exceeded for path: %s", parsed.NormalizedPath),
			map[string]interface{}{
				"path":       parsed.NormalizedPath,
				"user_agent": parsed.UserAgent,
			},
		)

		// Add to access-log buffer for dashboard (this rate-limited
		// request is itself an access-log row; the RATE_LIMIT security
		// event above is the corresponding audit-log row).
		api.AddToAccessBuffer(entry)

		w.blockRequest(wrappedRW, parsed, "RATE_LIMIT", startTime, 429)
		return
	}

	// ========================================================================
	// STEP 4: Rule Engine Evaluation
	// ========================================================================
	ruleStart := time.Now()
	evalResult := w.config.RuleEngine.Evaluate(parsed)
	ruleLatency := time.Since(ruleStart)
	w.config.Metrics.RecordLatency("rule_engine", ruleLatency)

	// Record rule matches
	for _, match := range evalResult.MatchedRules {
		w.config.Metrics.RecordRuleMatch(
			match.RuleID,
			match.Category,
			match.Severity,
			ruleLatency,
		)
	}

	// ========================================================================
	// STEP 4b: ML Inference (gray-zone only)
	// ========================================================================
	// Consult the model only when the rule score is ambiguous. Verdicts
	// below the confidence floor — and any transport / breaker error — leave
	// the score untouched, falling back to the rule-only path.
	mlVerdict := w.runMLInference(r.Context(), parsed, evalResult)

	// ========================================================================
	// STEP 5: Behavior Analysis
	// ========================================================================
	// Skip behavior analysis for static assets — they're noise for the
	// per-IP counters (bruteforce, velocity, attack patterns). The rule
	// engine still inspects them; we just don't let CSS/JS/font loads
	// move the suspicion score.
	var behaviorResult *behavior.BehaviorResult
	if isStaticAsset {
		behaviorResult = &behavior.BehaviorResult{
			ClientIP:        parsed.ClientIP,
			Timestamp:       time.Now(),
			ThreatDetected:  false,
			ThreatTypes:     []string{},
			SuspicionScore:  0.0,
			RecommendAction: "ALLOW",
		}
	} else {
		behaviorResult = w.config.BehaviorDetector.Analyze(parsed, evalResult)
	}

	// Record behavior threats
	for _, threat := range behaviorResult.ThreatTypes {
		w.config.Metrics.RecordBehaviorThreat(threat)
	}

	// ========================================================================
	// STEP 6: Make Final Decision
	// ========================================================================
	decisionResult := w.config.DecisionEngine.DecideWithDetails(
		evalResult,
		parsed,
		behaviorResult,
	)

	// Update average anomaly score
	w.config.Metrics.UpdateAverageAnomalyScore(decisionResult.FinalScore)

	// Total latency
	totalLatency := time.Since(startTime)
	w.config.Metrics.RecordLatency("total", totalLatency)

	// Determine response status based on decision
	var responseStatus int
	switch decisionResult.Decision {
	case "BLOCK":
		responseStatus = decisionResult.ResponseCode
		if responseStatus == 0 {
			responseStatus = 403 // Default for BLOCK
		}
	default:
		responseStatus = wrappedRW.statusCode
		if responseStatus == 0 {
			responseStatus = 200 // Default for ALLOW
		}
	}

	// ========================================================================
	// STEP 7: Log Audit Entry
	// ========================================================================
	w.logAccessEntry(parsed, evalResult, decisionResult, behaviorResult,
		responseStatus, totalLatency, mlVerdict)

	// ========================================================================
	// STEP 7b: Outbound Alert (Slack/email/webhook)
	// Fire-and-forget — never blocks the hot path. Fired for BLOCK only;
	// the notifier itself filters by severity + throttles dupes.
	// ========================================================================
	if w.config.Notifier != nil && !w.config.DryRun {
		if decisionResult.Decision == "BLOCK" {
			w.dispatchAlert(parsed, evalResult, decisionResult, r)
		}
	}

	// ========================================================================
	// STEP 8: Execute Decision
	// ========================================================================

	// Dry run mode - log only, don't block
	if w.config.DryRun {
		w.addDebugHeaders(wrappedRW, decisionResult, evalResult)
		w.mu.RLock()
		proxy := w.proxy
		w.mu.RUnlock()
		proxy.ServeHTTP(wrappedRW, r)
		w.config.Metrics.RecordRequestWithDetails(
			parsed.ClientIP,
			parsed.Method,
			parsed.NormalizedPath,
			"DRYRUN_"+decisionResult.Decision,
			decisionResult.FinalScore,
			totalLatency,
			parsed.BodySize,
			wrappedRW.bytesWritten,
		)
		return
	}

	// Execute based on decision
	switch decisionResult.Decision {
	case "BLOCK":
		w.blockRequest(wrappedRW, parsed, decisionResult.Reason, startTime,
			decisionResult.ResponseCode)

	case "ALLOW", "MONITOR":
		// Add debug headers if enabled
		if w.config.EnableDebugHeaders {
			w.addDebugHeaders(wrappedRW, decisionResult, evalResult)
		}

		// Forward to upstream
		w.mu.RLock()
		proxy := w.proxy
		w.mu.RUnlock()
		proxy.ServeHTTP(wrappedRW, r)

		// Record successful request
		w.config.Metrics.RecordRequestWithDetails(
			parsed.ClientIP,
			parsed.Method,
			parsed.NormalizedPath,
			decisionResult.Decision,
			decisionResult.FinalScore,
			totalLatency,
			parsed.BodySize,
			wrappedRW.bytesWritten,
		)

	default:
		// Unknown decision - default to block
		w.blockRequest(wrappedRW, parsed, "Unknown decision", startTime, 403)
	}
}

// ============================================================================
// Action Handlers
// ============================================================================

// blockRequest blocks a request and returns error page
func (w *WAFMiddleware) blockRequest(
	rw *responseWriter,
	parsed *engine.ParsedRequest,
	reason string,
	startTime time.Time,
	statusCode int,
) {
	// Set headers
	rw.Header().Set("X-WAF-Status", "BLOCKED")
	rw.Header().Set("X-WAF-Request-ID", parsed.RequestID)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Write status code
	rw.WriteHeader(statusCode)

	// Write block page
	blockPage := w.getBlockPage(parsed.RequestID, reason)
	io.WriteString(rw, blockPage)

	// Record metrics
	w.config.Metrics.RecordRequestWithDetails(
		parsed.ClientIP,
		parsed.Method,
		parsed.NormalizedPath,
		"BLOCK",
		0, // Score already recorded
		time.Since(startTime),
		parsed.BodySize,
		len(blockPage),
	)
}

// dispatchAlert builds a notifier.Event from a finalized decision and
// queues it for async fanout. The notifier handles its own severity gating
// and throttling — we just provide the data.
func (w *WAFMiddleware) dispatchAlert(
	parsed *engine.ParsedRequest,
	evalResult *engine.EvaluationResult,
	decisionResult *decision.DecisionResult,
	r *http.Request,
) {
	// Severity / rule id come from the highest-scoring rule match when present;
	// fall back to MEDIUM when no rule matched (e.g. score-only block).
	severity := "MEDIUM"
	ruleID := ""
	if len(evalResult.MatchedRules) > 0 {
		top := evalResult.MatchedRules[0]
		for _, m := range evalResult.MatchedRules[1:] {
			if m.Score > top.Score {
				top = m
			}
		}
		ruleID = top.RuleID
		if top.Severity != "" {
			severity = strings.ToUpper(top.Severity)
		}
	}
	host := r.Host
	if host == "" {
		host = parsed.Host
	}
	w.config.Notifier.Send(notifier.Event{
		Timestamp: time.Now(),
		Decision:  decisionResult.Decision,
		Severity:  severity,
		ClientIP:  parsed.ClientIP,
		Method:    parsed.Method,
		Host:      host,
		Path:      parsed.NormalizedPath,
		Reason:    decisionResult.Reason,
		RuleID:    ruleID,
		Score:     decisionResult.FinalScore,
		UserAgent: parsed.UserAgent,
		RequestID: parsed.RequestID,
	})
}

// handleError handles errors during request processing
func (w *WAFMiddleware) handleError(
	rw *responseWriter,
	r *http.Request,
	message string,
	statusCode int,
) {
	rw.Header().Set("X-WAF-Error", message)
	rw.WriteHeader(statusCode)
	io.WriteString(rw, message)

	// Log system event
	w.config.AuditLogger.LogSystemEvent("ERROR",
		fmt.Sprintf("%s: %s", r.URL.Path, message))
}

// proxyErrorHandler handles errors when forwarding to upstream
func (w *WAFMiddleware) proxyErrorHandler(rw http.ResponseWriter, r *http.Request, err error) {
	rw.Header().Set("X-WAF-Proxy-Error", err.Error())
	rw.WriteHeader(http.StatusBadGateway)
	fmt.Fprintf(rw, "Bad Gateway: %v", err)

	// Log system event
	w.config.AuditLogger.LogSystemEvent("PROXY_ERROR",
		fmt.Sprintf("Failed to proxy request to upstream: %v", err))
}

// ============================================================================
// Response Pages
// ============================================================================

// getBlockPage returns the Cloudflare-style block page. Clean neutral
// design — no scary animations. Shows request ID + IP + timestamp so the
// user can quote them if they file a false-positive ticket.
func (w *WAFMiddleware) getBlockPage(requestID, reason string) string {
	if w.config.CustomBlockPage != "" {
		return w.config.CustomBlockPage
	}
	host, _ := os.Hostname()
	ts := time.Now().UTC().Format("2006-01-02 15:04:05 UTC")
	return fmt.Sprintf(blockPageTpl, htmlEscape(requestID), htmlEscape(reason), htmlEscape(ts), htmlEscape(host))
}

const blockPageTpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Access denied · WAF</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f6f7f9; --card:#fff; --line:#e6e8eb;
  --fg:#1f2937; --fg-2:#4b5563; --fg-3:#6b7280; --fg-4:#9ca3af;
  --accent:#dc2626; --accent-soft:#fee2e2;
  --code-bg:#f3f4f6;
}
@media (prefers-color-scheme: dark){
  :root{ --bg:#0f1115;--card:#161b22;--line:#262c36;--fg:#e6edf3;--fg-2:#9ba6b6;--fg-3:#6e7681;--fg-4:#484f58;--accent:#f87171;--accent-soft:rgba(248,113,113,0.12);--code-bg:#1c2128 }
}
html,body{height:100%%}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;background:var(--bg);color:var(--fg);line-height:1.55}
.wrap{max-width:760px;margin:0 auto;min-height:100vh;display:flex;flex-direction:column;padding:24px}
.top{display:flex;align-items:center;gap:10px;padding:12px 0;color:var(--fg-3);font-size:13px}
.top .dot{width:8px;height:8px;border-radius:50%%;background:var(--accent)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:32px 36px;margin:24px 0}
.h1{font-size:22px;font-weight:600;letter-spacing:-.01em;margin-bottom:8px}
.h2{font-size:14px;font-weight:600;color:var(--fg-2);margin:18px 0 6px;text-transform:uppercase;letter-spacing:.04em}
.lead{color:var(--fg-2);font-size:15px;margin-bottom:8px}
.code-block{background:var(--code-bg);border:1px solid var(--line);border-radius:8px;padding:10px 14px;font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;color:var(--fg-2);word-break:break-all}
.kv{display:grid;grid-template-columns:140px 1fr;gap:10px 16px;font-size:13px;color:var(--fg-2);align-items:center}
.kv b{color:var(--fg-3);font-weight:500;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
.kv .v{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--fg);font-size:12.5px}
.section + .section{margin-top:18px;padding-top:18px;border-top:1px dashed var(--line)}
.foot{margin-top:auto;padding-top:20px;color:var(--fg-4);font-size:12px;text-align:center;line-height:1.7}
.foot strong{color:var(--fg-3);font-weight:600}
.error-badge{display:inline-flex;align-items:center;gap:8px;padding:4px 10px;background:var(--accent-soft);color:var(--accent);border-radius:999px;font-size:12px;font-weight:600;letter-spacing:.02em;margin-bottom:14px}
.shield{width:18px;height:18px}
ul{margin-left:18px;color:var(--fg-2);font-size:14px}
ul li{margin:4px 0}
</style>
</head>
<body>
<div class="wrap">
  <div class="top"><span class="dot"></span><span>Web Application Firewall</span></div>

  <div class="card">
    <span class="error-badge">
      <svg class="shield" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      Error 1020 — Access denied
    </span>
    <h1 class="h1">Sorry, you have been blocked</h1>
    <p class="lead">You are unable to access this site. The Web Application Firewall identified your request as potentially malicious and stopped it before it reached the application.</p>

    <h2 class="h2">Why was I blocked?</h2>
    <p class="lead">This protection is automatic. Common triggers include scanner tools, SQL/script-like payloads in URLs or form fields, unusual request patterns, or known-bad IP/User-Agent.</p>

    <h2 class="h2">What can I do?</h2>
    <ul>
      <li>Refresh and try again from a normal browser session.</li>
      <li>If you own this site, check the WAF logs for the request ID below.</li>
      <li>If you are a legitimate user, contact the site owner and include the details below.</li>
    </ul>
  </div>

  <div class="card">
    <h2 class="h2" style="margin-top:0">Incident details</h2>
    <div class="kv">
      <b>Ray ID</b><span class="v">%s</span>
      <b>Reason</b><span class="v">%s</span>
      <b>Timestamp</b><span class="v">%s</span>
      <b>Host</b><span class="v">%s</span>
    </div>
  </div>

  <div class="foot">
    <strong>Powered by NHT WAF</strong>
    Performance &amp; security by an in-house Web Application Firewall.
  </div>
</div>
</body>
</html>`

// htmlEscape escapes the small set of characters that matter when
// interpolating untrusted request fields into the block page HTML.
func htmlEscape(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;",
	).Replace(s)
}

// ============================================================================
// Helper Functions
// ============================================================================

// addDebugHeaders adds debug information to response headers
func (w *WAFMiddleware) addDebugHeaders(
	rw *responseWriter,
	decisionResult *decision.DecisionResult,
	evalResult *engine.EvaluationResult,
) {
	rw.Header().Set("X-WAF-Decision", decisionResult.Decision)
	rw.Header().Set("X-WAF-Score", fmt.Sprintf("%.2f", decisionResult.FinalScore))
	rw.Header().Set("X-WAF-Rule-Score", fmt.Sprintf("%.2f", decisionResult.RuleScore))
	rw.Header().Set("X-WAF-Behavior-Score", fmt.Sprintf("%.2f", decisionResult.BehaviorScore))
	rw.Header().Set("X-WAF-Matched-Rules", fmt.Sprintf("%d", len(evalResult.MatchedRules)))

	if len(evalResult.MatchedRules) > 0 {
		ruleIDs := make([]string, 0, len(evalResult.MatchedRules))
		for _, match := range evalResult.MatchedRules {
			ruleIDs = append(ruleIDs, match.RuleID)
		}
		rw.Header().Set("X-WAF-Rules", strings.Join(ruleIDs, ","))
	}
}

// ============================================================================
// Health Check
// ============================================================================

// HealthCheck returns WAF health status
func (w *WAFMiddleware) HealthCheck() map[string]interface{} {
	return map[string]interface{}{
		"status":      "healthy",
		"rules_count": w.config.RuleEngine.RuleCount(),
		"upstream":    w.config.Upstream,
	}
}

// NewWAFWithLogBuffer creates WAF middleware with log buffer integration
func NewWAFWithLogBuffer(config *WAFConfig) *WAFMiddleware {
	upstreamURL, err := url.Parse(config.Upstream)
	if err != nil {
		panic(fmt.Sprintf("Invalid upstream URL: %v", err))
	}

	// Access path falls back to the audit logger when not separately wired.
	if config.AccessLogger == nil {
		config.AccessLogger = config.AuditLogger
	}

	waf := &WAFMiddleware{
		config:     config,
		proxy:      httputil.NewSingleHostReverseProxy(upstreamURL),
		backendURL: config.Upstream,
	}

	waf.proxy.ErrorHandler = waf.proxyErrorHandler

	return waf
}

// GetBackend returns the current backend URL
func (w *WAFMiddleware) GetBackend() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.backendURL
}

// UpdateBackend updates the backend URL and recreates the reverse proxy
func (w *WAFMiddleware) UpdateBackend(newURL string) error {
	// Validate URL
	upstreamURL, err := url.Parse(newURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}

	// Check if scheme is valid
	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme: must be http or https")
	}

	// Create new reverse proxy
	newProxy := httputil.NewSingleHostReverseProxy(upstreamURL)
	newProxy.ErrorHandler = w.proxyErrorHandler

	// Update atomically
	w.mu.Lock()
	w.proxy = newProxy
	w.backendURL = newURL
	w.config.Upstream = newURL // Update config too
	w.mu.Unlock()

	return nil
}

// GetMLSettings returns the live ML scoring knobs. The enabled flag is read
// from the ML client (atomic); the float knobs are guarded by w.mu since the
// hot-path inference snapshot and dashboard edits race. The gray-zone band
// itself is not live-editable — it stays fixed at the config.yaml value.
func (w *WAFMiddleware) GetMLSettings() (enabled bool, attackBump, normalPenalty, confidence float64) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	enabled = w.config.MLClient != nil && w.config.MLClient.Enabled()
	return enabled,
		w.config.MLAttackBump, w.config.MLNormalPenalty,
		w.config.MLConfidenceMinimum
}

// SetMLSettings applies new ML scoring knobs live. enabled toggles the ML
// client (no-op if no client is wired). Validation is the caller's job.
func (w *WAFMiddleware) SetMLSettings(enabled bool, attackBump, normalPenalty, confidence float64) {
	w.mu.Lock()
	w.config.MLAttackBump = attackBump
	w.config.MLNormalPenalty = normalPenalty
	w.config.MLConfidenceMinimum = confidence
	client := w.config.MLClient
	w.mu.Unlock()
	if client != nil {
		client.SetEnabled(enabled)
	}
}

// logAccessEntry records the per-request access-log row (request metadata +
// WAF verdict) and stores it for the API dashboard.
func (w *WAFMiddleware) logAccessEntry(
	parsed *engine.ParsedRequest,
	evalResult *engine.EvaluationResult,
	decisionResult *decision.DecisionResult,
	behaviorResult *behavior.BehaviorResult,
	responseStatus int,
	latency time.Duration,
	mlVerdict mlVerdictRecord,
) {
	// Build rule matches
	matches := make([]audit.RuleMatch, 0, len(evalResult.MatchedRules))
	categories := make([]string, 0)
	categoryMap := make(map[string]bool)

	for _, match := range evalResult.MatchedRules {
		matches = append(matches, audit.RuleMatch{
			RuleID:    match.RuleID,
			Category:  match.Category,
			Severity:  match.Severity,
			Score:     match.Score,
			MatchedOn: match.MatchedOn,
			Pattern:   match.Pattern,
			Payload:   match.Value,
		})

		if !categoryMap[match.Category] {
			categories = append(categories, match.Category)
			categoryMap[match.Category] = true
		}
	}

	// Create audit entry
	entry := &audit.AuditEntry{
		Timestamp:       parsed.Timestamp,
		RequestID:       parsed.RequestID,
		ClientIP:        parsed.ClientIP,
		Method:          parsed.Method,
		Path:            parsed.NormalizedPath,
		Query:           parsed.NormalizedQuery,
		UserAgent:       parsed.UserAgent,
		Protocol:        parsed.Protocol,
		Host:            parsed.Host,
		ContentType:     parsed.ContentType,
		BodySize:        parsed.BodySize,
		Decision:        decisionResult.Decision,
		TotalScore:      decisionResult.FinalScore,
		RuleScore:       decisionResult.RuleScore,
		BehaviorScore:   decisionResult.BehaviorScore,
		MatchedRules:    matches,
		RuleCount:       len(matches),
		Categories:      categories,
		BehaviorThreats: behaviorResult.ThreatTypes,
		ResponseStatus:  responseStatus,
		Latency:         latency,
		LatencyMs:       float64(latency.Microseconds()) / 1000.0,
		RateLimited:     false,
		BlockDuration:   decisionResult.BlockDuration,
		BlockReason:     decisionResult.Reason,
		Metadata:        decisionResult.Metadata,
		Headers:         captureHeadersForAudit(parsed.RawHeaders),
	}

	// Surface ML verdict on the audit entry so the dashboard / training
	// pipeline can see what the model said, separately from the final score.
	if mlVerdict.called {
		if entry.Metadata == nil {
			entry.Metadata = make(map[string]interface{}, 4)
		}
		entry.Metadata["ml_label"] = mlVerdict.label
		entry.Metadata["ml_confidence"] = mlVerdict.confidence
		entry.Metadata["ml_is_attack"] = mlVerdict.isAttack
		entry.Metadata["ml_score_adjust"] = mlVerdict.adjustment
		if mlVerdict.errText != "" {
			entry.Metadata["ml_error"] = mlVerdict.errText
		}
	}

	// Log to the access-log file
	w.config.AccessLogger.Log(entry)

	// Add to access-log buffer for dashboard
	api.AddToAccessBuffer(entry)

	// Mirror to the training file. Skip noisy paths (static assets, infra,
	// websocket polling, plus user-supplied prefixes) so the dataset stays
	// focused on the protected app.
	if w.config.TrainingLogger != nil &&
		w.config.TrainingLogger.Enabled() &&
		!w.config.TrainingLogger.ShouldSkip(parsed.NormalizedPath) {
		w.config.TrainingLogger.Log(parsed, evalResult, decisionResult.Decision, responseStatus, latency)
	}
}

// (training package import is used above)
var _ = training.MaxTextLenDefault

// logWhitelistEntry records an audit row for an IP that auto-allowed via
// the whitelist. Without this entry operators see nothing in the dashboard
// for whitelisted traffic, which makes it hard to tell "WAF correctly
// allowed" apart from "request never arrived".
func (w *WAFMiddleware) logWhitelistEntry(
	parsed *engine.ParsedRequest,
	rw *responseWriter,
	latency time.Duration,
) {
	entry := &audit.AuditEntry{
		Timestamp:      parsed.Timestamp,
		RequestID:      parsed.RequestID,
		ClientIP:       parsed.ClientIP,
		Method:         parsed.Method,
		Path:           parsed.NormalizedPath,
		Query:          parsed.NormalizedQuery,
		UserAgent:      parsed.UserAgent,
		Protocol:       parsed.Protocol,
		Host:           parsed.Host,
		ContentType:    parsed.ContentType,
		BodySize:       parsed.BodySize,
		Decision:       "ALLOW",
		ResponseStatus: rw.statusCode,
		Latency:        latency,
		LatencyMs:      float64(latency.Microseconds()) / 1000.0,
		Headers:        captureHeadersForAudit(parsed.RawHeaders),
		Metadata: map[string]interface{}{
			"whitelisted": true,
		},
	}
	w.config.AccessLogger.Log(entry)
	api.AddToAccessBuffer(entry)
}

// captureHeadersForAudit copies the request headers verbatim. No redaction
// applied — operators want to see exactly what the client sent. Note that
// this means audit log files on disk will contain raw Cookie / Authorization
// values; secure the log path accordingly.
func captureHeadersForAudit(raw map[string][]string) map[string][]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string][]string, len(raw))
	for k, vs := range raw {
		cp := make([]string, len(vs))
		copy(cp, vs)
		out[k] = cp
	}
	return out
}

// mlVerdictRecord captures the outcome of one /predict call so it can be
// surfaced on the audit entry without leaking through the wider control flow.
type mlVerdictRecord struct {
	called     bool    // true if we actually invoked the client
	label      string  // predicted class (normal / sqli / xss / cmdi / path_traversal)
	confidence float64 // softmax probability of the predicted class
	isAttack   bool    // model's binary view (label != "normal")
	adjustment float64 // signed score delta we applied to evalResult.TotalScore
	errText    string  // populated when the call failed or breaker was open
}

// runMLInference consults the ML service when the rule score lands in the
// configured gray zone. It mutates evalResult.TotalScore in place so the
// downstream behavior + decision steps see the adjusted value. Errors are
// swallowed — the rule-only score remains in effect, which means a flapping
// model service degrades gracefully instead of taking the WAF down.
func (w *WAFMiddleware) runMLInference(
	ctx context.Context,
	parsed *engine.ParsedRequest,
	evalResult *engine.EvaluationResult,
) mlVerdictRecord {
	client := w.config.MLClient
	if client == nil || !client.Enabled() {
		return mlVerdictRecord{}
	}

	// Snapshot the live-editable knobs under the lock so a concurrent
	// dashboard edit (SetMLSettings) can't tear a read mid-request.
	w.mu.RLock()
	lower, upper := w.config.MLGrayLower, w.config.MLGrayUpper
	attackBump, normalPenalty := w.config.MLAttackBump, w.config.MLNormalPenalty
	minConfidence := w.config.MLConfidenceMinimum
	maxTextLen := w.config.MLMaxTextLen
	w.mu.RUnlock()

	score := evalResult.TotalScore
	if upper <= lower {
		// Misconfigured band — disable rather than guess.
		return mlVerdictRecord{}
	}
	if score < lower || score >= upper {
		return mlVerdictRecord{}
	}

	// Canonical full-request format — matches model_v5+ training input.
	// Redact() masks secrets the model never saw (same path as the training
	// logger), keeping the byte distribution at inference identical to train.
	text := training.Redact(training.BuildCanonicalText(parsed, evalResult, maxTextLen))
	if text == "" {
		return mlVerdictRecord{}
	}

	resp, err := client.Predict(ctx, text)
	if err != nil {
		// ErrDisabled and ErrCircuitOpen are not real failures — just signals
		// to fall back to the rule-only path.
		if errors.Is(err, ml.ErrDisabled) || errors.Is(err, ml.ErrCircuitOpen) {
			return mlVerdictRecord{called: true, errText: err.Error()}
		}
		return mlVerdictRecord{called: true, errText: err.Error()}
	}

	verdict := mlVerdictRecord{
		called:     true,
		label:      resp.Label,
		confidence: resp.Confidence,
		isAttack:   resp.IsAttack,
	}

	// Only apply the adjustment when the model is sure. Hedged predictions
	// (~50/50) carry no signal worth overriding the rule engine with.
	if resp.Confidence < minConfidence {
		return verdict
	}

	if resp.IsAttack {
		// Confident attack → bump the score up, typically over block_threshold.
		verdict.adjustment = attackBump
		evalResult.TotalScore = score + attackBump
	} else {
		// Confident normal → clear the request to ALLOW. Because any positive
		// score is now MONITOR, simply subtracting normalPenalty would leave a
		// matched-rule request flagged (it would land in (0, monitor) and stay
		// MONITOR). Zeroing the score lets a confidently-clean request pass as
		// ALLOW — this is what removes the gray-zone false positives the model
		// is there to catch. normalPenalty is kept as the *minimum* drop so the
		// logged adjustment is never smaller in magnitude than the configured
		// penalty.
		drop := score
		if normalPenalty > drop {
			drop = normalPenalty
		}
		verdict.adjustment = -drop
		evalResult.TotalScore = score - drop
		if evalResult.TotalScore < 0 {
			evalResult.TotalScore = 0
		}
	}
	return verdict
}
