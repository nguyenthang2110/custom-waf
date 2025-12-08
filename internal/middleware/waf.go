// internal/middleware/waf.go
package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"waf-project/internal/audit"
	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/normalizer"
	"waf-project/internal/parser"
	"waf-project/internal/ratelimit"
)

// WAFConfig holds configuration for WAF middleware
type WAFConfig struct {
	Parser           *parser.HTTPParser
	Normalizer       *normalizer.Normalizer
	RuleEngine       *engine.RuleEngine
	RateLimiter      *ratelimit.RateLimiter
	BehaviorDetector *behavior.Detector
	DecisionEngine   *decision.DecisionEngine
	AuditLogger      *audit.Logger
	Metrics          *metrics.Collector
	Upstream         string

	// Optional settings
	EnableDebugHeaders bool
	DryRun             bool // Log only, don't block
	CustomBlockPage    string
}

// WAFMiddleware is the main WAF HTTP middleware
type WAFMiddleware struct {
	config *WAFConfig
	proxy  *httputil.ReverseProxy
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

	waf := &WAFMiddleware{
		config: config,
		proxy:  httputil.NewSingleHostReverseProxy(upstreamURL),
	}

	// Customize proxy error handler
	waf.proxy.ErrorHandler = waf.proxyErrorHandler

	return waf
}

// ServeHTTP implements http.Handler interface
func (w *WAFMiddleware) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

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

	// Check if should bypass WAF
	if w.config.DecisionEngine.ShouldBypassWAF(parsed) {
		w.config.Metrics.RecordRequest("BYPASS", 0)
		w.proxy.ServeHTTP(wrappedRW, r)
		return
	}

	// ========================================================================
	// STEP 2: Normalize Request
	// ========================================================================
	normStart := time.Now()
	if err := w.config.Normalizer.Normalize(parsed); err != nil {
		w.handleError(wrappedRW, r, "Failed to normalize request", http.StatusBadRequest)
		return
	}
	w.config.Metrics.RecordLatency("normalizer", time.Since(normStart))

	// ========================================================================
	// STEP 3: Rate Limiting Check
	// ========================================================================
	if w.config.RateLimiter.IsRateLimitedWithRoute(parsed.ClientIP, parsed.NormalizedPath) {
		w.config.Metrics.RecordRateLimitHit(parsed.ClientIP)

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
	// STEP 5: Behavior Analysis
	// ========================================================================
	behaviorResult := w.config.BehaviorDetector.Analyze(parsed, evalResult)

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

	// ========================================================================
	// STEP 7: Log Audit Entry
	// ========================================================================
	w.logAuditEntry(parsed, evalResult, decisionResult, behaviorResult,
		wrappedRW.statusCode, totalLatency)

	// ========================================================================
	// STEP 8: Execute Decision
	// ========================================================================

	// Dry run mode - log only, don't block
	if w.config.DryRun {
		w.addDebugHeaders(wrappedRW, decisionResult, evalResult)
		w.proxy.ServeHTTP(wrappedRW, r)
		w.config.Metrics.RecordRequestWithDetails(
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

	case "CHALLENGE":
		w.challengeRequest(wrappedRW, parsed, decisionResult.ChallengeType)

	case "ALLOW", "LOG":
		// Add debug headers if enabled
		if w.config.EnableDebugHeaders {
			w.addDebugHeaders(wrappedRW, decisionResult, evalResult)
		}

		// Forward to upstream
		w.proxy.ServeHTTP(wrappedRW, r)

		// Record successful request
		w.config.Metrics.RecordRequestWithDetails(
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
		parsed.Method,
		parsed.NormalizedPath,
		"BLOCK",
		0, // Score already recorded
		time.Since(startTime),
		parsed.BodySize,
		len(blockPage),
	)
}

// challengeRequest presents a challenge to the user
func (w *WAFMiddleware) challengeRequest(
	rw *responseWriter,
	parsed *engine.ParsedRequest,
	challengeType string,
) {
	rw.Header().Set("X-WAF-Status", "CHALLENGE")
	rw.Header().Set("X-WAF-Request-ID", parsed.RequestID)
	rw.Header().Set("X-WAF-Challenge-Type", challengeType)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")

	rw.WriteHeader(http.StatusTooManyRequests)

	challengePage := w.getChallengePage(parsed.RequestID, challengeType)
	io.WriteString(rw, challengePage)
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

// getBlockPage returns HTML for block page
func (w *WAFMiddleware) getBlockPage(requestID, reason string) string {
	if w.config.CustomBlockPage != "" {
		return w.config.CustomBlockPage
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        .icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        .request-id {
            font-family: monospace;
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin: 20px 0;
            font-size: 12px;
            color: #666;
        }
        .reason {
            color: #555;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🛡️</div>
        <h1>Access Denied</h1>
        <p>Your request has been blocked by our Web Application Firewall.</p>
        <div class="reason">Reason: %s</div>
        <div class="request-id">Request ID: %s</div>
        <p style="color: #999; font-size: 14px;">
            If you believe this is an error, please contact support with the Request ID above.
        </p>
    </div>
</body>
</html>`, reason, requestID)
}

// getChallengePage returns HTML for challenge page
func (w *WAFMiddleware) getChallengePage(requestID, challengeType string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Security Challenge</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%);
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
        }
        h1 {
            color: #f5576c;
            margin-bottom: 20px;
        }
        .icon {
            font-size: 80px;
            margin-bottom: 20px;
        }
        button {
            background: #f5576c;
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            margin-top: 20px;
        }
        button:hover {
            background: #d94560;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⚠️</div>
        <h1>Security Verification</h1>
        <p>Please complete the security check to continue.</p>
        <p>Challenge Type: %s</p>
        <button onclick="window.location.reload()">Verify</button>
        <p style="color: #999; font-size: 12px; margin-top: 20px;">Request ID: %s</p>
    </div>
</body>
</html>`, challengeType, requestID)
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

// logAuditEntry creates and logs an audit entry
func (w *WAFMiddleware) logAuditEntry(
	parsed *engine.ParsedRequest,
	evalResult *engine.EvaluationResult,
	decisionResult *decision.DecisionResult,
	behaviorResult *behavior.BehaviorResult,
	responseStatus int,
	latency time.Duration,
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
		LatencyMs:       float64(latency.Milliseconds()),
		RateLimited:     false,
		BlockDuration:   decisionResult.BlockDuration,
		BlockReason:     decisionResult.Reason,
		Metadata:        decisionResult.Metadata,
	}

	w.config.AuditLogger.Log(entry)
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
