// internal/middleware/waf.go
package middleware

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"waf-project/internal/api"
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

	// Check if should bypass WAF
	if w.config.DecisionEngine.ShouldBypassWAF(parsed) {
		w.config.Metrics.RecordRequest("BYPASS", 0)
		w.mu.RLock()
		proxy := w.proxy
		w.mu.RUnlock()
		proxy.ServeHTTP(wrappedRW, r)
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
	// Skip rate limiting for static assets (images, CSS, JS, fonts)
	// This prevents legitimate page loads from being blocked while maintaining
	// protection for API endpoints and dynamic content
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

		// Add to API buffer for dashboard
		api.AddToLogBuffer(entry)

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

	// Determine response status based on decision
	var responseStatus int
	switch decisionResult.Decision {
	case "BLOCK":
		responseStatus = decisionResult.ResponseCode
		if responseStatus == 0 {
			responseStatus = 403 // Default for BLOCK
		}
	case "CHALLENGE":
		responseStatus = 429 // Challenge usually uses 429
	default:
		responseStatus = wrappedRW.statusCode
		if responseStatus == 0 {
			responseStatus = 200 // Default for ALLOW
		}
	}

	// ========================================================================
	// STEP 7: Log Audit Entry
	// ========================================================================
	w.logAuditEntry(parsed, evalResult, decisionResult, behaviorResult,
		responseStatus, totalLatency)

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

	case "CHALLENGE":
		w.challengeRequest(wrappedRW, parsed, decisionResult.ChallengeType)

	case "ALLOW", "LOG":
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

	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied - WAF Protection</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        
        body::before {
            content: '';
            position: absolute;
            width: 500px;
            height: 500px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 50%;
            top: -250px;
            right: -250px;
            animation: float 6s ease-in-out infinite;
        }
        
        body::after {
            content: '';
            position: absolute;
            width: 300px;
            height: 300px;
            background: rgba(255, 255, 255, 0.08);
            border-radius: 50%;
            bottom: -150px;
            left: -150px;
            animation: float 8s ease-in-out infinite reverse;
        }
        
        @keyframes float {
            0%, 100% { transform: translateY(0px) rotate(0deg); }
            50% { transform: translateY(-20px) rotate(5deg); }
        }
        
        @keyframes pulse {
            0%, 100% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.05); opacity: 0.8; }
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 60px 50px;
            border-radius: 24px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 550px;
            width: 100%;
            text-align: center;
            position: relative;
            z-index: 1;
            animation: slideUp 0.6s ease-out;
        }
        
        .shield-container {
            position: relative;
            width: 120px;
            height: 120px;
            margin: 0 auto 35px;
        }
        
        .shield {
            font-size: 90px;
            animation: pulse 2s ease-in-out infinite;
            display: inline-block;
            filter: drop-shadow(0 4px 8px rgba(231, 76, 60, 0.3));
        }
        
        h1 {
            color: #2c3e50;
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 18px;
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            color: #e74c3c;
            font-size: 19px;
            font-weight: 600;
            margin-bottom: 35px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        
        .message {
            color: #555;
            font-size: 17px;
            line-height: 1.7;
            margin-bottom: 40px;
            max-width: 450px;
            margin-left: auto;
            margin-right: auto;
        }
        
        .footer {
            color: #999;
            font-size: 14px;
            margin-top: 40px;
            line-height: 1.7;
            padding-top: 30px;
            border-top: 1px solid #e9ecef;
        }
        
        .footer strong {
            color: #666;
            display: block;
            margin-bottom: 8px;
        }
        
        @media (max-width: 600px) {
            .container {
                padding: 50px 30px;
            }
            
            h1 {
                font-size: 28px;
            }
            
            .subtitle {
                font-size: 16px;
            }
            
            .message {
                font-size: 15px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield-container">
            <div class="shield">🛡️</div>
        </div>
        
        <h1>Access Denied</h1>

        <div class="subtitle">Security Protection Active</div>
        
        <p class="message">
            Your request has been blocked by our Web Application Firewall. 
            This security measure protects our systems from potentially harmful traffic.
        </p>
        
        <div class="footer">
            <strong>Need assistance?</strong>
            If you believe this is an error, please contact our support team for help.
        </div>
    </div>
</body>
</html>`
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

// logAuditEntry records audit details and stores them for the API dashboard
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
		LatencyMs:       float64(latency.Milliseconds()),
		RateLimited:     false,
		BlockDuration:   decisionResult.BlockDuration,
		BlockReason:     decisionResult.Reason,
		Metadata:        decisionResult.Metadata,
	}

	// Log to file
	w.config.AuditLogger.Log(entry)

	// Add to API buffer for dashboard
	api.AddToLogBuffer(entry)
}
