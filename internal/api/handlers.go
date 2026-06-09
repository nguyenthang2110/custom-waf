// internal/api/handlers.go
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"waf-project/internal/audit"
	"waf-project/internal/auth"
	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/models"
	"waf-project/internal/notifier"
	"waf-project/internal/ratelimit"
)

// APIServer provides HTTP API for WAF dashboard
type APIServer struct {
	ruleEngine       *engine.RuleEngine
	rateLimiter      *ratelimit.RateLimiter
	behaviorDetector *behavior.Detector
	decisionEngine   *decision.DecisionEngine
	auditLogger      *audit.Logger
	metricsCollector *metrics.Collector
	wafMiddleware    WAFMiddlewareInterface // For backend configuration
	configStore      ConfigPersister        // Optional — when nil, runtime changes don't survive restart
	notifier         *notifier.Notifier     // Optional — alert dispatch + test endpoint

	// Authentication fields
	userRepo    *models.UserRepository
	jwtManager  *auth.JWTManager
	bcryptCost  int
	requireAuth bool
}

// ConfigPersister is the slice of configstore.Store that handlers need.
// Defined as an interface to keep this package free of a concrete dep on
// configstore (which already depends on decision/ratelimit).
type ConfigPersister interface {
	Save(key string, value any) error
}

// WAFMiddlewareInterface defines methods needed from WAFMiddleware
type WAFMiddlewareInterface interface {
	GetBackend() string
	UpdateBackend(url string) error
}

// NewAPIServer creates a new API server
func NewAPIServer(
	ruleEngine *engine.RuleEngine,
	rateLimiter *ratelimit.RateLimiter,
	behaviorDetector *behavior.Detector,
	decisionEngine *decision.DecisionEngine,
	auditLogger *audit.Logger,
	metricsCollector *metrics.Collector,
) *APIServer {
	return &APIServer{
		ruleEngine:       ruleEngine,
		rateLimiter:      rateLimiter,
		behaviorDetector: behaviorDetector,
		decisionEngine:   decisionEngine,
		auditLogger:      auditLogger,
		metricsCollector: metricsCollector,
	}
}

// SetWAFMiddleware sets the WAF middleware reference
func (s *APIServer) SetWAFMiddleware(waf WAFMiddlewareInterface) {
	s.wafMiddleware = waf
}

// SetConfigStore wires the persistent config store. Calling with nil
// disables persistence (handler updates still apply to live components).
func (s *APIServer) SetConfigStore(p ConfigPersister) {
	s.configStore = p
}

// SetNotifier wires the outbound alert dispatcher. Calling with nil
// disables the /waf-api/alerts/* endpoints (they return 503).
func (s *APIServer) SetNotifier(n *notifier.Notifier) {
	s.notifier = n
}

// RegisterRoutes registers all API routes
func (s *APIServer) RegisterRoutes(mux *http.ServeMux) {
	// Public auth endpoints (login + register)
	mux.HandleFunc("/waf-api/auth/register", s.handleRegister)
	mux.HandleFunc("/waf-api/auth/login", s.handleLogin)
	mux.HandleFunc("/waf-api/auth/logout", s.handleLogout)

	// Authenticated user info + self-service settings (any logged-in user)
	mux.HandleFunc("/waf-api/auth/me", s.requireAuthN(s.handleMe))
	mux.HandleFunc("/waf-api/auth/me/password", s.requireAuthN(s.handleChangeOwnPassword))

	// Admin-only user management
	// GET   /waf-api/auth/users         → list users
	// POST  /waf-api/auth/users         → create user (with chosen role)
	// GET   /waf-api/auth/users/{id}    → fetch one user (for edit-form prefill)
	// PUT   /waf-api/auth/users/{id}    → update role/email
	// DELETE /waf-api/auth/users/{id}   → delete (last-admin / self-delete guarded)
	// POST  /waf-api/auth/users/{id}/password → admin reset password
	mux.HandleFunc("/waf-api/auth/users", s.requireAdmin(s.handleUsers))
	mux.HandleFunc("/waf-api/auth/users/", s.requireAdmin(s.handleUserByID))

	// Stats endpoints (read-only — keep public for dashboard)
	mux.HandleFunc("/waf-api/stats", s.handleStats)
	mux.HandleFunc("/waf-api/stats/overview", s.handleStatsOverview)

	// Logs endpoints — read public, clear is admin-only
	mux.HandleFunc("/waf-api/logs", s.handleLogs)
	mux.HandleFunc("/waf-api/logs/recent", s.handleRecentLogs)
	mux.HandleFunc("/waf-api/logs/clear", s.requireAdmin(s.handleClearLogs))

	// IP endpoints — read public, unblock is admin-only
	mux.HandleFunc("/waf-api/ips", s.handleIPs)
	mux.HandleFunc("/waf-api/ips/blocked", s.handleBlockedIPs)
	mux.HandleFunc("/waf-api/ips/suspicious", s.handleSuspiciousIPs)
	mux.HandleFunc("/waf-api/ips/unblock", s.requireAdmin(s.handleUnblockIP))

	// Rules endpoints — read public, upload is admin-only
	mux.HandleFunc("/waf-api/rules", s.handleRules)
	mux.HandleFunc("/waf-api/rules/stats", s.handleRuleStats)
	mux.HandleFunc("/waf-api/rules/upload", s.requireAdmin(s.handleRuleUpload))
	mux.HandleFunc("/waf-api/rules/save", s.requireAdmin(s.handleRuleSave))
	mux.HandleFunc("/waf-api/rules/get/", s.handleRuleGet) // /waf-api/rules/get/<id>

	// Rate limit endpoints
	mux.HandleFunc("/waf-api/ratelimit", s.handleRateLimit)

	// Whitelist/Blacklist — read public, mutate is admin-only
	mux.HandleFunc("/waf-api/whitelist", s.requireAdminForWrite(s.handleWhitelist))
	mux.HandleFunc("/waf-api/blacklist", s.requireAdminForWrite(s.handleBlacklist))

	// Backend configuration — write is admin-only
	mux.HandleFunc("/waf-api/backend", s.requireAdminForWrite(s.handleBackend))

	// WAF configuration — write is admin-only
	mux.HandleFunc("/waf-api/config", s.requireAdminForWrite(s.handleConfig))

	// Alerts (Slack/Email/Webhook) — read public, mutate + test are admin-only.
	mux.HandleFunc("/waf-api/alerts/config", s.requireAdminForWrite(s.handleAlertsConfig))
	mux.HandleFunc("/waf-api/alerts/stats", s.handleAlertsStats)
	mux.HandleFunc("/waf-api/alerts/test", s.requireAdmin(s.handleAlertsTest))
	mux.HandleFunc("/waf-api/alerts/test-broadcast", s.requireAdmin(s.handleAlertsTestBroadcast))
}

// authContext holds the authenticated user identity extracted from a JWT.
type authContext struct {
	UserID   int
	Username string
	Role     string
}

// authenticate extracts a JWT from either the Authorization header
// (Bearer <token>) or the `waf_token` cookie, validates it, and returns the
// user. The cookie path is what lets browser navigations (full page loads)
// be guarded server-side; the header path is what the dashboard's fetch()
// calls use. Either is sufficient.
//
// Returns (nil, nil) for unauthenticated requests (no token anywhere) and
// (nil, err) only when a token was supplied but failed to validate (so the
// caller can return 401).
func (s *APIServer) authenticate(r *http.Request) (*authContext, error) {
	if s.jwtManager == nil {
		return nil, nil
	}
	tok := extractToken(r)
	if tok == "" {
		return nil, nil
	}
	claims, err := s.jwtManager.ValidateToken(tok)
	if err != nil {
		return nil, err
	}
	return &authContext{
		UserID:   claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
	}, nil
}

// requestIsHTTPS reports whether the original client request reached us
// over TLS. r.TLS alone is wrong when the WAF sits behind a TLS-
// terminating reverse proxy (CDN, load balancer) — then r.TLS is nil
// even though the user-facing leg was HTTPS. Honour X-Forwarded-Proto
// so cookies still get the Secure flag in that topology.
//
// Treats X-Forwarded-Proto as trustworthy: this WAF is itself the edge
// in most deployments, but if another proxy sits in front the operator
// is expected to scrub spoofed forwarded headers before they reach us
// (standard reverse-proxy hygiene).
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}

// extractToken pulls a JWT from `Authorization: Bearer <tok>` or the
// `waf_token` cookie, whichever is present. Header wins if both supplied.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); h != "" {
		parts := strings.SplitN(h, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return parts[1]
		}
	}
	if c, err := r.Cookie("waf_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return ""
}

// requireAuthN ensures the request carries a valid JWT (any role).
// When auth is globally disabled in config, the handler is invoked unchanged.
func (s *APIServer) requireAuthN(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth || s.jwtManager == nil {
			next(w, r)
			return
		}
		user, err := s.authenticate(r)
		if err != nil {
			writeErrorJSON(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		if user == nil {
			writeErrorJSON(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		next(w, r.WithContext(withAuth(r, user)))
	}
}

// requireAdmin ensures the request carries a valid JWT with role=admin.
// When auth is globally disabled, the handler is invoked unchanged.
func (s *APIServer) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth || s.jwtManager == nil {
			next(w, r)
			return
		}
		user, err := s.authenticate(r)
		if err != nil {
			writeErrorJSON(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		if user == nil {
			writeErrorJSON(w, "Authentication required", http.StatusUnauthorized)
			return
		}
		if user.Role != "admin" {
			writeErrorJSON(w, "Admin role required", http.StatusForbidden)
			return
		}
		next(w, r.WithContext(withAuth(r, user)))
	}
}

// PageGuard returns middleware that protects management HTML pages.
// Unauthenticated requests get a 302 redirect to /login.html?next=<original>.
// Invalid/expired tokens clear the cookie and redirect to /login.html.
//
// No-op when auth is disabled globally (require_auth: false in config) or
// the JWT manager isn't initialised (DB unavailable).
//
// Pages still embed the original JS-side check as a fallback for the case
// of `require_auth: false`, but with the cookie path active the redirect is
// authoritative server-side — users can't bypass by viewing source / curl.
func (s *APIServer) PageGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.requireAuth || s.jwtManager == nil {
			next.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			redirectToLogin(w, r, "")
			return
		}
		if _, err := s.jwtManager.ValidateToken(tok); err != nil {
			// Token invalid/expired — wipe the cookie before redirecting
			// so the browser stops re-sending it.
			http.SetCookie(w, &http.Cookie{
				Name: "waf_token", Value: "", Path: "/", MaxAge: -1,
				HttpOnly: true, SameSite: http.SameSiteLaxMode,
				Secure: requestIsHTTPS(r),
			})
			redirectToLogin(w, r, "session expired")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isSafeNextPath reports whether `p` is a same-origin relative URI safe
// to put in `?next=`. The JS-side check on login.html applies the same
// rule, but a defence-in-depth check here means an XSS / disabled-JS
// path can't turn the login page into an open-redirect bounce.
//
// Rules:
//   - must start with exactly one '/'
//   - must NOT start with "//" (protocol-relative URLs go cross-origin)
//   - must NOT start with "/\" (Chrome/Safari rewrite to scheme-relative)
//   - must NOT contain a control char or NUL (request smuggling / log
//     injection prevention)
func isSafeNextPath(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	if strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return false
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func redirectToLogin(w http.ResponseWriter, r *http.Request, reason string) {
	target := "/login.html"
	q := url.Values{}
	// Only propagate `next` when the original URI is genuinely same-origin
	// relative. RequestURI() includes path + query; if either is hostile
	// (cross-origin, protocol-relative, control chars) we drop it on the
	// floor and the user lands at the bare /login.html.
	if r.URL.Path != "" && r.URL.Path != "/login.html" {
		if candidate := r.URL.RequestURI(); isSafeNextPath(candidate) {
			q.Set("next", candidate)
		}
	}
	if reason != "" {
		q.Set("reason", reason)
	}
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// requireAdminForWrite enforces admin auth only on mutating verbs (POST/PUT/PATCH/DELETE),
// leaving GET/HEAD/OPTIONS open for the dashboard.
func (s *APIServer) requireAdminForWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next(w, r)
			return
		}
		s.requireAdmin(next)(w, r)
	}
}

type ctxKeyAuth struct{}

func withAuth(r *http.Request, user *authContext) context.Context {
	return context.WithValue(r.Context(), ctxKeyAuth{}, user)
}

// userFromContext returns the authenticated user attached by requireAuthN/requireAdmin.
func userFromContext(r *http.Request) (*authContext, bool) {
	user, ok := r.Context().Value(ctxKeyAuth{}).(*authContext)
	return user, ok
}

// ============================================================================
// Stats Handlers
// ============================================================================

type StatsResponse struct {
	TotalRequests   int64            `json:"total_requests"`
	TotalBlocked    int64            `json:"total_blocked"`
	TotalAllowed    int64            `json:"total_allowed"`
	TotalChallenged int64            `json:"total_challenged"`
	BlockRate       float64          `json:"block_rate"`
	AvgLatency      string           `json:"avg_latency"`
	Uptime          string           `json:"uptime"`
	RulesLoaded     int              `json:"rules_loaded"`
	UniqueClients   int              `json:"unique_clients"`
	TopRules        []RuleCount      `json:"top_rules"`
	TopCategories   map[string]int64 `json:"top_categories"`
}

type RuleCount struct {
	RuleID string `json:"rule_id"`
	Count  int64  `json:"count"`
}

func (s *APIServer) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get metrics from collector
	stats := s.metricsCollector.GetStats()

	// Get top rules
	topRules := s.metricsCollector.GetTopRules(10)
	topRulesResponse := make([]RuleCount, len(topRules))
	for i, rule := range topRules {
		topRulesResponse[i] = RuleCount{
			RuleID: rule.RuleID,
			Count:  rule.Count,
		}
	}

	response := StatsResponse{
		TotalRequests:   stats.TotalRequests,
		TotalBlocked:    stats.TotalBlocked,
		TotalAllowed:    stats.TotalAllowed,
		TotalChallenged: stats.TotalChallenged,
		BlockRate:       s.metricsCollector.GetBlockRate(),
		AvgLatency:      s.metricsCollector.GetAverageLatency().String(),
		Uptime:          s.metricsCollector.GetUptime().String(),
		RulesLoaded:     s.ruleEngine.RuleCount(),
		UniqueClients:   stats.UniqueClients,
		TopRules:        topRulesResponse,
		TopCategories:   stats.TopCategories,
	}

	writeJSON(w, response)
}

func (s *APIServer) handleStatsOverview(w http.ResponseWriter, r *http.Request) {
	stats := s.metricsCollector.GetStats()

	response := map[string]interface{}{
		"total_requests": stats.TotalRequests,
		"blocked":        stats.TotalBlocked,
		"allowed":        stats.TotalAllowed,
		"challenged":     stats.TotalChallenged,
		"block_rate":     s.metricsCollector.GetBlockRate(),
	}

	writeJSON(w, response)
}

// ============================================================================
// Logs Handlers
// ============================================================================

type RuleMatchAPI struct {
	RuleID    string  `json:"rule_id"`
	Category  string  `json:"category"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	MatchedOn string  `json:"matched_on"`
	Pattern   string  `json:"pattern,omitempty"`
	Payload   string  `json:"payload,omitempty"`
}

type LogEntry struct {
	Timestamp      string         `json:"timestamp"`
	RequestID      string         `json:"request_id"`
	ClientIP       string         `json:"client_ip"`
	Method         string         `json:"method"`
	Path           string         `json:"path"`
	Query          string         `json:"query"`
	UserAgent      string         `json:"user_agent"`
	Decision       string         `json:"decision"`
	TotalScore     float64        `json:"total_score"`
	MatchedRules   []RuleMatchAPI `json:"matched_rules"`
	Categories     []string       `json:"categories"`
	ResponseStatus int            `json:"response_status"`
	LatencyMs      float64        `json:"latency_ms"`

	// Source attribution for the dashboard. One of:
	//   "rule"        — rule engine alone produced the verdict
	//   "model"       — ML adjusted the score (rules didn't match)
	//   "rule+model"  — both contributed
	//   "-"           — clean traffic, neither path triggered
	Source string `json:"source"`

	// ML, when present, carries the verdict from /predict so the modal
	// can show the attack class and confidence even when no rule matched.
	ML *MLVerdictAPI `json:"ml,omitempty"`

	// Headers captured from the request — Cookie / Authorization values
	// are already redacted by the WAF middleware before they land here.
	Headers map[string][]string `json:"headers,omitempty"`

	// BlockReason carries the human-readable trigger that produced the
	// decision (rule name, rate-limit message, system event message,
	// etc.). The dashboard surfaces it on click and uses it as the row
	// text for SYSTEM entries that have no path/method.
	BlockReason string `json:"block_reason,omitempty"`

	// Metadata is the raw bag from the audit entry — primarily so SYSTEM
	// rows can show `event_type` + `message` without a server-side
	// transformation. For request rows this is also where ML verdict,
	// whitelist hits, and other side-channel info live.
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// MLVerdictAPI mirrors the ml_* metadata stamped onto the audit entry by
// the WAF middleware. Called=false means the request never reached the
// model (rule score outside the gray zone, or ML disabled).
type MLVerdictAPI struct {
	Called      bool    `json:"called"`
	Label       string  `json:"label,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	IsAttack    bool    `json:"is_attack,omitempty"`
	ScoreAdjust float64 `json:"score_adjust,omitempty"`
	Error       string  `json:"error,omitempty"`
}

// extractMLVerdict pulls the ml_* fields out of an audit entry's metadata
// bag. Returns nil when the model wasn't consulted for this request.
func extractMLVerdict(meta map[string]interface{}) *MLVerdictAPI {
	if meta == nil {
		return nil
	}
	_, hasLabel := meta["ml_label"]
	_, hasErr := meta["ml_error"]
	if !hasLabel && !hasErr {
		return nil
	}
	v := &MLVerdictAPI{Called: true}
	if s, ok := meta["ml_label"].(string); ok {
		v.Label = s
	}
	if f, ok := meta["ml_confidence"].(float64); ok {
		v.Confidence = f
	}
	if b, ok := meta["ml_is_attack"].(bool); ok {
		v.IsAttack = b
	}
	if f, ok := meta["ml_score_adjust"].(float64); ok {
		v.ScoreAdjust = f
	}
	if s, ok := meta["ml_error"].(string); ok {
		v.Error = s
	}
	return v
}

// computeSource labels each request with whichever subsystem drove the
// verdict. Both rule and model can contribute in the gray zone, so
// "rule+model" is a valid third option. Whitelisted IPs skipped the full
// pipeline — they get their own source label so operators can spot them.
func computeSource(matchedRuleCount int, ml *MLVerdictAPI, whitelisted bool) string {
	if whitelisted {
		return "whitelist"
	}
	hasRule := matchedRuleCount > 0
	hasML := ml != nil && ml.ScoreAdjust != 0
	switch {
	case hasRule && hasML:
		return "rule+model"
	case hasML:
		return "model"
	case hasRule:
		return "rule"
	default:
		return "-"
	}
}

// isWhitelistedEntry reports whether the audit entry was produced by the
// whitelist short-circuit (the WAF middleware tags those with metadata
// "whitelisted":true so the dashboard can label them).
func isWhitelistedEntry(meta map[string]interface{}) bool {
	if meta == nil {
		return false
	}
	v, _ := meta["whitelisted"].(bool)
	return v
}

func (s *APIServer) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get pagination parameters
	pageStr := r.URL.Query().Get("page")
	page := 1
	if pageStr != "" {
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
	}

	perPageStr := r.URL.Query().Get("per_page")
	perPage := 50
	if perPageStr != "" {
		if pp, err := strconv.Atoi(perPageStr); err == nil && pp > 0 && pp <= 1000 {
			perPage = pp
		}
	}

	// Get filter parameters
	decision := r.URL.Query().Get("decision")
	ip := r.URL.Query().Get("ip")
	method := r.URL.Query().Get("method")
	pathContains := r.URL.Query().Get("path_contains")

	// Optional time-range filter. Accepts RFC3339 (with offset or "Z").
	// Invalid values are silently ignored — the dashboard sends an empty
	// string when the input is empty so we can't error on parse failure.
	var fromT, toT time.Time
	if v := strings.TrimSpace(r.URL.Query().Get("from")); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			fromT = t
		}
	}
	if v := strings.TrimSpace(r.URL.Query().Get("to")); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			toT = t
		}
	}

	// Get sorting parameters
	sortBy := r.URL.Query().Get("sort_by")
	if sortBy == "" {
		sortBy = "timestamp"
	}
	sortOrder := r.URL.Query().Get("sort_order")
	if sortOrder == "" {
		sortOrder = "desc"
	}

	logMutex.RLock()
	defer logMutex.RUnlock()

	// Filter logs
	filteredLogs := make([]LogEntry, 0)
	for i := len(logBuffer) - 1; i >= 0; i-- {
		entry := logBuffer[i]

		// Apply filters
		if decision != "" && entry.Decision != decision {
			continue
		}
		if ip != "" && entry.ClientIP != ip {
			continue
		}
		if method != "" && entry.Method != method {
			continue
		}
		if pathContains != "" && !strings.Contains(entry.Path, pathContains) {
			continue
		}
		if !fromT.IsZero() && entry.Timestamp.Before(fromT) {
			continue
		}
		if !toT.IsZero() && entry.Timestamp.After(toT) {
			continue
		}

		// Map rule matches to API format
		ruleMatches := make([]RuleMatchAPI, 0, len(entry.MatchedRules))
		for _, rule := range entry.MatchedRules {
			ruleMatches = append(ruleMatches, RuleMatchAPI{
				RuleID:    rule.RuleID,
				Category:  rule.Category,
				Severity:  rule.Severity,
				Score:     rule.Score,
				MatchedOn: rule.MatchedOn,
				Pattern:   rule.Pattern,
				Payload:   rule.Payload,
			})
		}

		mlVerdict := extractMLVerdict(entry.Metadata)
		filteredLogs = append(filteredLogs, LogEntry{
			Timestamp:      entry.Timestamp.Format(time.RFC3339),
			RequestID:      entry.RequestID,
			ClientIP:       entry.ClientIP,
			Method:         entry.Method,
			Path:           entry.Path,
			Query:          entry.Query,
			UserAgent:      entry.UserAgent,
			Decision:       entry.Decision,
			TotalScore:     entry.TotalScore,
			MatchedRules:   ruleMatches,
			Categories:     entry.Categories,
			ResponseStatus: entry.ResponseStatus,
			LatencyMs:      entry.LatencyMs,
			Source:         computeSource(len(ruleMatches), mlVerdict, isWhitelistedEntry(entry.Metadata)),
			ML:             mlVerdict,
			Headers:        entry.Headers,
			BlockReason:    entry.BlockReason,
			Metadata:       entry.Metadata,
		})
	}

	// Sort logs
	sort.Slice(filteredLogs, func(i, j int) bool {
		var less bool
		switch sortBy {
		case "timestamp":
			less = filteredLogs[i].Timestamp < filteredLogs[j].Timestamp
		case "client_ip":
			less = filteredLogs[i].ClientIP < filteredLogs[j].ClientIP
		case "method":
			less = filteredLogs[i].Method < filteredLogs[j].Method
		case "path":
			less = filteredLogs[i].Path < filteredLogs[j].Path
		case "decision":
			less = filteredLogs[i].Decision < filteredLogs[j].Decision
		case "total_score":
			less = filteredLogs[i].TotalScore < filteredLogs[j].TotalScore
		case "latency_ms":
			less = filteredLogs[i].LatencyMs < filteredLogs[j].LatencyMs
		default:
			less = filteredLogs[i].Timestamp < filteredLogs[j].Timestamp
		}

		if sortOrder == "desc" {
			return !less
		}
		return less
	})

	// Calculate pagination
	total := len(filteredLogs)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}

	// Get page slice
	start := (page - 1) * perPage
	end := start + perPage
	if start >= total {
		start = 0
		end = 0
	}
	if end > total {
		end = total
	}

	paginatedLogs := filteredLogs[start:end]

	// Return response with metadata
	response := map[string]interface{}{
		"logs": paginatedLogs,
		"metadata": map[string]interface{}{
			"total":       total,
			"page":        page,
			"per_page":    perPage,
			"total_pages": totalPages,
		},
	}

	writeJSON(w, response)
}

func (s *APIServer) handleRecentLogs(w http.ResponseWriter, r *http.Request) {
	logMutex.RLock()
	defer logMutex.RUnlock()

	// Return last 50 logs
	logs := make([]LogEntry, 0)
	start := len(logBuffer) - 50
	if start < 0 {
		start = 0
	}

	for i := len(logBuffer) - 1; i >= start; i-- {
		entry := logBuffer[i]

		ruleMatches := make([]RuleMatchAPI, 0, len(entry.MatchedRules))
		for _, rule := range entry.MatchedRules {
			ruleMatches = append(ruleMatches, RuleMatchAPI{
				RuleID:    rule.RuleID,
				Category:  rule.Category,
				Severity:  rule.Severity,
				Score:     rule.Score,
				MatchedOn: rule.MatchedOn,
				Pattern:   rule.Pattern,
				Payload:   rule.Payload,
			})
		}

		mlVerdict := extractMLVerdict(entry.Metadata)
		logs = append(logs, LogEntry{
			Timestamp:      entry.Timestamp.Format(time.RFC3339),
			RequestID:      entry.RequestID,
			ClientIP:       entry.ClientIP,
			Method:         entry.Method,
			Path:           entry.Path,
			Query:          entry.Query,
			Decision:       entry.Decision,
			TotalScore:     entry.TotalScore,
			MatchedRules:   ruleMatches,
			ResponseStatus: entry.ResponseStatus,
			LatencyMs:      entry.LatencyMs,
			Source:         computeSource(len(ruleMatches), mlVerdict, isWhitelistedEntry(entry.Metadata)),
			ML:             mlVerdict,
			Headers:        entry.Headers,
			BlockReason:    entry.BlockReason,
			Metadata:       entry.Metadata,
		})
	}

	writeJSON(w, logs)
}

func (s *APIServer) handleClearLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clear the log buffer
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in ClearLogBuffer: %v\n", r)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	ClearLogBuffer()
	fmt.Println("Logs cleared successfully")

	// Log the action
	s.auditLogger.LogSystemEvent("LOGS_CLEARED", "Admin cleared all logs from buffer")

	writeJSON(w, map[string]interface{}{
		"success": true,
		"message": "All logs cleared successfully",
	})
}

// ============================================================================
// IP Handlers
// ============================================================================

type IPInfo struct {
	IP              string   `json:"ip"`
	TotalRequests   int      `json:"total_requests"`
	BlockedRequests int      `json:"blocked_requests"`
	LastSeen        string   `json:"last_seen"`
	IsBlocked       bool     `json:"is_blocked"`
	IsSuspicious    bool     `json:"is_suspicious"`
	SuspicionScore  float64  `json:"suspicion_score"`
	DetectedAttacks []string `json:"detected_attacks"`

	// Extended fields surfaced when a row is expanded in the dashboard.
	// All optional — empty values are fine when behavior tracking has no data
	// for the IP (e.g. IP only appears in the metrics collector).
	FailedAttempts      int            `json:"failed_attempts,omitempty"`
	SuccessfulAttempts  int            `json:"successful_attempts,omitempty"`
	UniquePathsAccessed int            `json:"unique_paths_accessed,omitempty"`
	IsBot               bool           `json:"is_bot,omitempty"`
	FirstSeen           string         `json:"first_seen,omitempty"`
	BlockedUntil        string         `json:"blocked_until,omitempty"`
	AttackCounts        map[string]int `json:"attack_counts,omitempty"`
	Reasons             []string       `json:"reasons,omitempty"`
}

func (s *APIServer) handleIPs(w http.ResponseWriter, r *http.Request) {
	// Get stats from metrics collector (Source of Truth for request counts)
	metricsStats := s.metricsCollector.GetStats()

	ips := make([]IPInfo, 0, len(metricsStats.Clients))
	for ip, clientStat := range metricsStats.Clients {
		// Get behavior info
		behaviorStats := s.behaviorDetector.GetIPStats(ip)

		attacks := make([]string, 0)
		attackCounts := map[string]int{}
		suspicionScore := 0.0
		isSuspicious := false
		isBot := false
		failed := 0
		succeeded := 0
		uniquePaths := 0
		firstSeen := ""
		blockedUntil := ""

		if behaviorStats != nil {
			suspicionScore = behaviorStats.SuspicionScore
			isSuspicious = behaviorStats.IsSuspicious
			isBot = behaviorStats.IsBot
			failed = behaviorStats.FailedAttempts
			succeeded = behaviorStats.SuccessfulAttempts
			uniquePaths = behaviorStats.UniquePathsAccessed
			if !behaviorStats.FirstSeen.IsZero() {
				firstSeen = behaviorStats.FirstSeen.Format(time.RFC3339)
			}
			if !behaviorStats.BlockedUntil.IsZero() {
				blockedUntil = behaviorStats.BlockedUntil.Format(time.RFC3339)
			}
			for attack, count := range behaviorStats.DetectedAttacks {
				attacks = append(attacks, attack)
				attackCounts[attack] = count
			}
		}

		// IP is considered "blocked" if either:
		//   (a) rate limiter token bucket is exhausted (tokens < 0), OR
		//   (b) behavior detector has placed a temporary block (bruteforce
		//       triggered → stats.isBlocked + blockedUntil > now).
		// Without (b) the dashboard would never surface the "blocked" state
		// because the ratelimit bucket stops at 0, not negative.
		isBlocked := s.rateLimiter.IsClientBlocked(ip)
		if !isBlocked && behaviorStats != nil && behaviorStats.IsBlocked &&
			time.Now().Before(behaviorStats.BlockedUntil) {
			isBlocked = true
		}

		// Build human-readable reasons explaining the current status.
		// Order matters: most severe first so the UI can show them top-down.
		reasons := buildIPReasons(buildIPReasonsInput{
			IsBlocked:       isBlocked,
			IsSuspicious:    isSuspicious,
			IsBot:           isBot,
			SuspicionScore:  suspicionScore,
			FailedAttempts:  failed,
			BlockedRequests: int(clientStat.TotalBlocked),
			UniquePaths:     uniquePaths,
			AttackCounts:    attackCounts,
			BehaviorStats:   behaviorStats != nil,
			BlockedUntil:    blockedUntil,
		})

		ips = append(ips, IPInfo{
			IP:                  ip,
			TotalRequests:       int(clientStat.TotalRequests),
			BlockedRequests:     int(clientStat.TotalBlocked),
			LastSeen:            clientStat.LastSeen.Format(time.RFC3339),
			IsBlocked:           isBlocked,
			IsSuspicious:        isSuspicious,
			SuspicionScore:      suspicionScore,
			DetectedAttacks:     attacks,
			FailedAttempts:      failed,
			SuccessfulAttempts:  succeeded,
			UniquePathsAccessed: uniquePaths,
			IsBot:               isBot,
			FirstSeen:           firstSeen,
			BlockedUntil:        blockedUntil,
			AttackCounts:        attackCounts,
			Reasons:             reasons,
		})
	}

	// Sort by total requests desc
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].TotalRequests > ips[j].TotalRequests
	})

	writeJSON(w, ips)
}

// buildIPReasonsInput bundles every signal that contributes to a "reason"
// line on the IP detail panel — keeps the call site readable.
type buildIPReasonsInput struct {
	IsBlocked       bool
	IsSuspicious    bool
	IsBot           bool
	SuspicionScore  float64
	FailedAttempts  int
	BlockedRequests int
	UniquePaths     int
	AttackCounts    map[string]int
	BehaviorStats   bool
	BlockedUntil    string
}

// buildIPReasons turns raw behavior + metrics into the short bullet list the
// dashboard shows when a user clicks an IP row. Lines are ordered most-severe
// first so the operator sees the headline finding without scrolling.
func buildIPReasons(in buildIPReasonsInput) []string {
	reasons := []string{}

	if in.IsBlocked {
		if in.BlockedUntil != "" {
			reasons = append(reasons, fmt.Sprintf("Currently blocked (until %s)", in.BlockedUntil))
		} else {
			reasons = append(reasons, "Currently blocked")
		}
	}
	if in.FailedAttempts > 0 {
		reasons = append(reasons,
			fmt.Sprintf("%d failed/blocked attempts recorded by behavior detector", in.FailedAttempts))
	}
	if in.BlockedRequests > 0 {
		reasons = append(reasons,
			fmt.Sprintf("%d request(s) blocked by WAF rules", in.BlockedRequests))
	}
	if len(in.AttackCounts) > 0 {
		// Sort attack names for stable output.
		keys := make([]string, 0, len(in.AttackCounts))
		for k := range in.AttackCounts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			reasons = append(reasons, fmt.Sprintf("Attack pattern: %s (×%d)", k, in.AttackCounts[k]))
		}
	}
	if in.IsBot {
		reasons = append(reasons, "Bot signature matched (User-Agent / heuristics)")
	}
	if in.UniquePaths > 0 && in.IsSuspicious {
		// Only mention scanning if the suspicion actually fired — otherwise a
		// normal client browsing many pages would look guilty here.
		reasons = append(reasons, fmt.Sprintf("Scanned %d unique paths (possible recon)", in.UniquePaths))
	}
	if in.IsSuspicious && len(reasons) == 0 {
		// Suspicion is on but we didn't surface a specific signal — fall back
		// to the raw score so the user knows *why* it's flagged at all.
		reasons = append(reasons, fmt.Sprintf("Suspicion score %.2f exceeds threshold", in.SuspicionScore))
	}
	if len(reasons) == 0 {
		// Either behavior detector hasn't recorded this IP yet, or it has but
		// none of the threat signals fired. Either way the operator deserves
		// a positive confirmation rather than an empty panel.
		reasons = append(reasons, "No threat signals detected — normal traffic")
	}

	return reasons
}

func (s *APIServer) handleBlockedIPs(w http.ResponseWriter, r *http.Request) {
	blockedStats := s.behaviorDetector.GetBlockedIPs()

	ips := make([]IPInfo, 0, len(blockedStats))
	for _, stat := range blockedStats {
		ips = append(ips, IPInfo{
			IP:        stat.ClientIP,
			IsBlocked: stat.IsBlocked,
			LastSeen:  stat.LastSeen.Format(time.RFC3339),
		})
	}

	writeJSON(w, ips)
}

func (s *APIServer) handleSuspiciousIPs(w http.ResponseWriter, r *http.Request) {
	suspiciousStats := s.behaviorDetector.GetSuspiciousIPs()

	ips := make([]IPInfo, 0, len(suspiciousStats))
	for _, stat := range suspiciousStats {
		attacks := make([]string, 0)
		for attack := range stat.DetectedAttacks {
			attacks = append(attacks, attack)
		}

		ips = append(ips, IPInfo{
			IP:              stat.ClientIP,
			TotalRequests:   stat.TotalRequests,
			IsSuspicious:    stat.IsSuspicious,
			SuspicionScore:  stat.SuspicionScore,
			DetectedAttacks: attacks,
		})
	}

	writeJSON(w, ips)
}

func (s *APIServer) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.IP == "" {
		http.Error(w, "IP address required", http.StatusBadRequest)
		return
	}

	s.behaviorDetector.UnblockIP(req.IP)

	writeJSON(w, map[string]string{
		"status":  "success",
		"message": fmt.Sprintf("IP %s has been unblocked", req.IP),
	})
}

// ============================================================================
// Rules Handlers
// ============================================================================

func (s *APIServer) handleRules(w http.ResponseWriter, r *http.Request) {
	rules := s.ruleEngine.ListRules()

	// Optional filters: ?category=, ?severity=, ?enabled=true|false
	q := r.URL.Query()
	cat := q.Get("category")
	sev := strings.ToUpper(q.Get("severity"))
	enabledFilter := q.Get("enabled")

	filtered := make([]engine.RuleSummary, 0, len(rules))
	for _, ru := range rules {
		if cat != "" && !strings.EqualFold(ru.Category, cat) {
			continue
		}
		if sev != "" && ru.Severity != sev {
			continue
		}
		if enabledFilter != "" {
			want := enabledFilter == "true" || enabledFilter == "1"
			if ru.Enabled != want {
				continue
			}
		}
		filtered = append(filtered, ru)
	}

	writeJSON(w, map[string]interface{}{
		"status":      "loaded",
		"total_rules": len(rules),
		"returned":    len(filtered),
		"rules":       filtered,
	})
}

func (s *APIServer) handleRuleStats(w http.ResponseWriter, r *http.Request) {
	metrics := s.ruleEngine.GetMetrics()

	response := map[string]interface{}{
		"total_evaluations": metrics.TotalEvaluations,
		"total_matches":     metrics.TotalMatches,
		"rule_hit_count":    metrics.RuleHitCount,
		"category_stats":    metrics.CategoryStats,
	}

	writeJSON(w, response)
}

// UploadResponse represents the response for rule upload
type UploadResponse struct {
	Success     bool     `json:"success"`
	Message     string   `json:"message"`
	RulesLoaded int      `json:"rules_loaded"`
	BackupPath  string   `json:"backup_path,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// handleRuleUpload handles uploading new rule files
func (s *APIServer) handleRuleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (10MB max)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Failed to parse form data",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Get file from form
	file, header, err := r.FormFile("rules")
	if err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "No file provided",
			Errors:  []string{err.Error()},
		})
		return
	}
	defer file.Close()

	// Extension check — filepath.Ext handles trailing dots, multiple
	// extensions ("rules.json.html" → ".html"), and Windows-style paths.
	// We also check the Content-Type the browser advertised; a strict
	// allow-list keeps an attacker from sending an arbitrary blob with a
	// renamed extension.
	if !strings.EqualFold(filepath.Ext(header.Filename), ".json") {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "File must have a .json extension",
		})
		return
	}
	if ct := header.Header.Get("Content-Type"); ct != "" &&
		!strings.HasPrefix(ct, "application/json") &&
		!strings.HasPrefix(ct, "text/json") &&
		ct != "application/octet-stream" {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Unexpected Content-Type for a rules file",
			Errors:  []string{"got " + ct + ", expected application/json"},
		})
		return
	}

	// Read file content. io.ReadAll bounded by ParseMultipartForm's 10MB
	// limit above — the body has already been buffered by the multipart
	// parser, so this won't blow memory. The previous `file.Read(make(...,
	// header.Size))` was racy: Read may return fewer bytes than asked for
	// without erroring, leaving a tail of zero bytes in the buffer that
	// would then fail JSON parsing with a confusing message.
	fileData, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Failed to read file",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Validate rules before applying
	ruleCount, err := s.ruleEngine.ValidateRulesJSON(fileData)
	if err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Rule validation failed",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Create backup of current rules
	backupPath := ""
	currentRulesPath := "configs/rules/all_rules.json"
	if _, err := os.Stat(currentRulesPath); err == nil {
		timestamp := time.Now().Format("20060102_150405")
		backupPath = fmt.Sprintf("configs/rules/backups/all_rules_%s.json", timestamp)

		// Read current rules
		currentData, err := os.ReadFile(currentRulesPath)
		if err == nil {
			// Write backup
			os.WriteFile(backupPath, currentData, 0644)
		}
	}

	// Reload rules in rule engine
	err = s.ruleEngine.ReloadRules(fileData)
	if err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Failed to reload rules",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Save uploaded rules to file
	err = os.WriteFile(currentRulesPath, fileData, 0644)
	if err != nil {
		// Rules are loaded in memory but not saved to disk
		writeJSON(w, UploadResponse{
			Success:     true,
			Message:     fmt.Sprintf("Rules loaded successfully (%d rules) but failed to save to disk", ruleCount),
			RulesLoaded: ruleCount,
			BackupPath:  backupPath,
			Errors:      []string{"Failed to persist rules: " + err.Error()},
		})
		return
	}

	// Success
	writeJSON(w, UploadResponse{
		Success:     true,
		Message:     fmt.Sprintf("Successfully uploaded and loaded %d rules", ruleCount),
		RulesLoaded: ruleCount,
		BackupPath:  backupPath,
	})
}

// ============================================================================
// Rate Limit Handlers
// ============================================================================

func (s *APIServer) handleRateLimit(w http.ResponseWriter, r *http.Request) {
	stats := s.rateLimiter.GetStats()

	response := map[string]interface{}{
		"total_requests": stats.TotalRequests,
		"total_blocked":  stats.TotalBlocked,
		"block_rate":     stats.BlockRate,
		"active_clients": stats.ActiveClients,
	}

	writeJSON(w, response)
}

// ============================================================================
// Whitelist/Blacklist Handlers
// ============================================================================

// ipMutationRequest is the body for POST/DELETE on whitelist/blacklist.
// action defaults to "add" for POST and "remove" for DELETE so older clients
// that send {"action":"remove"} on POST still work.
//
// TTLSeconds (optional, POST only): when > 0 the entry expires
// `ttl_seconds` after now. When 0 or omitted the entry is permanent.
// Negative values are clamped to 0 (permanent) — we don't surface an
// error so the dashboard can be sloppy with form data.
type ipMutationRequest struct {
	IP         string `json:"ip"`
	Action     string `json:"action,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
}

func (s *APIServer) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"ips":     s.decisionEngine.GetWhitelistIPs(),     // legacy field — flat IP list
			"entries": s.decisionEngine.GetWhitelistEntries(), // {ip, expires_at}
		})
	case http.MethodPost, http.MethodDelete:
		s.mutateIPList(w, r,
			s.decisionEngine.AddWhitelistIPWithTTL,
			s.decisionEngine.RemoveWhitelistIP,
			s.decisionEngine.GetWhitelistEntries,
			"whitelist_ips")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"ips":     s.decisionEngine.GetBlacklistIPs(),
			"entries": s.decisionEngine.GetBlacklistEntries(),
		})
	case http.MethodPost, http.MethodDelete:
		s.mutateIPList(w, r,
			s.decisionEngine.AddBlacklistIPWithTTL,
			s.decisionEngine.RemoveBlacklistIP,
			s.decisionEngine.GetBlacklistEntries,
			"blacklist_ips")
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) mutateIPList(
	w http.ResponseWriter,
	r *http.Request,
	add func(string, time.Duration),
	remove func(string),
	current func() []decision.IPListEntry,
	persistKey string,
) {
	var req ipMutationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.IP == "" {
		http.Error(w, "ip required", http.StatusBadRequest)
		return
	}

	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		if r.Method == http.MethodDelete {
			action = "remove"
		} else {
			action = "add"
		}
	}

	switch action {
	case "add":
		ttl := time.Duration(0)
		if req.TTLSeconds > 0 {
			ttl = time.Duration(req.TTLSeconds) * time.Second
		}
		add(req.IP, ttl)
		s.persistIPList(persistKey, current)
		resp := map[string]interface{}{"status": "added", "ip": req.IP}
		if ttl > 0 {
			resp["expires_at"] = time.Now().Add(ttl).Format(time.RFC3339)
		}
		writeJSON(w, resp)
	case "remove", "delete":
		remove(req.IP)
		s.persistIPList(persistKey, current)
		writeJSON(w, map[string]string{"status": "removed", "ip": req.IP})
	default:
		http.Error(w, "action must be add or remove", http.StatusBadRequest)
	}
}

// persistIPList snapshots the current full allow/deny list into the
// config store so the change survives a restart. Failure is logged via
// the audit log but doesn't fail the request — the in-memory mutation
// already happened.
func (s *APIServer) persistIPList(key string, current func() []decision.IPListEntry) {
	if s.configStore == nil {
		return
	}
	if err := s.configStore.Save(key, current()); err != nil {
		s.auditLogger.LogSystemEvent("CONFIG_PERSIST_ERROR", key+": "+err.Error())
	}
}

// ============================================================================
// Configuration Management Handlers
// ============================================================================

func (s *APIServer) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Get current configuration
		decisionConfig := s.decisionEngine.GetConfig()
		rateLimitConfig := s.rateLimiter.GetConfig()

		writeJSON(w, map[string]interface{}{
			"decision": map[string]interface{}{
				"block_threshold":     decisionConfig.BlockThreshold,
				"challenge_threshold": decisionConfig.ChallengeThreshold,
				"bypass_paths":        s.decisionEngine.GetBypassPaths(),
			},
			"rate_limit": map[string]interface{}{
				"requests_per_min": rateLimitConfig.RequestsPerMin,
				"burst_size":       rateLimitConfig.BurstSize,
				"endpoint_limits":  rateLimitConfig.EndpointLimits,
			},
		})

	case http.MethodPost:
		// Update configuration
		var req struct {
			Decision struct {
				BlockThreshold     float64  `json:"block_threshold"`
				ChallengeThreshold float64  `json:"challenge_threshold"`
				BypassPaths        []string `json:"bypass_paths"`
			} `json:"decision"`
			RateLimit struct {
				RequestsPerMin int                              `json:"requests_per_min"`
				BurstSize      int                              `json:"burst_size"`
				EndpointLimits map[string]ratelimit.LimitConfig `json:"endpoint_limits"`
			} `json:"rate_limit"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Invalid request format",
				"error":   err.Error(),
			})
			return
		}

		// Validate values
		if req.Decision.BlockThreshold < 0 || req.Decision.BlockThreshold > 100 {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Block threshold must be between 0 and 100",
			})
			return
		}
		if req.Decision.ChallengeThreshold < 0 || req.Decision.ChallengeThreshold > 100 {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Challenge threshold must be between 0 and 100",
			})
			return
		}
		if req.Decision.ChallengeThreshold >= req.Decision.BlockThreshold {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Challenge threshold must be less than block threshold",
			})
			return
		}
		if req.RateLimit.RequestsPerMin < 1 || req.RateLimit.RequestsPerMin > 10000 {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Requests per minute must be between 1 and 10000",
			})
			return
		}
		if req.RateLimit.BurstSize < 1 || req.RateLimit.BurstSize > 1000 {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Burst size must be between 1 and 1000",
			})
			return
		}

		// Update decision engine config
		decisionConfig := s.decisionEngine.GetConfig()
		if req.Decision.BlockThreshold > 0 {
			decisionConfig.BlockThreshold = req.Decision.BlockThreshold
		}
		if req.Decision.ChallengeThreshold > 0 {
			decisionConfig.ChallengeThreshold = req.Decision.ChallengeThreshold
		}
		s.decisionEngine.SetConfig(decisionConfig)

		// Replace user-configured bypass prefixes whenever the field is
		// present in the request — empty array clears the list.
		if req.Decision.BypassPaths != nil {
			s.decisionEngine.SetBypassPaths(req.Decision.BypassPaths)
		}

		// Update rate limiter config
		rateLimitConfig := s.rateLimiter.GetConfig()
		if req.RateLimit.RequestsPerMin > 0 {
			rateLimitConfig.RequestsPerMin = req.RateLimit.RequestsPerMin
		}
		if req.RateLimit.BurstSize > 0 {
			rateLimitConfig.BurstSize = req.RateLimit.BurstSize
		}
		if req.RateLimit.EndpointLimits != nil {
			rateLimitConfig.EndpointLimits = req.RateLimit.EndpointLimits
		}
		s.rateLimiter.SetConfig(rateLimitConfig)

		// Log the change
		s.auditLogger.LogSystemEvent("CONFIG_CHANGE",
			fmt.Sprintf("Configuration updated - Block: %.1f, Challenge: %.1f, RPM: %d, Burst: %d",
				req.Decision.BlockThreshold, req.Decision.ChallengeThreshold,
				req.RateLimit.RequestsPerMin, req.RateLimit.BurstSize))

		// Persist to DB so changes survive a restart. Failure is non-fatal —
		// the in-memory update has already been applied.
		if s.configStore != nil {
			if err := s.configStore.Save("decision", map[string]interface{}{
				"block_threshold":     decisionConfig.BlockThreshold,
				"challenge_threshold": decisionConfig.ChallengeThreshold,
				"bypass_paths":        s.decisionEngine.GetBypassPaths(),
			}); err != nil {
				s.auditLogger.LogSystemEvent("CONFIG_PERSIST_ERROR", "decision: "+err.Error())
			}
			if err := s.configStore.Save("rate_limit", map[string]interface{}{
				"requests_per_min": rateLimitConfig.RequestsPerMin,
				"burst_size":       rateLimitConfig.BurstSize,
				"endpoint_limits":  rateLimitConfig.EndpointLimits,
			}); err != nil {
				s.auditLogger.LogSystemEvent("CONFIG_PERSIST_ERROR", "rate_limit: "+err.Error())
			}
		}

		writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Configuration updated successfully",
			"config": map[string]interface{}{
				"decision": map[string]interface{}{
					"block_threshold":     decisionConfig.BlockThreshold,
					"challenge_threshold": decisionConfig.ChallengeThreshold,
					"bypass_paths":        s.decisionEngine.GetBypassPaths(),
				},
				"rate_limit": map[string]interface{}{
					"requests_per_min": rateLimitConfig.RequestsPerMin,
					"burst_size":       rateLimitConfig.BurstSize,
				},
			},
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// Backend Configuration Handlers
// ============================================================================

func (s *APIServer) handleBackend(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// Get current backend
		if s.wafMiddleware == nil {
			writeJSON(w, map[string]interface{}{
				"backend": "unknown",
				"error":   "WAF middleware not initialized",
			})
			return
		}
		writeJSON(w, map[string]interface{}{
			"backend": s.wafMiddleware.GetBackend(),
		})

	case http.MethodPost:
		// Update backend
		var req struct {
			BackendURL string `json:"backend_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Invalid request format",
				"error":   err.Error(),
			})
			return
		}

		if s.wafMiddleware == nil {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "WAF middleware not initialized",
			})
			return
		}

		// Validate and update backend
		if err := s.wafMiddleware.UpdateBackend(req.BackendURL); err != nil {
			writeJSON(w, map[string]interface{}{
				"success": false,
				"message": "Failed to update backend",
				"error":   err.Error(),
			})
			return
		}

		// Log the change
		s.auditLogger.LogSystemEvent("CONFIG_CHANGE",
			fmt.Sprintf("Backend URL updated to: %s", req.BackendURL))

		// Persist so the backend stays put across restarts.
		if s.configStore != nil {
			if err := s.configStore.Save("backend", map[string]interface{}{
				"url": req.BackendURL,
			}); err != nil {
				s.auditLogger.LogSystemEvent("CONFIG_PERSIST_ERROR", "backend: "+err.Error())
			}
		}

		writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Backend updated successfully",
			"backend": req.BackendURL,
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ============================================================================
// Helper Functions
// ============================================================================

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	json.NewEncoder(w).Encode(data)
}

// ============================================================================
// Rule single-get + single-save (used by the in-browser Rule Builder)
// ============================================================================

// handleRuleGet — GET /waf-api/rules/get/<id>
// Returns the full Rule object as JSON (v2 schema).
func (s *APIServer) handleRuleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/waf-api/rules/get/")
	id = strings.TrimSpace(id)
	if id == "" {
		writeJSON(w, map[string]interface{}{"error": "rule id required"})
		return
	}
	data, ok := s.ruleEngine.GetRuleJSON(id)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		writeJSON(w, map[string]interface{}{"error": "rule not found", "id": id})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_, _ = w.Write(data)
}

// handleRuleSave — POST /waf-api/rules/save
// Body: { "rule": { <full rule JSON v2> } }
// Adds the rule (or replaces by ID) and persists to disk.
// Designed for the in-browser Rule Builder so each save touches only one rule
// rather than wiping the whole ruleset (as /upload does).
func (s *APIServer) handleRuleSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Rule json.RawMessage `json:"rule"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Rule) == 0 {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Body must be {\"rule\": {...}}",
			Errors:  []string{"invalid request body"},
		})
		return
	}

	// Validate the single rule by wrapping in an array.
	wrapped := append([]byte("["), body.Rule...)
	wrapped = append(wrapped, ']')
	if _, err := s.ruleEngine.ValidateRulesJSON(wrapped); err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Rule validation failed",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Load existing rules file, replace/add by ID, write back, then hot-reload.
	rulesPath := "configs/rules/all_rules.json"
	existing, err := os.ReadFile(rulesPath)
	if err != nil {
		// Start with empty array if file missing.
		existing = []byte("[]")
	}
	var existingArr []json.RawMessage
	if err := json.Unmarshal(existing, &existingArr); err != nil {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "Existing rules file is not a JSON array",
			Errors:  []string{err.Error()},
		})
		return
	}

	// Find ID of the new rule.
	var meta struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body.Rule, &meta)
	if meta.ID == "" {
		writeJSON(w, UploadResponse{Success: false, Message: "rule.id is required"})
		return
	}

	// Replace or append.
	replaced := false
	for i, raw := range existingArr {
		var m struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(raw, &m); err == nil && m.ID == meta.ID {
			existingArr[i] = body.Rule
			replaced = true
			break
		}
	}
	if !replaced {
		existingArr = append(existingArr, body.Rule)
	}

	// Backup current file.
	backupPath := ""
	if len(existing) > 2 {
		timestamp := time.Now().Format("20060102_150405")
		backupPath = fmt.Sprintf("configs/rules/backups/all_rules_%s.json", timestamp)
		_ = os.MkdirAll("configs/rules/backups", 0o755)
		_ = os.WriteFile(backupPath, existing, 0o644)
	}

	out, err := json.MarshalIndent(existingArr, "", "  ")
	if err != nil {
		writeJSON(w, UploadResponse{Success: false, Message: "marshal failed", Errors: []string{err.Error()}})
		return
	}

	if err := os.WriteFile(rulesPath, out, 0o644); err != nil {
		writeJSON(w, UploadResponse{Success: false, Message: "failed to write rules file", Errors: []string{err.Error()}})
		return
	}

	if err := s.ruleEngine.ReloadRules(out); err != nil {
		writeJSON(w, UploadResponse{Success: false, Message: "hot-reload failed", Errors: []string{err.Error()}})
		return
	}

	action := "added"
	if replaced {
		action = "updated"
	}
	writeJSON(w, UploadResponse{
		Success:     true,
		Message:     fmt.Sprintf("Rule %q %s", meta.ID, action),
		RulesLoaded: s.ruleEngine.RuleCount(),
		BackupPath:  backupPath,
	})
}
