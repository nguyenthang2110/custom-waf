// internal/api/handlers.go
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

	// Authentication fields
	userRepo    *models.UserRepository
	jwtManager  *auth.JWTManager
	bcryptCost  int
	requireAuth bool
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

// RegisterRoutes registers all API routes
func (s *APIServer) RegisterRoutes(mux *http.ServeMux) {
	// Public auth endpoints (login + register)
	mux.HandleFunc("/waf-api/auth/register", s.handleRegister)
	mux.HandleFunc("/waf-api/auth/login", s.handleLogin)
	mux.HandleFunc("/waf-api/auth/logout", s.handleLogout)

	// Authenticated user info (any logged-in user)
	mux.HandleFunc("/waf-api/auth/me", s.requireAuthN(s.handleGetCurrentUser))

	// Admin-only user management
	mux.HandleFunc("/waf-api/auth/users", s.requireAdmin(s.handleListUsers))

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

	// Rate limit endpoints
	mux.HandleFunc("/waf-api/ratelimit", s.handleRateLimit)

	// Whitelist/Blacklist — read public, mutate is admin-only
	mux.HandleFunc("/waf-api/whitelist", s.requireAdminForWrite(s.handleWhitelist))
	mux.HandleFunc("/waf-api/blacklist", s.requireAdminForWrite(s.handleBlacklist))

	// Backend configuration — write is admin-only
	mux.HandleFunc("/waf-api/backend", s.requireAdminForWrite(s.handleBackend))

	// WAF configuration — write is admin-only
	mux.HandleFunc("/waf-api/config", s.requireAdminForWrite(s.handleConfig))
}

// authContext holds the authenticated user identity extracted from a JWT.
type authContext struct {
	UserID   int
	Username string
	Role     string
}

// authenticate parses the Authorization header and returns the user, or nil
// if the request is unauthenticated. err is non-nil only when a token was
// provided but invalid (so the caller can short-circuit with 401).
func (s *APIServer) authenticate(r *http.Request) (*authContext, error) {
	if s.jwtManager == nil {
		return nil, nil
	}
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, nil
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, fmt.Errorf("invalid authorization header format")
	}
	claims, err := s.jwtManager.ValidateToken(parts[1])
	if err != nil {
		return nil, err
	}
	return &authContext{
		UserID:   claims.UserID,
		Username: claims.Username,
		Role:     claims.Role,
	}, nil
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

		logs = append(logs, LogEntry{
			Timestamp:      entry.Timestamp.Format(time.RFC3339),
			RequestID:      entry.RequestID,
			ClientIP:       entry.ClientIP,
			Method:         entry.Method,
			Path:           entry.Path,
			Decision:       entry.Decision,
			TotalScore:     entry.TotalScore,
			MatchedRules:   ruleMatches,
			ResponseStatus: entry.ResponseStatus,
			LatencyMs:      entry.LatencyMs,
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
}

func (s *APIServer) handleIPs(w http.ResponseWriter, r *http.Request) {
	// Get stats from metrics collector (Source of Truth for request counts)
	metricsStats := s.metricsCollector.GetStats()

	ips := make([]IPInfo, 0, len(metricsStats.Clients))
	for ip, clientStat := range metricsStats.Clients {
		// Get behavior info
		behaviorStats := s.behaviorDetector.GetIPStats(ip)

		attacks := make([]string, 0)
		suspicionScore := 0.0
		isSuspicious := false

		if behaviorStats != nil {
			suspicionScore = behaviorStats.SuspicionScore
			isSuspicious = behaviorStats.IsSuspicious
			for attack := range behaviorStats.DetectedAttacks {
				attacks = append(attacks, attack)
			}
		}

		// Check if blocked by rate limiter
		isBlocked := s.rateLimiter.IsClientBlocked(ip)

		ips = append(ips, IPInfo{
			IP:              ip,
			TotalRequests:   int(clientStat.TotalRequests),
			BlockedRequests: int(clientStat.TotalBlocked),
			LastSeen:        clientStat.LastSeen.Format(time.RFC3339),
			IsBlocked:       isBlocked,
			IsSuspicious:    isSuspicious,
			SuspicionScore:  suspicionScore,
			DetectedAttacks: attacks,
		})
	}

	// Sort by total requests desc
	sort.Slice(ips, func(i, j int) bool {
		return ips[i].TotalRequests > ips[j].TotalRequests
	})

	writeJSON(w, ips)
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

	// Check file extension
	if header.Filename[len(header.Filename)-5:] != ".json" {
		writeJSON(w, UploadResponse{
			Success: false,
			Message: "File must be a JSON file",
		})
		return
	}

	// Read file content
	fileData := make([]byte, header.Size)
	_, err = file.Read(fileData)
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
type ipMutationRequest struct {
	IP     string `json:"ip"`
	Action string `json:"action,omitempty"`
}

func (s *APIServer) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"ips": s.decisionEngine.GetWhitelistIPs()})
	case http.MethodPost, http.MethodDelete:
		s.mutateIPList(w, r, s.decisionEngine.AddWhitelistIP, s.decisionEngine.RemoveWhitelistIP)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) handleBlacklist(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{"ips": s.decisionEngine.GetBlacklistIPs()})
	case http.MethodPost, http.MethodDelete:
		s.mutateIPList(w, r, s.decisionEngine.AddBlacklistIP, s.decisionEngine.RemoveBlacklistIP)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *APIServer) mutateIPList(
	w http.ResponseWriter,
	r *http.Request,
	add func(string),
	remove func(string),
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
		add(req.IP)
		writeJSON(w, map[string]string{"status": "added", "ip": req.IP})
	case "remove", "delete":
		remove(req.IP)
		writeJSON(w, map[string]string{"status": "removed", "ip": req.IP})
	default:
		http.Error(w, "action must be add or remove", http.StatusBadRequest)
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
				BlockThreshold     float64 `json:"block_threshold"`
				ChallengeThreshold float64 `json:"challenge_threshold"`
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

		writeJSON(w, map[string]interface{}{
			"success": true,
			"message": "Configuration updated successfully",
			"config": map[string]interface{}{
				"decision": map[string]interface{}{
					"block_threshold":     decisionConfig.BlockThreshold,
					"challenge_threshold": decisionConfig.ChallengeThreshold,
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
