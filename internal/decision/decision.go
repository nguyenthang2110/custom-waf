// internal/decision/decision.go
package decision

import (
	"strings"
	"sync"
	"time"

	"waf-project/internal/behavior"
	"waf-project/internal/engine"
)

// DecisionEngine makes final decisions about request handling
type DecisionEngine struct {
	config         DecisionConfig
	whitelistIPs   map[string]bool
	blacklistIPs   map[string]bool
	whitelistPaths map[string]bool
	mu             sync.RWMutex

	// Statistics
	stats *DecisionStats
}

// DecisionConfig defines decision engine configuration
type DecisionConfig struct {
	// Thresholds
	BlockThreshold     float64 // Score >= this → BLOCK
	ChallengeThreshold float64 // Score >= this → CHALLENGE
	LogThreshold       float64 // Score >= this → LOG

	// Default actions
	DefaultAction string // ALLOW, BLOCK, CHALLENGE

	// Behavior integration
	UseBehaviorScore    bool    // Consider behavior analysis
	BehaviorScoreWeight float64 // Weight for behavior score

	// Whitelist/Blacklist
	EnableWhitelist bool
	EnableBlacklist bool

	// Challenge settings
	ChallengeEnabled bool
	ChallengeTimeout time.Duration

	// Advanced features
	AdaptiveThreshold bool // Adjust threshold based on traffic
	GeoBlocking       bool // Block specific countries
	BlockedCountries  []string
}

// DecisionStats tracks decision statistics
type DecisionStats struct {
	TotalDecisions int64
	AllowCount     int64
	BlockCount     int64
	ChallengeCount int64
	LogCount       int64
	WhitelistHits  int64
	BlacklistHits  int64
	mu             sync.RWMutex
}

// DecisionResult contains the final decision
type DecisionResult struct {
	Decision        string                 // ALLOW, BLOCK, CHALLENGE, LOG
	Reason          string                 // Why this decision was made
	FinalScore      float64                // Combined score
	RuleScore       float64                // Score from rule engine
	BehaviorScore   float64                // Score from behavior analysis
	IsWhitelisted   bool                   // From whitelist
	IsBlacklisted   bool                   // From blacklist
	BlockDuration   time.Duration          // How long to block
	ChallengeType   string                 // Type of challenge to present
	ResponseCode    int                    // HTTP status code to return
	ResponseMessage string                 // Message to return
	Metadata        map[string]interface{} // Additional context
}

// NewDecisionEngine creates a new decision engine
func NewDecisionEngine(config DecisionConfig) *DecisionEngine {
	// Set defaults
	if config.BlockThreshold == 0 {
		config.BlockThreshold = 10.0
	}
	if config.ChallengeThreshold == 0 {
		config.ChallengeThreshold = 5.0
	}
	if config.LogThreshold == 0 {
		config.LogThreshold = 3.0
	}
	if config.DefaultAction == "" {
		config.DefaultAction = "ALLOW"
	}
	if config.BehaviorScoreWeight == 0 {
		config.BehaviorScoreWeight = 0.3 // 30% weight
	}
	if config.ChallengeTimeout == 0 {
		config.ChallengeTimeout = 5 * time.Minute
	}

	return &DecisionEngine{
		config:         config,
		whitelistIPs:   make(map[string]bool),
		blacklistIPs:   make(map[string]bool),
		whitelistPaths: make(map[string]bool),
		stats:          &DecisionStats{},
	}
}

// Decide makes the final decision on how to handle a request
func (de *DecisionEngine) Decide(evalResult *engine.EvaluationResult, req *engine.ParsedRequest) string {
	result := de.DecideWithDetails(evalResult, req, nil)
	return result.Decision
}

// DecideWithDetails makes a decision with full context and explanation
func (de *DecisionEngine) DecideWithDetails(
	evalResult *engine.EvaluationResult,
	req *engine.ParsedRequest,
	behaviorResult *behavior.BehaviorResult,
) *DecisionResult {

	de.mu.RLock()
	defer de.mu.RUnlock()

	result := &DecisionResult{
		Decision:     de.config.DefaultAction,
		RuleScore:    evalResult.TotalScore,
		ResponseCode: 200,
		Metadata:     make(map[string]interface{}),
	}

	// Update statistics
	de.updateStats(func() {
		de.stats.TotalDecisions++
	})

	// Step 1: Check blacklist (highest priority)
	if de.config.EnableBlacklist {
		isBlocked := de.isBlacklisted(req.ClientIP)

		if isBlocked {
			result.Decision = "BLOCK"
			result.Reason = "IP is blacklisted"
			result.IsBlacklisted = true
			result.ResponseCode = 403
			result.ResponseMessage = "Access Denied"
			// result.BlockDuration = 24 * time.Hour

			de.updateStats(func() {
				de.stats.BlacklistHits++
				de.stats.BlockCount++
			})
			return result
		}
	}

	// Step 2: Check whitelist (second highest priority)
	if de.config.EnableWhitelist && de.isWhitelisted(req.ClientIP, req.NormalizedPath) {
		result.Decision = "ALLOW"
		result.Reason = "IP or path is whitelisted"
		result.IsWhitelisted = true
		result.ResponseCode = 200

		de.updateStats(func() {
			de.stats.WhitelistHits++
			de.stats.AllowCount++
		})
		return result
	}

	// Step 3: Calculate combined score
	finalScore := evalResult.TotalScore

	// Add behavior score if available
	if behaviorResult != nil && de.config.UseBehaviorScore {
		behaviorScore := behaviorResult.SuspicionScore * 10.0 // Normalize to 0-10 scale
		finalScore += behaviorScore * de.config.BehaviorScoreWeight
		result.BehaviorScore = behaviorScore
	}

	result.FinalScore = finalScore

	// Step 4: Apply thresholds and make decision
	if finalScore >= de.config.BlockThreshold {
		result.Decision = "BLOCK"
		result.Reason = de.buildReason("Score exceeds block threshold", evalResult, behaviorResult)
		result.ResponseCode = 403
		result.ResponseMessage = "Request blocked by WAF"
		result.BlockDuration = de.calculateBlockDuration(finalScore)

		de.updateStats(func() {
			de.stats.BlockCount++
		})

	} else if finalScore >= de.config.ChallengeThreshold && de.config.ChallengeEnabled {
		result.Decision = "CHALLENGE"
		result.Reason = de.buildReason("Score exceeds challenge threshold", evalResult, behaviorResult)
		result.ResponseCode = 429
		result.ResponseMessage = "Please complete the challenge"
		result.ChallengeType = de.selectChallengeType(finalScore)

		de.updateStats(func() {
			de.stats.ChallengeCount++
		})

	} else if finalScore >= de.config.LogThreshold {
		result.Decision = "LOG"
		result.Reason = de.buildReason("Score exceeds log threshold", evalResult, behaviorResult)
		result.ResponseCode = 200

		de.updateStats(func() {
			de.stats.LogCount++
		})

	} else {
		result.Decision = "ALLOW"
		result.Reason = "Score below all thresholds"
		result.ResponseCode = 200

		de.updateStats(func() {
			de.stats.AllowCount++
		})
	}

	// Step 5: Override with behavior recommendation if critical
	if behaviorResult != nil && behaviorResult.ThreatDetected {
		if behaviorResult.RecommendAction == "BLOCK" && result.Decision != "BLOCK" {
			result.Decision = "BLOCK"
			result.Reason = "Overridden by behavior detection: " +
				de.formatThreatTypes(behaviorResult.ThreatTypes)
			result.ResponseCode = 403

			de.updateStats(func() {
				// Adjust stats
				if result.Decision == "ALLOW" {
					de.stats.AllowCount--
				} else if result.Decision == "CHALLENGE" {
					de.stats.ChallengeCount--
				}
				de.stats.BlockCount++
			})
		}
	}

	// Step 6: Apply geo-blocking if enabled
	if de.config.GeoBlocking {
		// TODO: Implement GeoIP lookup
		// if isBlockedCountry(req.ClientIP) {
		//     result.Decision = "BLOCK"
		//     result.Reason = "Geographic location blocked"
		// }
	}

	// Add metadata
	result.Metadata["matched_rules"] = len(evalResult.MatchedRules)
	result.Metadata["eval_time"] = evalResult.EvalTime.String()
	if behaviorResult != nil {
		result.Metadata["behavior_threats"] = behaviorResult.ThreatTypes
	}

	return result
}

// buildReason constructs a detailed reason for the decision
func (de *DecisionEngine) buildReason(
	baseReason string,
	evalResult *engine.EvaluationResult,
	behaviorResult *behavior.BehaviorResult,
) string {
	reason := baseReason

	// Add rule information
	if len(evalResult.MatchedRules) > 0 {
		reason += " (Rules: "
		for i, match := range evalResult.MatchedRules {
			if i > 0 {
				reason += ", "
			}
			reason += match.RuleID
			if i >= 2 { // Limit to first 3 rules
				reason += "..."
				break
			}
		}
		reason += ")"
	}

	// Add behavior information
	if behaviorResult != nil && len(behaviorResult.ThreatTypes) > 0 {
		reason += " [Threats: " + de.formatThreatTypes(behaviorResult.ThreatTypes) + "]"
	}

	return reason
}

// formatThreatTypes formats threat types into readable string
func (de *DecisionEngine) formatThreatTypes(threats []string) string {
	if len(threats) == 0 {
		return "none"
	}

	result := threats[0]
	for i := 1; i < len(threats) && i < 3; i++ {
		result += ", " + threats[i]
	}
	if len(threats) > 3 {
		result += "..."
	}
	return result
}

// calculateBlockDuration determines how long to block based on score
func (de *DecisionEngine) calculateBlockDuration(score float64) time.Duration {
	if score >= 20.0 {
		return 24 * time.Hour // Severe: 24 hours
	} else if score >= 15.0 {
		return 6 * time.Hour // High: 6 hours
	} else if score >= 12.0 {
		return 1 * time.Hour // Medium: 1 hour
	}
	return 15 * time.Minute // Low: 15 minutes
}

// selectChallengeType determines what type of challenge to present
func (de *DecisionEngine) selectChallengeType(score float64) string {
	if score >= 8.0 {
		return "CAPTCHA" // Hard challenge
	} else if score >= 6.0 {
		return "JS_CHALLENGE" // JavaScript proof-of-work
	}
	return "RATE_LIMIT" // Simple rate limit
}

// isWhitelisted checks if IP or path is whitelisted
func (de *DecisionEngine) isWhitelisted(ip, path string) bool {
	if de.whitelistIPs[ip] {
		return true
	}
	if de.whitelistPaths[path] {
		return true
	}
	return false
}

// isBlacklisted checks if IP is blacklisted
func (de *DecisionEngine) isBlacklisted(ip string) bool {
	return de.blacklistIPs[ip]
}

// AddWhitelistIP adds an IP to whitelist
func (de *DecisionEngine) AddWhitelistIP(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.whitelistIPs[ip] = true
}

// RemoveWhitelistIP removes an IP from whitelist
func (de *DecisionEngine) RemoveWhitelistIP(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	delete(de.whitelistIPs, ip)
}

// AddBlacklistIP adds an IP to blacklist
func (de *DecisionEngine) AddBlacklistIP(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.blacklistIPs[ip] = true
}

// RemoveBlacklistIP removes an IP from blacklist
func (de *DecisionEngine) RemoveBlacklistIP(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	delete(de.blacklistIPs, ip)
}

// AddWhitelistPath adds a path to whitelist
func (de *DecisionEngine) AddWhitelistPath(path string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.whitelistPaths[path] = true
}

// RemoveWhitelistPath removes a path from whitelist
func (de *DecisionEngine) RemoveWhitelistPath(path string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	delete(de.whitelistPaths, path)
}

// GetWhitelistIPs returns all whitelisted IPs
func (de *DecisionEngine) GetWhitelistIPs() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()

	ips := make([]string, 0, len(de.whitelistIPs))
	for ip := range de.whitelistIPs {
		ips = append(ips, ip)
	}
	return ips
}

// GetBlacklistIPs returns all blacklisted IPs
func (de *DecisionEngine) GetBlacklistIPs() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()

	ips := make([]string, 0, len(de.blacklistIPs))
	for ip := range de.blacklistIPs {
		ips = append(ips, ip)
	}
	return ips
}

// GetStats returns decision statistics
func (de *DecisionEngine) GetStats() *DecisionStats {
	de.stats.mu.RLock()
	defer de.stats.mu.RUnlock()

	return &DecisionStats{
		TotalDecisions: de.stats.TotalDecisions,
		AllowCount:     de.stats.AllowCount,
		BlockCount:     de.stats.BlockCount,
		ChallengeCount: de.stats.ChallengeCount,
		LogCount:       de.stats.LogCount,
		WhitelistHits:  de.stats.WhitelistHits,
		BlacklistHits:  de.stats.BlacklistHits,
	}
}

// GetBlockRate calculates the percentage of blocked requests
func (de *DecisionEngine) GetBlockRate() float64 {
	de.stats.mu.RLock()
	defer de.stats.mu.RUnlock()

	if de.stats.TotalDecisions == 0 {
		return 0.0
	}
	return float64(de.stats.BlockCount) / float64(de.stats.TotalDecisions) * 100
}

// ResetStats resets all statistics
func (de *DecisionEngine) ResetStats() {
	de.stats.mu.Lock()
	defer de.stats.mu.Unlock()

	de.stats.TotalDecisions = 0
	de.stats.AllowCount = 0
	de.stats.BlockCount = 0
	de.stats.ChallengeCount = 0
	de.stats.LogCount = 0
	de.stats.WhitelistHits = 0
	de.stats.BlacklistHits = 0
}

// SetConfig updates configuration dynamically
func (de *DecisionEngine) SetConfig(config DecisionConfig) {
	de.mu.Lock()
	defer de.mu.Unlock()
	de.config = config
}

// GetConfig returns current configuration
func (de *DecisionEngine) GetConfig() DecisionConfig {
	de.mu.RLock()
	defer de.mu.RUnlock()
	return de.config
}

// updateStats safely updates statistics
func (de *DecisionEngine) updateStats(fn func()) {
	de.stats.mu.Lock()
	defer de.stats.mu.Unlock()
	fn()
}

// AdjustThreshold dynamically adjusts threshold based on traffic
func (de *DecisionEngine) AdjustThreshold(blockRate float64) {
	if !de.config.AdaptiveThreshold {
		return
	}

	de.mu.Lock()
	defer de.mu.Unlock()

	// If block rate is too high, increase threshold (be more lenient)
	if blockRate > 10.0 {
		de.config.BlockThreshold *= 1.1
		de.config.ChallengeThreshold *= 1.1
	}
	// If block rate is too low, decrease threshold (be more strict)
	if blockRate < 1.0 {
		de.config.BlockThreshold *= 0.9
		de.config.ChallengeThreshold *= 0.9
	}

	// Keep thresholds within reasonable bounds
	if de.config.BlockThreshold < 5.0 {
		de.config.BlockThreshold = 5.0
	}
	if de.config.BlockThreshold > 20.0 {
		de.config.BlockThreshold = 20.0
	}
}

// IsHealthCheckPath checks if path is a health check / WAF infrastructure
// endpoint that should bypass rule evaluation. Note: "/api/" is intentionally
// NOT in this list — that prefix is the main upstream surface for many apps,
// and bypassing it lets every API attack through.
func (de *DecisionEngine) IsHealthCheckPath(path string) bool {
	healthCheckPaths := []string{
		"/health",
		"/healthz",
		"/health/check",
		"/ping",
		"/status",
		"/metrics",
		"/dashboard",  // WAF dashboard UI (static)
		"/waf-api/",   // WAF management API (auth-protected)
		"/login.html", // WAF auth pages
		"/register.html",
	}

	for _, hcp := range healthCheckPaths {
		if path == hcp || strings.HasPrefix(path, hcp) {
			return true
		}
	}
	return false
}

// IsRealtimePath returns true for paths used by long-poll / websocket
// transports that legitimate apps poll constantly. Inspecting them with
// the rule engine produces no security signal but generates large
// volumes of false positives and skews rate-limit counters.
func (de *DecisionEngine) IsRealtimePath(path string) bool {
	realtimePrefixes := []string{
		"/socket.io/",
		"/sockjs-node/",
		"/_ws/",
		"/ws/",
	}
	for _, p := range realtimePrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// ShouldBypassWAF determines if request should bypass WAF entirely.
// Bypassed requests skip rate-limit, rule evaluation, and behavior analysis.
// Blacklisted IPs are NEVER bypassed — admin-blacklisted addresses must be
// rejected even when targeting health/dashboard paths.
func (de *DecisionEngine) ShouldBypassWAF(req *engine.ParsedRequest) bool {
	if de.config.EnableBlacklist && de.isBlacklisted(req.ClientIP) {
		return false
	}

	// Bypass health checks
	if de.IsHealthCheckPath(req.NormalizedPath) {
		return true
	}

	// Bypass realtime/websocket transports (no inspectable payload,
	// pure noise for the rule engine and rate limiter).
	if de.IsRealtimePath(req.NormalizedPath) {
		return true
	}

	// Bypass whitelisted IPs
	if de.config.EnableWhitelist && de.whitelistIPs[req.ClientIP] {
		return true
	}

	return false
}
