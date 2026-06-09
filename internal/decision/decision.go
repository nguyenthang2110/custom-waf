// internal/decision/decision.go
package decision

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"waf-project/internal/behavior"
	"waf-project/internal/engine"
)

// DecisionEngine makes final decisions about request handling.
//
// Whitelist / blacklist entries are tracked as (ip → expires_at).
// A zero time means "permanent" — never expires. Anything else is an
// expiry timestamp; expired entries are filtered out of every lookup
// and pruned by a background goroutine (Run via PruneExpired in startup).
type DecisionEngine struct {
	config         DecisionConfig
	whitelistIPs   map[string]time.Time // value zero = permanent
	blacklistIPs   map[string]time.Time // value zero = permanent
	whitelistPaths map[string]bool
	mu             sync.RWMutex

	// Statistics
	stats *DecisionStats
}

// IPListEntry is a single whitelist/blacklist record carrying an
// optional expiry. ExpiresAt zero means permanent.
//
// MarshalJSON below ensures permanent entries serialize with no
// expires_at key at all (Go's struct-tag omitempty doesn't trigger for
// non-pointer time.Time zero values).
type IPListEntry struct {
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"-"`
}

// MarshalJSON emits {"ip":..., "expires_at":...} only when ExpiresAt is
// non-zero; permanent entries collapse to {"ip":...} so the dashboard
// can use a simple falsy check.
func (e IPListEntry) MarshalJSON() ([]byte, error) {
	if e.ExpiresAt.IsZero() {
		return json.Marshal(struct {
			IP string `json:"ip"`
		}{IP: e.IP})
	}
	return json.Marshal(struct {
		IP        string `json:"ip"`
		ExpiresAt string `json:"expires_at"`
	}{IP: e.IP, ExpiresAt: e.ExpiresAt.Format(time.RFC3339)})
}

// UnmarshalJSON accepts either v1 (no expires_at) or v2 (with expires_at)
// payloads. Errors out only if `ip` is missing or unparseable.
func (e *IPListEntry) UnmarshalJSON(data []byte) error {
	var raw struct {
		IP        string `json:"ip"`
		ExpiresAt string `json:"expires_at,omitempty"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	e.IP = raw.IP
	if raw.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, raw.ExpiresAt)
		if err != nil {
			return err
		}
		e.ExpiresAt = t
	}
	return nil
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

	// User-configurable list of path prefixes that bypass WAF inspection
	// AND audit logging. Joined with the built-in IsRealtimePath /
	// IsHealthCheckPath lists. Useful for noisy app-specific endpoints
	// (heartbeats, internal polling) you want to silence at runtime.
	BypassPathPrefixes []string
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
		whitelistIPs:   make(map[string]time.Time),
		blacklistIPs:   make(map[string]time.Time),
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
			// Capture the original decision BEFORE overwriting, otherwise
			// the stat-adjust branches below would all compare against
			// "BLOCK" and never decrement the original counter — the
			// previous version inflated AllowCount/ChallengeCount whenever
			// behavior detection escalated a request to BLOCK.
			origDecision := result.Decision

			result.Decision = "BLOCK"
			result.Reason = "Overridden by behavior detection: " +
				de.formatThreatTypes(behaviorResult.ThreatTypes)
			result.ResponseCode = 403

			de.updateStats(func() {
				switch origDecision {
				case "ALLOW":
					de.stats.AllowCount--
				case "CHALLENGE":
					de.stats.ChallengeCount--
				case "LOG":
					de.stats.LogCount--
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

// entryActive reports whether a map value (interpreted as expires_at)
// is still in effect: zero time means permanent, anything else must be
// strictly in the future. Used by every isWhitelisted/isBlacklisted
// lookup so expired entries simply stop matching without needing the
// pruner to have run yet.
func entryActive(exp time.Time) bool {
	return exp.IsZero() || time.Now().Before(exp)
}

// isWhitelisted checks if IP or path is whitelisted
func (de *DecisionEngine) isWhitelisted(ip, path string) bool {
	if exp, ok := de.whitelistIPs[ip]; ok && entryActive(exp) {
		return true
	}
	if de.whitelistPaths[path] {
		return true
	}
	return false
}

// isBlacklisted checks if IP is blacklisted
func (de *DecisionEngine) isBlacklisted(ip string) bool {
	exp, ok := de.blacklistIPs[ip]
	return ok && entryActive(exp)
}

// AddWhitelistIP adds an IP to whitelist permanently (no expiry).
func (de *DecisionEngine) AddWhitelistIP(ip string) {
	de.AddWhitelistIPWithTTL(ip, 0)
}

// AddWhitelistIPWithTTL adds an IP to whitelist with optional TTL.
// ttl <= 0 → permanent. ttl > 0 → expires_at = now + ttl.
func (de *DecisionEngine) AddWhitelistIPWithTTL(ip string, ttl time.Duration) {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	de.mu.Lock()
	defer de.mu.Unlock()
	de.whitelistIPs[ip] = exp
}

// RemoveWhitelistIP removes an IP from whitelist
func (de *DecisionEngine) RemoveWhitelistIP(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	delete(de.whitelistIPs, ip)
}

// AddBlacklistIP adds an IP to blacklist permanently (no expiry).
func (de *DecisionEngine) AddBlacklistIP(ip string) {
	de.AddBlacklistIPWithTTL(ip, 0)
}

// AddBlacklistIPWithTTL adds an IP to blacklist with optional TTL.
// ttl <= 0 → permanent. ttl > 0 → expires_at = now + ttl.
func (de *DecisionEngine) AddBlacklistIPWithTTL(ip string, ttl time.Duration) {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	de.mu.Lock()
	defer de.mu.Unlock()
	de.blacklistIPs[ip] = exp
}

// RemoveBlacklistIP removes an IP from blacklist
func (de *DecisionEngine) RemoveBlacklistIP(ip string) {
	de.mu.Lock()
	defer de.mu.Unlock()
	delete(de.blacklistIPs, ip)
}

// PruneExpiredIPs removes whitelist/blacklist entries whose expires_at
// has passed. Returns (whitelistRemoved, blacklistRemoved) so a periodic
// caller can log activity. Safe to call concurrently with lookups.
func (de *DecisionEngine) PruneExpiredIPs() (int, int) {
	now := time.Now()
	de.mu.Lock()
	defer de.mu.Unlock()
	wl := 0
	for ip, exp := range de.whitelistIPs {
		if !exp.IsZero() && !now.Before(exp) {
			delete(de.whitelistIPs, ip)
			wl++
		}
	}
	bl := 0
	for ip, exp := range de.blacklistIPs {
		if !exp.IsZero() && !now.Before(exp) {
			delete(de.blacklistIPs, ip)
			bl++
		}
	}
	return wl, bl
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

// GetWhitelistIPs returns all currently-active whitelisted IPs as a
// flat string slice. Expired entries are filtered out.
func (de *DecisionEngine) GetWhitelistIPs() []string {
	return activeIPsOnly(de, de.whitelistIPs)
}

// GetBlacklistIPs returns all currently-active blacklisted IPs as a
// flat string slice. Expired entries are filtered out.
func (de *DecisionEngine) GetBlacklistIPs() []string {
	return activeIPsOnly(de, de.blacklistIPs)
}

// GetWhitelistEntries returns whitelist entries with their (possibly
// zero) expiry. Used by the dashboard to render the "expires in" column
// alongside each IP. Expired entries are omitted from the response.
func (de *DecisionEngine) GetWhitelistEntries() []IPListEntry {
	return activeEntriesOnly(de, de.whitelistIPs)
}

// GetBlacklistEntries returns blacklist entries with their (possibly
// zero) expiry. Expired entries are omitted from the response.
func (de *DecisionEngine) GetBlacklistEntries() []IPListEntry {
	return activeEntriesOnly(de, de.blacklistIPs)
}

func activeIPsOnly(de *DecisionEngine, m map[string]time.Time) []string {
	de.mu.RLock()
	defer de.mu.RUnlock()
	out := make([]string, 0, len(m))
	for ip, exp := range m {
		if entryActive(exp) {
			out = append(out, ip)
		}
	}
	return out
}

func activeEntriesOnly(de *DecisionEngine, m map[string]time.Time) []IPListEntry {
	de.mu.RLock()
	defer de.mu.RUnlock()
	out := make([]IPListEntry, 0, len(m))
	for ip, exp := range m {
		if entryActive(exp) {
			out = append(out, IPListEntry{IP: ip, ExpiresAt: exp})
		}
	}
	return out
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

// ShouldBypassWAF reports whether the request should skip the full
// pipeline silently. It's a thin wrapper over BypassReason.
//
// Bypass means "as if the WAF wasn't there" — no rule eval, no rate limit,
// no audit log. Reserved for paths that produce pure noise (health checks,
// websocket polling, app-specific heartbeats). For *trusted* IPs the
// dashboard manages an allow-list — see IsWhitelistedIP — which auto-allows
// but still logs the request so operators can see what happened.
func (de *DecisionEngine) ShouldBypassWAF(req *engine.ParsedRequest) bool {
	return de.BypassReason(req) != ""
}

// BypassReason returns a short string identifying why the request should
// skip the pipeline silently, or "" if the request should run the full
// flow. Reasons are path-based only — IP allow-listing is handled by
// IsWhitelistedIP (which logs).
//
// Returned reasons (stable — used as audit metadata keys):
//
//	""          — no bypass, run the full pipeline
//	"health"    — built-in health/dashboard/api-management path
//	"realtime"  — websocket / long-poll transport
//	"path"      — user-configured bypass prefix
//
// Blacklisted IPs are NEVER bypassed; this method returns "" for them so
// the request flows into the rule engine and gets explicitly blocked.
func (de *DecisionEngine) BypassReason(req *engine.ParsedRequest) string {
	if de.config.EnableBlacklist && de.isBlacklisted(req.ClientIP) {
		return ""
	}
	if de.IsHealthCheckPath(req.NormalizedPath) {
		return "health"
	}
	if de.IsRealtimePath(req.NormalizedPath) {
		return "realtime"
	}
	if de.matchesBypassPrefix(req.NormalizedPath) {
		return "path"
	}
	return ""
}

// IsWhitelistedIP reports whether the client IP is on the admin-managed
// allow-list. Whitelisted IPs short-circuit rule + rate-limit evaluation
// (the WAF auto-allows), but the request is still logged with decision
// "ALLOW" so operators can see the bypass happened. Returns false when
// whitelisting is disabled in config, even if the IP is in the map.
//
// Blacklist takes precedence: an IP on both lists is rejected.
func (de *DecisionEngine) IsWhitelistedIP(ip string) bool {
	if !de.config.EnableWhitelist {
		return false
	}
	if de.config.EnableBlacklist && de.isBlacklisted(ip) {
		return false
	}
	exp, ok := de.whitelistIPs[ip]
	return ok && entryActive(exp)
}

// matchesBypassPrefix returns true when path starts with any of the
// runtime-configurable bypass prefixes. The list is small in practice,
// so a linear scan is cheaper than building a trie.
func (de *DecisionEngine) matchesBypassPrefix(path string) bool {
	prefixes := de.config.BypassPathPrefixes
	for _, p := range prefixes {
		if p == "" {
			continue
		}
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// GetBypassPaths returns the user-configured bypass prefixes (excluding
// built-in lists) — used by the API for the dashboard.
func (de *DecisionEngine) GetBypassPaths() []string {
	de.mu.RLock()
	defer de.mu.RUnlock()
	out := make([]string, 0, len(de.config.BypassPathPrefixes))
	out = append(out, de.config.BypassPathPrefixes...)
	return out
}

// SetBypassPaths replaces the user-configured bypass prefix list. Empty
// strings are filtered out and entries are de-duplicated to keep the list
// tidy when the dashboard pushes the whole array on each edit.
func (de *DecisionEngine) SetBypassPaths(paths []string) {
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	de.mu.Lock()
	de.config.BypassPathPrefixes = out
	de.mu.Unlock()
}

// SetWhitelistIPs / SetBlacklistIPs replace the entire allow/deny set
// with permanent entries (no TTL). Used when restoring older persisted
// state at boot. Trims and de-duplicates so stray whitespace from the
// dashboard doesn't corrupt the in-memory map.
func (de *DecisionEngine) SetWhitelistIPs(ips []string) {
	out := make(map[string]time.Time, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			out[ip] = time.Time{} // permanent
		}
	}
	de.mu.Lock()
	de.whitelistIPs = out
	de.mu.Unlock()
}

func (de *DecisionEngine) SetBlacklistIPs(ips []string) {
	out := make(map[string]time.Time, len(ips))
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			out[ip] = time.Time{} // permanent
		}
	}
	de.mu.Lock()
	de.blacklistIPs = out
	de.mu.Unlock()
}

// SetWhitelistEntries / SetBlacklistEntries replace the entire list with
// TTL-aware entries — used when restoring v2+ persisted state at boot.
// Entries whose expires_at is already in the past at load time are
// silently dropped so a stale snapshot doesn't resurrect expired blocks.
func (de *DecisionEngine) SetWhitelistEntries(entries []IPListEntry) {
	out := make(map[string]time.Time, len(entries))
	now := time.Now()
	for _, e := range entries {
		ip := strings.TrimSpace(e.IP)
		if ip == "" {
			continue
		}
		if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
			continue
		}
		out[ip] = e.ExpiresAt
	}
	de.mu.Lock()
	de.whitelistIPs = out
	de.mu.Unlock()
}

func (de *DecisionEngine) SetBlacklistEntries(entries []IPListEntry) {
	out := make(map[string]time.Time, len(entries))
	now := time.Now()
	for _, e := range entries {
		ip := strings.TrimSpace(e.IP)
		if ip == "" {
			continue
		}
		if !e.ExpiresAt.IsZero() && !now.Before(e.ExpiresAt) {
			continue
		}
		out[ip] = e.ExpiresAt
	}
	de.mu.Lock()
	de.blacklistIPs = out
	de.mu.Unlock()
}
