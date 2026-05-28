// internal/behavior/detector.go
package behavior

import (
	"sync"
	"time"

	"waf-project/internal/engine"
)

// Detector performs behavior-based analysis and threat detection
type Detector struct {
	ipStats       map[string]*ipStatistics
	sessionStats  map[string]*sessionStatistics
	pathStats     map[string]*pathStatistics
	mu            sync.RWMutex
	config        BehaviorConfig
	cleanupTicker *time.Ticker
	stopCleanup   chan bool
}

// BehaviorConfig defines behavior detection configuration
type BehaviorConfig struct {
	// Bruteforce detection
	BruteForceThreshold int           // Failed attempts before blocking
	BruteForceWindow    time.Duration // Time window for counting attempts

	// Bot detection
	BotDetectionEnabled bool
	BotScoreThreshold   float64

	// Session anomaly
	SessionEnabled   bool
	MaxSessionsPerIP int
	SessionDuration  time.Duration

	// Velocity checks
	VelocityEnabled      bool
	MaxRequestsPerSecond int

	// Cleanup
	CleanupInterval time.Duration
}

// ipStatistics tracks statistics for a single IP address
type ipStatistics struct {
	// Bruteforce tracking
	failedAttempts     int
	successfulAttempts int
	lastAttempt        time.Time
	firstAttempt       time.Time
	isBlocked          bool
	blockedUntil       time.Time

	// Request patterns
	totalRequests     int
	uniquePaths       map[string]bool
	uniqueUserAgents  map[string]bool
	requestTimestamps []time.Time

	// Anomaly indicators
	suspicionScore float64
	isSuspicious   bool
	isBot          bool

	// Attack categories detected
	detectedAttacks map[string]int
}

// sessionStatistics tracks session-level statistics
type sessionStatistics struct {
	sessionID       string
	ipAddress       string
	userAgent       string
	createdAt       time.Time
	lastActivity    time.Time
	requestCount    int
	failedRequests  int
	blockedRequests int
}

// pathStatistics tracks access patterns for specific paths
type pathStatistics struct {
	path           string
	totalAccess    int
	uniqueIPs      map[string]bool
	failedAttempts int
	lastAccess     time.Time
}

// NewDetector creates a new behavior detector
func NewDetector(config BehaviorConfig) *Detector {
	// Set defaults
	if config.BruteForceThreshold == 0 {
		config.BruteForceThreshold = 5
	}
	if config.BruteForceWindow == 0 {
		config.BruteForceWindow = 5 * time.Minute
	}
	if config.BotScoreThreshold == 0 {
		config.BotScoreThreshold = 0.7
	}
	if config.MaxSessionsPerIP == 0 {
		config.MaxSessionsPerIP = 5
	}
	if config.MaxRequestsPerSecond == 0 {
		config.MaxRequestsPerSecond = 10
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 10 * time.Minute
	}

	d := &Detector{
		ipStats:      make(map[string]*ipStatistics),
		sessionStats: make(map[string]*sessionStatistics),
		pathStats:    make(map[string]*pathStatistics),
		config:       config,
		stopCleanup:  make(chan bool),
	}

	// Start cleanup goroutine
	d.startCleanup()

	return d
}

// Analyze performs behavior analysis on a request
func (d *Detector) Analyze(req *engine.ParsedRequest, evalResult *engine.EvaluationResult) *BehaviorResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	clientIP := req.ClientIP

	// Get or create IP statistics
	stats, exists := d.ipStats[clientIP]
	if !exists {
		stats = &ipStatistics{
			firstAttempt:      now,
			uniquePaths:       make(map[string]bool),
			uniqueUserAgents:  make(map[string]bool),
			requestTimestamps: make([]time.Time, 0),
			detectedAttacks:   make(map[string]int),
		}
		d.ipStats[clientIP] = stats
	}

	// Update basic stats
	stats.totalRequests++
	stats.lastAttempt = now
	stats.uniquePaths[req.NormalizedPath] = true
	stats.uniqueUserAgents[req.UserAgent] = true
	stats.requestTimestamps = append(stats.requestTimestamps, now)

	// Track attack categories
	for _, match := range evalResult.MatchedRules {
		stats.detectedAttacks[match.Category]++
	}

	result := &BehaviorResult{
		ClientIP:        clientIP,
		Timestamp:       now,
		ThreatDetected:  false,
		ThreatTypes:     make([]string, 0),
		SuspicionScore:  0.0,
		RecommendAction: "ALLOW",
	}

	// Check if already blocked
	if stats.isBlocked && now.Before(stats.blockedUntil) {
		result.ThreatDetected = true
		result.ThreatTypes = append(result.ThreatTypes, "TEMPORARILY_BLOCKED")
		result.RecommendAction = "BLOCK"
		return result
	} else if stats.isBlocked && now.After(stats.blockedUntil) {
		// Unblock after timeout
		stats.isBlocked = false
		stats.failedAttempts = 0
	}

	// Run detection checks
	d.checkBruteForce(stats, evalResult, result)

	if d.config.BotDetectionEnabled {
		d.checkBotBehavior(stats, req, result)
	}

	if d.config.VelocityEnabled {
		d.checkVelocity(stats, result)
	}

	// Check for attack pattern repetition
	d.checkAttackPatterns(stats, result)

	// Update path statistics
	d.updatePathStats(req.NormalizedPath, clientIP, evalResult.Decision == "BLOCK")

	// Calculate final suspicion score
	stats.suspicionScore = result.SuspicionScore
	stats.isSuspicious = result.SuspicionScore > 0.5

	return result
}

// checkBruteForce detects bruteforce attempts
func (d *Detector) checkBruteForce(stats *ipStatistics, evalResult *engine.EvaluationResult, result *BehaviorResult) {
	now := time.Now()

	// Check if request was blocked (indicates attack attempt)
	if evalResult.Decision == "BLOCK" {
		stats.failedAttempts++
	} else {
		stats.successfulAttempts++
	}

	// Check if within bruteforce window
	if now.Sub(stats.firstAttempt) <= d.config.BruteForceWindow {
		if stats.failedAttempts >= d.config.BruteForceThreshold {
			result.ThreatDetected = true
			result.ThreatTypes = append(result.ThreatTypes, "BRUTEFORCE")
			result.SuspicionScore += 0.4
			result.RecommendAction = "BLOCK"

			// Block IP temporarily
			stats.isBlocked = true
			stats.blockedUntil = now.Add(10 * time.Minute)
		}
	} else {
		// Reset counter if outside window
		stats.failedAttempts = 0
		stats.firstAttempt = now
	}

	// Add suspicion for high fail rate
	if stats.totalRequests > 10 {
		failRate := float64(stats.failedAttempts) / float64(stats.totalRequests)
		if failRate > 0.5 {
			result.SuspicionScore += 0.2
		}
	}
}

// checkBotBehavior detects automated bot activity
func (d *Detector) checkBotBehavior(stats *ipStatistics, req *engine.ParsedRequest, result *BehaviorResult) {
	botScore := 0.0

	// Check 1: Missing or suspicious User-Agent
	ua := req.UserAgent
	if ua == "" {
		botScore += 0.3
	} else if d.isSuspiciousUserAgent(ua) {
		botScore += 0.4
		result.ThreatTypes = append(result.ThreatTypes, "SCANNER_TOOL")
	}

	// Check 2: Too many different paths in short time
	if len(stats.uniquePaths) > 50 && stats.totalRequests < 100 {
		botScore += 0.2
	}

	// Check 3: Regular timing patterns (too consistent)
	if d.hasRegularPattern(stats.requestTimestamps) {
		botScore += 0.2
	}

	// Check 4: Only one User-Agent but many requests
	if len(stats.uniqueUserAgents) == 1 && stats.totalRequests > 100 {
		botScore += 0.1
	}

	if botScore >= d.config.BotScoreThreshold {
		result.ThreatDetected = true
		result.ThreatTypes = append(result.ThreatTypes, "AUTOMATED_BOT")
		result.SuspicionScore += botScore
		stats.isBot = true
	}
}

// checkVelocity detects abnormally high request velocity
func (d *Detector) checkVelocity(stats *ipStatistics, result *BehaviorResult) {
	now := time.Now()
	oneSecondAgo := now.Add(-1 * time.Second)

	// Count requests in last second
	recentRequests := 0
	for i := len(stats.requestTimestamps) - 1; i >= 0; i-- {
		if stats.requestTimestamps[i].After(oneSecondAgo) {
			recentRequests++
		} else {
			break
		}
	}

	if recentRequests > d.config.MaxRequestsPerSecond {
		result.ThreatDetected = true
		result.ThreatTypes = append(result.ThreatTypes, "HIGH_VELOCITY")
		result.SuspicionScore += 0.3
		result.RecommendAction = "CHALLENGE"
	}
}

// checkAttackPatterns looks for repeated attack patterns
func (d *Detector) checkAttackPatterns(stats *ipStatistics, result *BehaviorResult) {
	// Check if same attack type triggered multiple times
	for category, count := range stats.detectedAttacks {
		if count >= 3 {
			result.ThreatDetected = true
			result.ThreatTypes = append(result.ThreatTypes, "REPEATED_"+category)
			result.SuspicionScore += 0.2
		}
	}
}

// updatePathStats updates statistics for a specific path
func (d *Detector) updatePathStats(path, clientIP string, wasBlocked bool) {
	stats, exists := d.pathStats[path]
	if !exists {
		stats = &pathStatistics{
			path:      path,
			uniqueIPs: make(map[string]bool),
		}
		d.pathStats[path] = stats
	}

	stats.totalAccess++
	stats.uniqueIPs[clientIP] = true
	stats.lastAccess = time.Now()

	if wasBlocked {
		stats.failedAttempts++
	}
}

// isSuspiciousUserAgent checks for known scanner/tool user agents
func (d *Detector) isSuspiciousUserAgent(ua string) bool {
	suspiciousPatterns := []string{
		"sqlmap", "nikto", "nmap", "masscan", "nessus", "openvas",
		"acunetix", "burp", "zgrab", "python-requests", "curl", "wget",
		"scanner", "bot", "crawler", "spider",
	}

	uaLower := ua
	for _, pattern := range suspiciousPatterns {
		if contains(uaLower, pattern) {
			return true
		}
	}
	return false
}

// hasRegularPattern detects too-consistent timing (bot indicator)
func (d *Detector) hasRegularPattern(timestamps []time.Time) bool {
	if len(timestamps) < 10 {
		return false
	}

	// Check last 10 timestamps
	intervals := make([]time.Duration, 0)
	start := len(timestamps) - 10
	for i := start; i < len(timestamps)-1; i++ {
		interval := timestamps[i+1].Sub(timestamps[i])
		intervals = append(intervals, interval)
	}

	// Calculate variance
	var sum time.Duration
	for _, interval := range intervals {
		sum += interval
	}
	avg := sum / time.Duration(len(intervals))

	variance := 0.0
	for _, interval := range intervals {
		diff := float64(interval - avg)
		variance += diff * diff
	}
	variance /= float64(len(intervals))

	// If variance is very low, timing is too regular (bot-like)
	return variance < 1000000000 // Less than 1 second variance
}

// GetIPStats returns statistics for a specific IP
func (d *Detector) GetIPStats(clientIP string) *IPStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats, exists := d.ipStats[clientIP]
	if !exists {
		return nil
	}

	return &IPStats{
		ClientIP:            clientIP,
		TotalRequests:       stats.totalRequests,
		FailedAttempts:      stats.failedAttempts,
		SuccessfulAttempts:  stats.successfulAttempts,
		UniquePathsAccessed: len(stats.uniquePaths),
		IsBlocked:           stats.isBlocked,
		BlockedUntil:        stats.blockedUntil,
		SuspicionScore:      stats.suspicionScore,
		IsSuspicious:        stats.isSuspicious,
		IsBot:               stats.isBot,
		DetectedAttacks:     stats.detectedAttacks,
		FirstSeen:           stats.firstAttempt,
		LastSeen:            stats.lastAttempt,
	}
}

// GetSuspiciousIPs returns all IPs with high suspicion scores
func (d *Detector) GetSuspiciousIPs() []*IPStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	suspicious := make([]*IPStats, 0)
	for ip, stats := range d.ipStats {
		if stats.isSuspicious || stats.suspicionScore > 0.5 {
			suspicious = append(suspicious, &IPStats{
				ClientIP:        ip,
				TotalRequests:   stats.totalRequests,
				SuspicionScore:  stats.suspicionScore,
				IsSuspicious:    stats.isSuspicious,
				IsBot:           stats.isBot,
				DetectedAttacks: stats.detectedAttacks,
			})
		}
	}
	return suspicious
}

// GetBlockedIPs returns all currently blocked IPs
func (d *Detector) GetBlockedIPs() []*IPStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	blocked := make([]*IPStats, 0)
	now := time.Now()

	for ip, stats := range d.ipStats {
		if stats.isBlocked && now.Before(stats.blockedUntil) {
			blocked = append(blocked, &IPStats{
				ClientIP:     ip,
				IsBlocked:    true,
				BlockedUntil: stats.blockedUntil,
			})
		}
	}
	return blocked
}

// UnblockIP manually unblocks an IP address
func (d *Detector) UnblockIP(clientIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if stats, exists := d.ipStats[clientIP]; exists {
		stats.isBlocked = false
		stats.failedAttempts = 0
	}
}

// ResetIPStats clears statistics for an IP
func (d *Detector) ResetIPStats(clientIP string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.ipStats, clientIP)
}

// startCleanup starts background cleanup goroutine
func (d *Detector) startCleanup() {
	d.cleanupTicker = time.NewTicker(d.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-d.cleanupTicker.C:
				d.cleanup()
			case <-d.stopCleanup:
				d.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old statistics
func (d *Detector) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	cleanupThreshold := 30 * time.Minute

	// Cleanup old IP stats
	for ip, stats := range d.ipStats {
		if now.Sub(stats.lastAttempt) > cleanupThreshold && !stats.isBlocked {
			delete(d.ipStats, ip)
		}
	}

	// Cleanup old path stats
	for path, stats := range d.pathStats {
		if now.Sub(stats.lastAccess) > cleanupThreshold {
			delete(d.pathStats, path)
		}
	}
}

// Stop stops the detector and cleanup goroutine
func (d *Detector) Stop() {
	d.stopCleanup <- true
}

// ============================================================================
// Data Structures
// ============================================================================

// BehaviorResult contains the result of behavior analysis
type BehaviorResult struct {
	ClientIP        string
	Timestamp       time.Time
	ThreatDetected  bool
	ThreatTypes     []string
	SuspicionScore  float64
	RecommendAction string
}

// IPStats contains statistics for an IP address
type IPStats struct {
	ClientIP            string
	TotalRequests       int
	FailedAttempts      int
	SuccessfulAttempts  int
	UniquePathsAccessed int
	IsBlocked           bool
	BlockedUntil        time.Time
	SuspicionScore      float64
	IsSuspicious        bool
	IsBot               bool
	DetectedAttacks     map[string]int
	FirstSeen           time.Time
	LastSeen            time.Time
}

// ============================================================================
// Helper Functions
// ============================================================================

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
