// internal/ratelimit/ratelimit.go
package ratelimit

import (
	"strings"
	"sync"
	"time"
)

// RateLimiter implements token bucket algorithm for rate limiting
type RateLimiter struct {
	clients         map[string]*clientBucket
	endpointBuckets map[string]map[string]*clientBucket // endpoint -> clientIP -> bucket
	routes          map[string]*routeBucket
	mu              sync.RWMutex
	config          RateLimitConfig
	cleanupTicker   *time.Ticker
	stopCleanup     chan bool
}

// RateLimitConfig defines rate limiting configuration.
//
// Behavior: rate limiting is OPT-IN per path. A request is only throttled
// when its route matches an entry in EndpointLimits — either by exact
// path or by subtree-prefix (entries ending in "/", same convention as
// http.ServeMux). Anything that doesn't match passes through with no
// per-IP bookkeeping. RequestsPerMin / BurstSize are *default fallbacks*
// used when an EndpointLimits entry leaves those fields at zero.
type RateLimitConfig struct {
	RequestsPerMin  int                    // Default rpm applied to endpoint entries with rpm=0
	BurstSize       int                    // Default burst applied to endpoint entries with burst=0
	CleanupInterval time.Duration          // How often to cleanup old entries
	RouteEnabled    bool                   // Enable per-route rate limiting (Legacy/Additional)
	RouteLimit      int                    // Requests per minute per route
	EndpointLimits  map[string]LimitConfig // Per-endpoint limits (opt-in; empty = no rate limiting)
}

// LimitConfig defines rate limit for a specific context. JSON tags are
// snake_case so endpoint_limits round-trip cleanly through the dashboard
// (POST /waf-api/config) and the persisted config store. Without them
// the decoder would silently zero the fields on every save.
type LimitConfig struct {
	RequestsPerMin int `json:"requests_per_min"`
	BurstSize      int `json:"burst_size"`
}

// clientBucket tracks rate limit state for a single client IP
type clientBucket struct {
	tokens       int       // Current available tokens
	lastRefill   time.Time // Last time tokens were refilled
	requestCount int       // Total requests made
	blockedCount int       // Total requests blocked
	firstRequest time.Time // First request timestamp
	lastRequest  time.Time // Most recent request timestamp
}

// routeBucket tracks rate limit state for a specific route
type routeBucket struct {
	tokens       int
	lastRefill   time.Time
	requestCount int
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	// Set defaults if not configured
	if config.RequestsPerMin == 0 {
		config.RequestsPerMin = 100
	}
	if config.BurstSize == 0 {
		config.BurstSize = 20
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 5 * time.Minute
	}

	rl := &RateLimiter{
		clients:         make(map[string]*clientBucket),
		endpointBuckets: make(map[string]map[string]*clientBucket),
		routes:          make(map[string]*routeBucket),
		config:          config,
		stopCleanup:     make(chan bool),
	}

	// Start cleanup goroutine
	rl.startCleanup()

	return rl
}

// IsRateLimited checks if a client IP is rate limited
func (rl *RateLimiter) IsRateLimited(clientIP string) bool {
	return rl.IsRateLimitedWithRoute(clientIP, "")
}

// IsRateLimitedWithRoute checks the rate limit for (clientIP, route).
//
// Rate limiting is opt-in: a request is only throttled when its route
// matches an entry in config.EndpointLimits. An unconfigured route returns
// false immediately and creates no bookkeeping. This means an empty
// endpoint_limits map means "no rate limiting anywhere" — the safest
// default for a WAF that sits in front of arbitrary traffic.
//
// Matching is exact first, then subtree-prefix for entries ending in "/"
// (the longest such pattern wins, matching net/http.ServeMux semantics).
// The bucket is keyed by the matched *pattern*, so a single "/api/auth/"
// entry shares one bucket across all requests under that subtree per
// client IP — operators get one knob, not N hidden buckets.
func (rl *RateLimiter) IsRateLimitedWithRoute(clientIP, route string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	limitConfig, matchedKey, ok := rl.matchEndpointLocked(route)
	if !ok {
		// No matching endpoint pattern → not rate limited. We intentionally
		// don't even touch the clients map here; an unconfigured path
		// should leave zero footprint so attackers can't poison memory by
		// spraying random URLs.
		return false
	}

	// Fall back to global defaults for any field the operator left at zero
	// in the endpoint entry — saves them from repeating the same numbers
	// across every endpoint when most should share one limit.
	rpm := limitConfig.RequestsPerMin
	burst := limitConfig.BurstSize
	if rpm == 0 {
		rpm = rl.config.RequestsPerMin
	}
	if burst == 0 {
		burst = rl.config.BurstSize
	}
	// If even the global defaults are zero we have no usable limit; treat
	// as "configured but inert" rather than crashing or dividing by zero.
	if rpm <= 0 || burst <= 0 {
		return false
	}

	if rl.endpointBuckets == nil {
		rl.endpointBuckets = make(map[string]map[string]*clientBucket)
	}
	if rl.endpointBuckets[matchedKey] == nil {
		rl.endpointBuckets[matchedKey] = make(map[string]*clientBucket)
	}

	bucket, exists := rl.endpointBuckets[matchedKey][clientIP]
	if !exists {
		bucket = &clientBucket{
			tokens:       burst,
			lastRefill:   now,
			firstRequest: now,
			lastRequest:  now,
		}
		rl.endpointBuckets[matchedKey][clientIP] = bucket
	}

	rl.refillTokensWithConfig(bucket, now, rpm, burst)

	bucket.requestCount++
	bucket.lastRequest = now

	if bucket.tokens <= 0 {
		bucket.blockedCount++
		return true
	}

	bucket.tokens--

	// Legacy/Secondary Route Rate Limit (Shared across all IPs). Protects
	// the route itself from total traffic overload regardless of IP. Off
	// by default; only kicks in when config.RouteEnabled is set.
	if rl.config.RouteEnabled && route != "" {
		if rl.isRouteLimited(route, now) {
			bucket.blockedCount++
			return true
		}
	}

	return false
}

// matchEndpointLocked resolves route to its EndpointLimits entry.
//
// Exact match wins. Otherwise, among keys ending in "/" (subtree
// patterns), the longest one that prefixes route wins. Caller must hold
// rl.mu (read or write — we only read rl.config here).
func (rl *RateLimiter) matchEndpointLocked(route string) (LimitConfig, string, bool) {
	if route == "" || len(rl.config.EndpointLimits) == 0 {
		return LimitConfig{}, "", false
	}
	if lc, ok := rl.config.EndpointLimits[route]; ok {
		return lc, route, true
	}
	var bestKey string
	var bestLC LimitConfig
	for k, v := range rl.config.EndpointLimits {
		if !strings.HasSuffix(k, "/") {
			continue
		}
		if !strings.HasPrefix(route, k) {
			continue
		}
		if len(k) > len(bestKey) {
			bestKey = k
			bestLC = v
		}
	}
	if bestKey == "" {
		return LimitConfig{}, "", false
	}
	return bestLC, bestKey, true
}

// refillTokensWithConfig adds tokens based on dynamic config
func (rl *RateLimiter) refillTokensWithConfig(bucket *clientBucket, now time.Time, rpm, burst int) {
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := int(elapsed.Seconds()) * (rpm / 60)

	if tokensToAdd > 0 {
		bucket.tokens += tokensToAdd
		if bucket.tokens > burst {
			bucket.tokens = burst
		}
		bucket.lastRefill = now
	}
}

// refillTokens adds tokens to bucket based on elapsed time
func (rl *RateLimiter) refillTokens(bucket *clientBucket, now time.Time) {
	elapsed := now.Sub(bucket.lastRefill)

	// Calculate tokens to add based on configured rate
	// Formula: (elapsed seconds) * (requests per minute / 60)
	tokensToAdd := int(elapsed.Seconds()) * (rl.config.RequestsPerMin / 60)

	if tokensToAdd > 0 {
		bucket.tokens += tokensToAdd

		// Cap at burst size
		if bucket.tokens > rl.config.BurstSize {
			bucket.tokens = rl.config.BurstSize
		}

		bucket.lastRefill = now
	}
}

// isRouteLimited checks route-specific rate limit
func (rl *RateLimiter) isRouteLimited(route string, now time.Time) bool {
	bucket, exists := rl.routes[route]
	if !exists {
		bucket = &routeBucket{
			tokens:     rl.config.RouteLimit,
			lastRefill: now,
		}
		rl.routes[route] = bucket
	}

	// Refill route bucket
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := int(elapsed.Seconds()) * (rl.config.RouteLimit / 60)

	if tokensToAdd > 0 {
		bucket.tokens += tokensToAdd
		if bucket.tokens > rl.config.RouteLimit {
			bucket.tokens = rl.config.RouteLimit
		}
		bucket.lastRefill = now
	}

	bucket.requestCount++

	if bucket.tokens <= 0 {
		return true
	}

	bucket.tokens--
	return false
}

// GetClientStats returns statistics for a specific client IP
func (rl *RateLimiter) GetClientStats(clientIP string) *ClientStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.clients[clientIP]
	if !exists {
		return nil
	}

	return &ClientStats{
		IP:             clientIP,
		RequestCount:   bucket.requestCount,
		BlockedCount:   bucket.blockedCount,
		CurrentTokens:  bucket.tokens,
		FirstRequest:   bucket.firstRequest,
		LastRequest:    bucket.lastRequest,
		RequestsPerMin: rl.calculateRPM(bucket),
	}
}

// calculateRPM calculates current requests per minute for a client
func (rl *RateLimiter) calculateRPM(bucket *clientBucket) float64 {
	duration := bucket.lastRequest.Sub(bucket.firstRequest)
	if duration.Seconds() == 0 {
		return 0
	}
	return float64(bucket.requestCount) / duration.Minutes()
}

// GetAllClientStats returns statistics for all tracked clients
func (rl *RateLimiter) GetAllClientStats() []*ClientStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	stats := make([]*ClientStats, 0, len(rl.clients))
	for ip, bucket := range rl.clients {
		stats = append(stats, &ClientStats{
			IP:             ip,
			RequestCount:   bucket.requestCount,
			BlockedCount:   bucket.blockedCount,
			CurrentTokens:  bucket.tokens,
			FirstRequest:   bucket.firstRequest,
			LastRequest:    bucket.lastRequest,
			RequestsPerMin: rl.calculateRPM(bucket),
		})
	}

	return stats
}

// GetTopClients returns the top N clients by request count
func (rl *RateLimiter) GetTopClients(n int) []*ClientStats {
	allStats := rl.GetAllClientStats()

	// Sort by request count (simple bubble sort for small N)
	for i := 0; i < len(allStats)-1; i++ {
		for j := 0; j < len(allStats)-i-1; j++ {
			if allStats[j].RequestCount < allStats[j+1].RequestCount {
				allStats[j], allStats[j+1] = allStats[j+1], allStats[j]
			}
		}
	}

	if len(allStats) > n {
		return allStats[:n]
	}
	return allStats
}

// GetBlockedClients returns all clients that have been blocked
func (rl *RateLimiter) GetBlockedClients() []*ClientStats {
	allStats := rl.GetAllClientStats()

	blocked := make([]*ClientStats, 0)
	for _, stat := range allStats {
		if stat.BlockedCount > 0 {
			blocked = append(blocked, stat)
		}
	}

	return blocked
}

// ResetClient removes rate limit state for a specific client
func (rl *RateLimiter) ResetClient(clientIP string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.clients, clientIP)
}

// ResetAllClients clears all rate limit state
func (rl *RateLimiter) ResetAllClients() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.clients = make(map[string]*clientBucket)
	rl.endpointBuckets = make(map[string]map[string]*clientBucket)
	rl.routes = make(map[string]*routeBucket)
}

// startCleanup starts background goroutine to cleanup old entries
func (rl *RateLimiter) startCleanup() {
	rl.cleanupTicker = time.NewTicker(rl.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-rl.cleanupTicker.C:
				rl.cleanup()
			case <-rl.stopCleanup:
				rl.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanup removes old entries that haven't been accessed recently
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cleanupThreshold := 10 * time.Minute

	// Cleanup old clients
	for ip, bucket := range rl.clients {
		if now.Sub(bucket.lastRequest) > cleanupThreshold {
			delete(rl.clients, ip)
		}
	}

	// Cleanup endpoint buckets
	for _, ipMap := range rl.endpointBuckets {
		for ip, bucket := range ipMap {
			if now.Sub(bucket.lastRequest) > cleanupThreshold {
				delete(ipMap, ip)
			}
		}
	}

	// Cleanup old routes
	for route, bucket := range rl.routes {
		if now.Sub(bucket.lastRefill) > cleanupThreshold {
			delete(rl.routes, route)
		}
	}
}

// Stop stops the rate limiter and cleanup goroutine
func (rl *RateLimiter) Stop() {
	rl.stopCleanup <- true
}

// GetStats returns overall rate limiter statistics
func (rl *RateLimiter) GetStats() *RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	totalRequests := 0
	totalBlocked := 0
	activeClients := len(rl.clients)

	for _, bucket := range rl.clients {
		totalRequests += bucket.requestCount
		totalBlocked += bucket.blockedCount
	}

	blockRate := 0.0
	if totalRequests > 0 {
		blockRate = float64(totalBlocked) / float64(totalRequests) * 100
	}

	return &RateLimiterStats{
		TotalRequests: totalRequests,
		TotalBlocked:  totalBlocked,
		ActiveClients: activeClients,
		ActiveRoutes:  len(rl.routes),
		BlockRate:     blockRate,
		ConfigRPM:     rl.config.RequestsPerMin,
		ConfigBurst:   rl.config.BurstSize,
	}
}

// SetConfig updates rate limiter configuration dynamically
func (rl *RateLimiter) SetConfig(config RateLimitConfig) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	rl.config = config
}

// GetConfig returns current configuration
func (rl *RateLimiter) GetConfig() RateLimitConfig {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return rl.config
}

// ============================================================================
// Data Structures
// ============================================================================

// ClientStats contains statistics for a single client
type ClientStats struct {
	IP             string
	RequestCount   int
	BlockedCount   int
	CurrentTokens  int
	FirstRequest   time.Time
	LastRequest    time.Time
	RequestsPerMin float64
}

// RateLimiterStats contains overall rate limiter statistics
type RateLimiterStats struct {
	TotalRequests int
	TotalBlocked  int
	ActiveClients int
	ActiveRoutes  int
	BlockRate     float64
	ConfigRPM     int
	ConfigBurst   int
}

// ============================================================================
// Advanced Features
// ============================================================================

// AllowBurst temporarily increases burst size for a client
func (rl *RateLimiter) AllowBurst(clientIP string, additionalTokens int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.clients[clientIP]
	if exists {
		bucket.tokens += additionalTokens
	}
}

// BlockClient temporarily blocks a client by setting tokens to negative
func (rl *RateLimiter) BlockClient(clientIP string, duration time.Duration) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.clients[clientIP]
	if !exists {
		bucket = &clientBucket{
			tokens:       -1000, // Large negative number
			lastRefill:   time.Now(),
			firstRequest: time.Now(),
			lastRequest:  time.Now(),
		}
		rl.clients[clientIP] = bucket
	} else {
		bucket.tokens = -1000
	}
}

// IsClientBlocked checks if a client is currently blocked
func (rl *RateLimiter) IsClientBlocked(clientIP string) bool {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.clients[clientIP]
	return exists && bucket.tokens < 0
}

// GetRemainingTokens returns how many tokens a client has available
func (rl *RateLimiter) GetRemainingTokens(clientIP string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.clients[clientIP]
	if !exists {
		return rl.config.BurstSize
	}
	return bucket.tokens
}

// GetTimeUntilRefill returns how long until next token refill
func (rl *RateLimiter) GetTimeUntilRefill(clientIP string) time.Duration {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.clients[clientIP]
	if !exists {
		return 0
	}

	// Calculate when next refill occurs (every second)
	nextRefill := bucket.lastRefill.Add(1 * time.Second)
	remaining := time.Until(nextRefill)

	if remaining < 0 {
		return 0
	}
	return remaining
}
