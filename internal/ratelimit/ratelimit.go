// internal/ratelimit/ratelimit.go
package ratelimit

import (
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

// RateLimitConfig defines rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMin  int                    // Max requests per minute per client (Global)
	BurstSize       int                    // Maximum burst size (token bucket capacity)
	CleanupInterval time.Duration          // How often to cleanup old entries
	RouteEnabled    bool                   // Enable per-route rate limiting (Legacy/Additional)
	RouteLimit      int                    // Requests per minute per route
	EndpointLimits  map[string]LimitConfig // Specific limits per endpoint
}

// LimitConfig defines rate limit for a specific context
type LimitConfig struct {
	RequestsPerMin int
	BurstSize      int
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

// IsRateLimitedWithRoute checks rate limit for client IP and optional route
func (rl *RateLimiter) IsRateLimitedWithRoute(clientIP, route string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// 1. Check Endpoint-Specific Limits
	// If the route matches a specific endpoint config, we use that bucket INSTEAD of global
	// This allows setting higher or lower limits for specific paths
	var usedBucket *clientBucket
	var rpm int
	var burst int

	// Simple exact match for now (can be enhanced to prefix match later if needed)
	if limitConfig, ok := rl.config.EndpointLimits[route]; ok {
		// Ensure map exists for this endpoint
		if rl.endpointBuckets == nil {
			rl.endpointBuckets = make(map[string]map[string]*clientBucket)
		}
		if rl.endpointBuckets[route] == nil {
			rl.endpointBuckets[route] = make(map[string]*clientBucket)
		}

		bucket, exists := rl.endpointBuckets[route][clientIP]
		if !exists {
			bucket = &clientBucket{
				tokens:       limitConfig.BurstSize,
				lastRefill:   now,
				firstRequest: now,
				lastRequest:  now,
			}
			rl.endpointBuckets[route][clientIP] = bucket
		}
		usedBucket = bucket
		rpm = limitConfig.RequestsPerMin
		burst = limitConfig.BurstSize
	} else {
		// 2. Global Limit (Fallback)
		bucket, exists := rl.clients[clientIP]
		if !exists {
			bucket = &clientBucket{
				tokens:       rl.config.BurstSize,
				lastRefill:   now,
				firstRequest: now,
				lastRequest:  now,
			}
			rl.clients[clientIP] = bucket
		}
		usedBucket = bucket
		rpm = rl.config.RequestsPerMin
		burst = rl.config.BurstSize
	}

	// Refill tokens
	rl.refillTokensWithConfig(usedBucket, now, rpm, burst)

	// Update tracking
	usedBucket.requestCount++
	usedBucket.lastRequest = now

	// Check limit
	if usedBucket.tokens <= 0 {
		usedBucket.blockedCount++
		return true
	}

	usedBucket.tokens--

	// 3. Legacy/Secondary Route Rate Limit (Shared across all IPs)
	// This protects the route itself from total traffic overload, regardless of IP
	if rl.config.RouteEnabled && route != "" {
		if rl.isRouteLimited(route, now) {
			usedBucket.blockedCount++ // Credit the block to the user too
			return true
		}
	}

	return false
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
