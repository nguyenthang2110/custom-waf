// internal/metrics/metrics.go
package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Collector collects and exports WAF metrics
type Collector struct {
	// Request metrics
	requestsTotal   *prometheus.CounterVec
	requestDuration *prometheus.HistogramVec
	requestSize     prometheus.Histogram
	responseSize    prometheus.Histogram

	// WAF decision metrics
	decisionsTotal *prometheus.CounterVec
	blockedTotal   prometheus.Counter
	monitoredTotal prometheus.Counter
	allowedTotal   prometheus.Counter

	// Anomaly score metrics
	anomalyScore      prometheus.Histogram
	anomalyScoreGauge prometheus.Gauge

	// Rule metrics
	ruleMatchesTotal   *prometheus.CounterVec
	ruleEvaluationTime *prometheus.HistogramVec
	rulesLoaded        prometheus.Gauge

	// Rate limiting metrics
	rateLimitedTotal   prometheus.Counter
	rateLimitHitsTotal *prometheus.CounterVec

	// Behavior detection metrics
	bruteforceDetected prometheus.Counter
	botDetected        prometheus.Counter
	scanningDetected   prometheus.Counter
	suspiciousIPsGauge prometheus.Gauge

	// Performance metrics
	parserLatency     prometheus.Histogram
	normalizerLatency prometheus.Histogram
	ruleEngineLatency prometheus.Histogram
	totalLatency      prometheus.Histogram

	// System metrics
	activeConnections prometheus.Gauge
	queuedRequests    prometheus.Gauge
	droppedRequests   prometheus.Counter

	// Category metrics
	categoryHits *prometheus.CounterVec
	severityHits *prometheus.CounterVec

	// Client metrics
	uniqueClientsGauge prometheus.Gauge
	topClientsGauge    *prometheus.GaugeVec

	// Statistics (non-Prometheus)
	stats *MetricsStats
	mu    sync.RWMutex
}

// ClientStat tracks statistics for a single client IP
type ClientStat struct {
	TotalRequests int64
	TotalBlocked  int64
	LastSeen      time.Time
}

// MetricsStats holds internal statistics
type MetricsStats struct {
	StartTime      time.Time
	TotalRequests  int64
	TotalBlocked   int64
	TotalMonitored int64
	TotalAllowed   int64
	TotalLatency   time.Duration
	UniqueClients  int
	TopRules       map[string]int64
	TopCategories  map[string]int64
	Clients        map[string]*ClientStat
}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	c := &Collector{
		stats: &MetricsStats{
			StartTime:     time.Now(),
			TopRules:      make(map[string]int64),
			TopCategories: make(map[string]int64),
			Clients:       make(map[string]*ClientStat),
		},
	}

	// Initialize Prometheus metrics
	c.initRequestMetrics()
	c.initDecisionMetrics()
	c.initRuleMetrics()
	c.initRateLimitMetrics()
	c.initBehaviorMetrics()
	c.initPerformanceMetrics()
	c.initSystemMetrics()

	return c
}

// ============================================================================
// Initialization
// ============================================================================

func (c *Collector) initRequestMetrics() {
	c.requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_requests_total",
			Help: "Total number of requests processed by WAF",
		},
		[]string{"method", "path", "decision"},
	)

	c.requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "waf_request_duration_seconds",
			Help:    "Request processing duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "decision"},
	)

	c.requestSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_request_size_bytes",
			Help:    "Request body size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 7),
		},
	)

	c.responseSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_response_size_bytes",
			Help:    "Response body size in bytes",
			Buckets: prometheus.ExponentialBuckets(100, 10, 7),
		},
	)
}

func (c *Collector) initDecisionMetrics() {
	c.decisionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_decisions_total",
			Help: "Total decisions made by WAF",
		},
		[]string{"decision"},
	)

	c.blockedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_blocked_total",
			Help: "Total number of blocked requests",
		},
	)

	c.monitoredTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_monitored_total",
			Help: "Total number of monitored (flagged but forwarded) requests",
		},
	)

	c.allowedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_allowed_total",
			Help: "Total number of allowed requests",
		},
	)

	c.anomalyScore = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_anomaly_score",
			Help:    "Distribution of anomaly scores",
			Buckets: []float64{0, 1, 2, 3, 5, 7, 10, 15, 20, 30, 50},
		},
	)

	c.anomalyScoreGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_anomaly_score_current",
			Help: "Current average anomaly score",
		},
	)
}

func (c *Collector) initRuleMetrics() {
	c.ruleMatchesTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_rule_matches_total",
			Help: "Total rule matches by rule ID",
		},
		[]string{"rule_id", "category", "severity"},
	)

	c.ruleEvaluationTime = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "waf_rule_evaluation_seconds",
			Help:    "Rule evaluation time in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"rule_id"},
	)

	c.rulesLoaded = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_rules_loaded",
			Help: "Number of rules currently loaded",
		},
	)

	c.categoryHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_category_hits_total",
			Help: "Total hits by attack category",
		},
		[]string{"category"},
	)

	c.severityHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_severity_hits_total",
			Help: "Total hits by severity level",
		},
		[]string{"severity"},
	)
}

func (c *Collector) initRateLimitMetrics() {
	c.rateLimitedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_rate_limited_total",
			Help: "Total rate limited requests",
		},
	)

	c.rateLimitHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "waf_rate_limit_hits_total",
			Help: "Rate limit hits by client IP",
		},
		[]string{"client_ip"},
	)
}

func (c *Collector) initBehaviorMetrics() {
	c.bruteforceDetected = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_bruteforce_detected_total",
			Help: "Total bruteforce attempts detected",
		},
	)

	c.botDetected = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_bot_detected_total",
			Help: "Total bot activity detected",
		},
	)

	c.scanningDetected = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_scanning_detected_total",
			Help: "Total scanning attempts detected",
		},
	)

	c.suspiciousIPsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_suspicious_ips",
			Help: "Number of currently suspicious IPs",
		},
	)
}

func (c *Collector) initPerformanceMetrics() {
	c.parserLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_parser_latency_seconds",
			Help:    "HTTP parser latency",
			Buckets: []float64{.0001, .0005, .001, .002, .005, .01, .02, .05},
		},
	)

	c.normalizerLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_normalizer_latency_seconds",
			Help:    "Normalizer latency",
			Buckets: []float64{.0001, .0005, .001, .002, .005, .01, .02, .05},
		},
	)

	c.ruleEngineLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_rule_engine_latency_seconds",
			Help:    "Rule engine evaluation latency",
			Buckets: []float64{.001, .002, .005, .01, .02, .05, .1},
		},
	)

	c.totalLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "waf_total_latency_seconds",
			Help:    "Total WAF processing latency",
			Buckets: []float64{.001, .005, .01, .02, .05, .1, .2, .5},
		},
	)
}

func (c *Collector) initSystemMetrics() {
	c.activeConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_active_connections",
			Help: "Number of active connections",
		},
	)

	c.queuedRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_queued_requests",
			Help: "Number of requests in queue",
		},
	)

	c.droppedRequests = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "waf_dropped_requests_total",
			Help: "Total dropped requests",
		},
	)

	c.uniqueClientsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "waf_unique_clients",
			Help: "Number of unique client IPs",
		},
	)

	c.topClientsGauge = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "waf_top_clients_requests",
			Help: "Request count for top clients",
		},
		[]string{"client_ip"},
	)
}

// ============================================================================
// Recording Methods
// ============================================================================

// RecordRequest records a request with decision
func (c *Collector) RecordRequest(decision string, score float64) {
	c.mu.Lock()
	c.stats.TotalRequests++

	switch decision {
	case "BLOCK":
		c.stats.TotalBlocked++
	case "MONITOR":
		c.stats.TotalMonitored++
	case "ALLOW":
		c.stats.TotalAllowed++
	}
	c.mu.Unlock()

	// Update Prometheus metrics
	c.decisionsTotal.WithLabelValues(decision).Inc()
	c.anomalyScore.Observe(score)

	if decision == "BLOCK" {
		c.blockedTotal.Inc()
	} else if decision == "MONITOR" {
		c.monitoredTotal.Inc()
	} else {
		c.allowedTotal.Inc()
	}
}

// RecordRequestWithDetails records detailed request metrics
func (c *Collector) RecordRequestWithDetails(
	clientIP, method, path, decision string,
	score float64,
	duration time.Duration,
	requestSize, responseSize int,
) {
	c.mu.Lock()
	// Update client stats
	client, exists := c.stats.Clients[clientIP]
	if !exists {
		client = &ClientStat{}
		c.stats.Clients[clientIP] = client
		c.stats.UniqueClients++
		c.uniqueClientsGauge.Set(float64(c.stats.UniqueClients))
	}
	client.TotalRequests++
	client.LastSeen = time.Now()
	if decision == "BLOCK" {
		client.TotalBlocked++
	}
	c.mu.Unlock()

	c.RecordRequest(decision, score)

	c.requestsTotal.WithLabelValues(method, path, decision).Inc()
	c.requestDuration.WithLabelValues(method, decision).Observe(duration.Seconds())
	c.requestSize.Observe(float64(requestSize))
	c.responseSize.Observe(float64(responseSize))

	c.mu.Lock()
	c.stats.TotalLatency += duration
	c.mu.Unlock()
}

// RecordRuleMatch records a rule match
func (c *Collector) RecordRuleMatch(ruleID, category, severity string, evalTime time.Duration) {
	c.ruleMatchesTotal.WithLabelValues(ruleID, category, severity).Inc()
	c.ruleEvaluationTime.WithLabelValues(ruleID).Observe(evalTime.Seconds())
	c.categoryHits.WithLabelValues(category).Inc()
	c.severityHits.WithLabelValues(severity).Inc()

	c.mu.Lock()
	c.stats.TopRules[ruleID]++
	c.stats.TopCategories[category]++
	c.mu.Unlock()
}

// RecordRateLimitHit records rate limit hit
func (c *Collector) RecordRateLimitHit(clientIP string) {
	c.rateLimitedTotal.Inc()
	c.rateLimitHitsTotal.WithLabelValues(clientIP).Inc()
}

// RecordBehaviorThreat records behavior-based threat detection
func (c *Collector) RecordBehaviorThreat(threatType string) {
	switch threatType {
	case "BRUTEFORCE":
		c.bruteforceDetected.Inc()
	case "AUTOMATED_BOT", "SCANNER_TOOL":
		c.botDetected.Inc()
	case "PATH_SCANNING":
		c.scanningDetected.Inc()
	}
}

// RecordLatency records component latencies
func (c *Collector) RecordLatency(component string, duration time.Duration) {
	switch component {
	case "parser":
		c.parserLatency.Observe(duration.Seconds())
	case "normalizer":
		c.normalizerLatency.Observe(duration.Seconds())
	case "rule_engine":
		c.ruleEngineLatency.Observe(duration.Seconds())
	case "total":
		c.totalLatency.Observe(duration.Seconds())
	}
}

// UpdateRulesLoaded updates the number of loaded rules
func (c *Collector) UpdateRulesLoaded(count int) {
	c.rulesLoaded.Set(float64(count))
}

// UpdateSuspiciousIPs updates suspicious IPs gauge
func (c *Collector) UpdateSuspiciousIPs(count int) {
	c.suspiciousIPsGauge.Set(float64(count))
}

// UpdateActiveConnections updates active connections gauge
func (c *Collector) UpdateActiveConnections(count int) {
	c.activeConnections.Set(float64(count))
}

// UpdateQueuedRequests updates queued requests gauge
func (c *Collector) UpdateQueuedRequests(count int) {
	c.queuedRequests.Set(float64(count))
}

// RecordDroppedRequest records a dropped request
func (c *Collector) RecordDroppedRequest() {
	c.droppedRequests.Inc()
}

// UpdateUniqueClients updates unique client count
func (c *Collector) UpdateUniqueClients(count int) {
	c.uniqueClientsGauge.Set(float64(count))

	c.mu.Lock()
	c.stats.UniqueClients = count
	c.mu.Unlock()
}

// UpdateTopClients updates top client metrics
func (c *Collector) UpdateTopClients(clients map[string]int64) {
	for ip, count := range clients {
		c.topClientsGauge.WithLabelValues(ip).Set(float64(count))
	}
}

// UpdateAverageAnomalyScore updates average anomaly score
func (c *Collector) UpdateAverageAnomalyScore(score float64) {
	c.anomalyScoreGauge.Set(score)
}

// ============================================================================
// Statistics
// ============================================================================

// GetStats returns internal statistics
func (c *Collector) GetStats() *MetricsStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return &MetricsStats{
		StartTime:      c.stats.StartTime,
		TotalRequests:  c.stats.TotalRequests,
		TotalBlocked:   c.stats.TotalBlocked,
		TotalMonitored: c.stats.TotalMonitored,
		TotalAllowed:   c.stats.TotalAllowed,
		TotalLatency:   c.stats.TotalLatency,
		UniqueClients:  c.stats.UniqueClients,
		TopRules:       copyMap(c.stats.TopRules),
		TopCategories:  copyMap(c.stats.TopCategories),
		Clients:        copyClients(c.stats.Clients),
	}
}

// GetBlockRate returns block rate percentage
func (c *Collector) GetBlockRate() float64 {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.stats.TotalRequests == 0 {
		return 0.0
	}
	return float64(c.stats.TotalBlocked) / float64(c.stats.TotalRequests) * 100
}

// GetAverageLatency returns average request latency
func (c *Collector) GetAverageLatency() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.stats.TotalRequests == 0 {
		return 0
	}
	return c.stats.TotalLatency / time.Duration(c.stats.TotalRequests)
}

// GetUptime returns WAF uptime
func (c *Collector) GetUptime() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return time.Since(c.stats.StartTime)
}

// GetTopRules returns top N rules by match count
func (c *Collector) GetTopRules(n int) []RuleCount {
	c.mu.RLock()
	defer c.mu.RUnlock()

	rules := make([]RuleCount, 0, len(c.stats.TopRules))
	for ruleID, count := range c.stats.TopRules {
		rules = append(rules, RuleCount{RuleID: ruleID, Count: count})
	}

	// Simple bubble sort for top N
	for i := 0; i < len(rules)-1; i++ {
		for j := 0; j < len(rules)-i-1; j++ {
			if rules[j].Count < rules[j+1].Count {
				rules[j], rules[j+1] = rules[j+1], rules[j]
			}
		}
	}

	if len(rules) > n {
		return rules[:n]
	}
	return rules
}

// ResetStats resets internal statistics
func (c *Collector) ResetStats() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats = &MetricsStats{
		StartTime:     time.Now(),
		TopRules:      make(map[string]int64),
		TopCategories: make(map[string]int64),
		Clients:       make(map[string]*ClientStat),
	}
}

// ============================================================================
// Helper Types
// ============================================================================

// RuleCount represents rule match count
type RuleCount struct {
	RuleID string
	Count  int64
}

// ============================================================================
// Helper Functions
// ============================================================================

func copyMap(m map[string]int64) map[string]int64 {
	result := make(map[string]int64, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

func copyClients(m map[string]*ClientStat) map[string]*ClientStat {
	result := make(map[string]*ClientStat, len(m))
	for k, v := range m {
		// Copy struct value
		val := *v
		result[k] = &val
	}
	return result
}
