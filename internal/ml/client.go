// Package ml provides an HTTP client for the FastAPI DistilBERT inference service.
package ml

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Client talks to the ml-service over HTTP.
type Client struct {
	endpoint string
	httpc    *http.Client
	enabled  atomic.Bool

	cache   *predictionCache
	breaker *circuitBreaker

	// Stats
	mu            sync.RWMutex
	totalCalls    uint64
	totalErrors   uint64
	totalLatency  time.Duration
	lastErrorText string
}

// Config configures the ML client.
type Config struct {
	Endpoint   string        // e.g. "http://ml:8000"
	Timeout    time.Duration // per request
	Enabled    bool
	MaxBodyLen int // truncate input text to this many bytes

	// LRU cache for predictions. Set CacheSize <= 0 to disable.
	CacheSize int
	CacheTTL  time.Duration

	// Circuit breaker. Set BreakerThreshold <= 0 to disable.
	BreakerThreshold int           // consecutive failures that open the circuit
	BreakerCooldown  time.Duration // how long the circuit stays open
}

// PredictRequest is the JSON payload sent to /predict.
type PredictRequest struct {
	Text string `json:"text"`
}

// PredictResponse mirrors the FastAPI response shape.
type PredictResponse struct {
	Label      string             `json:"label"`
	LabelID    int                `json:"label_id"`
	Confidence float64            `json:"confidence"`
	Scores     map[string]float64 `json:"scores"`
	IsAttack   bool               `json:"is_attack"`
	LatencyMs  float64            `json:"latency_ms"`
}

const defaultMaxBodyLen = 4096

// NewClient builds a new ML client. Safe to call even if disabled.
func NewClient(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 800 * time.Millisecond
	}
	if cfg.MaxBodyLen == 0 {
		cfg.MaxBodyLen = defaultMaxBodyLen
	}
	c := &Client{
		endpoint: cfg.Endpoint,
		httpc: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
	c.enabled.Store(cfg.Enabled && cfg.Endpoint != "")

	if cfg.CacheSize > 0 {
		c.cache = newPredictionCache(cfg.CacheSize, cfg.CacheTTL)
	}
	if cfg.BreakerThreshold > 0 {
		c.breaker = newCircuitBreaker(cfg.BreakerThreshold, cfg.BreakerCooldown)
	}
	return c
}

// Enabled reports whether the client is wired up and turned on.
func (c *Client) Enabled() bool { return c.enabled.Load() }

// SetEnabled toggles the client at runtime.
func (c *Client) SetEnabled(v bool) { c.enabled.Store(v) }

// Predict sends a single text to the model service.
// Returns (resp, nil) on success or (nil, err) on transport/parse error.
// On disabled client, returns (nil, ErrDisabled) without making an HTTP call.
func (c *Client) Predict(ctx context.Context, text string) (*PredictResponse, error) {
	if !c.enabled.Load() {
		return nil, ErrDisabled
	}
	if len(text) == 0 {
		return nil, fmt.Errorf("ml: empty input")
	}
	// Truncate huge bodies — model max_length is 256 tokens anyway.
	if len(text) > defaultMaxBodyLen {
		text = text[:defaultMaxBodyLen]
	}

	// Cache hit fast-path: replayed payloads (scanner loops, browser retries)
	// don't need a fresh model round-trip.
	if cached, ok := c.cache.Get(text); ok {
		return cached, nil
	}

	// Circuit breaker: if the ML service has been unhealthy, fail fast and let
	// the decision engine fall back to its rule-only path.
	if c.breaker != nil && !c.breaker.allow() {
		return nil, ErrCircuitOpen
	}

	body, err := json.Marshal(PredictRequest{Text: text})
	if err != nil {
		return nil, fmt.Errorf("ml: marshal: %w", err)
	}

	url := c.endpoint + "/predict"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("ml: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	res, err := c.httpc.Do(req)
	if err != nil {
		c.recordError(err.Error(), time.Since(start))
		if c.breaker != nil {
			c.breaker.recordFailure()
		}
		return nil, fmt.Errorf("ml: do: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		errMsg := fmt.Sprintf("status=%d body=%s", res.StatusCode, string(raw))
		c.recordError(errMsg, time.Since(start))
		if c.breaker != nil {
			c.breaker.recordFailure()
		}
		return nil, fmt.Errorf("ml: %s", errMsg)
	}

	var out PredictResponse
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		c.recordError("decode: "+err.Error(), time.Since(start))
		if c.breaker != nil {
			c.breaker.recordFailure()
		}
		return nil, fmt.Errorf("ml: decode: %w", err)
	}

	c.recordSuccess(time.Since(start))
	if c.breaker != nil {
		c.breaker.recordSuccess()
	}
	c.cache.Put(text, &out)
	return &out, nil
}

// Health checks the /health endpoint.
func (c *Client) Health(ctx context.Context) error {
	if c.endpoint == "" {
		return ErrDisabled
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/health", nil)
	if err != nil {
		return err
	}
	res, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("ml: health status=%d", res.StatusCode)
	}
	return nil
}

// Stats holds aggregated client metrics.
type Stats struct {
	TotalCalls    uint64
	TotalErrors   uint64
	AvgLatencyMs  float64
	LastErrorText string

	// Cache and breaker diagnostics (zero values if disabled).
	Cache        CacheStats
	BreakerState string
}

// Stats returns a snapshot of the client metrics.
func (c *Client) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var avg float64
	if c.totalCalls > 0 {
		avg = float64(c.totalLatency.Milliseconds()) / float64(c.totalCalls)
	}
	return Stats{
		TotalCalls:    c.totalCalls,
		TotalErrors:   c.totalErrors,
		AvgLatencyMs:  avg,
		LastErrorText: c.lastErrorText,
		Cache:         c.cache.Stats(),
		BreakerState:  c.breaker.State(),
	}
}

func (c *Client) recordSuccess(d time.Duration) {
	c.mu.Lock()
	c.totalCalls++
	c.totalLatency += d
	c.mu.Unlock()
}

func (c *Client) recordError(msg string, d time.Duration) {
	c.mu.Lock()
	c.totalCalls++
	c.totalErrors++
	c.totalLatency += d
	c.lastErrorText = msg
	c.mu.Unlock()
}

// ErrDisabled is returned when the client is not enabled.
var ErrDisabled = fmt.Errorf("ml: client disabled")
