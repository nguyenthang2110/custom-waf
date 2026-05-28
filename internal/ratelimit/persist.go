// internal/ratelimit/persist.go
//
// Snapshot/Restore for the rate limiter. The token buckets, request /
// block counters and per-endpoint state must survive restart so an
// attacker can't reset their rate by triggering a WAF bounce.
package ratelimit

import (
	"encoding/json"
	"time"
)

type snapshotV1 struct {
	Version         int                              `json:"version"`
	SavedAt         time.Time                        `json:"saved_at"`
	Clients         map[string]*clientBucketWire     `json:"clients"`
	EndpointBuckets map[string]map[string]*clientBucketWire `json:"endpoint_buckets"`
	Routes          map[string]*routeBucketWire      `json:"routes"`
}

type clientBucketWire struct {
	Tokens       int       `json:"tokens"`
	LastRefill   time.Time `json:"last_refill"`
	RequestCount int       `json:"request_count"`
	BlockedCount int       `json:"blocked_count"`
	FirstRequest time.Time `json:"first_request"`
	LastRequest  time.Time `json:"last_request"`
}

type routeBucketWire struct {
	Tokens       int       `json:"tokens"`
	LastRefill   time.Time `json:"last_refill"`
	RequestCount int       `json:"request_count"`
}

// Snapshot serializes every client / endpoint / route bucket.
func (rl *RateLimiter) Snapshot() ([]byte, error) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	snap := snapshotV1{
		Version:         1,
		SavedAt:         time.Now(),
		Clients:         make(map[string]*clientBucketWire, len(rl.clients)),
		EndpointBuckets: make(map[string]map[string]*clientBucketWire, len(rl.endpointBuckets)),
		Routes:          make(map[string]*routeBucketWire, len(rl.routes)),
	}

	for ip, b := range rl.clients {
		snap.Clients[ip] = clientBucketToWire(b)
	}

	for ep, ipMap := range rl.endpointBuckets {
		inner := make(map[string]*clientBucketWire, len(ipMap))
		for ip, b := range ipMap {
			inner[ip] = clientBucketToWire(b)
		}
		snap.EndpointBuckets[ep] = inner
	}

	for r, b := range rl.routes {
		snap.Routes[r] = &routeBucketWire{
			Tokens:       b.tokens,
			LastRefill:   b.lastRefill,
			RequestCount: b.requestCount,
		}
	}

	return json.Marshal(&snap)
}

// Restore replaces all bucket state. Unknown versions are ignored so an
// older binary doesn't choke on a forward-compatible blob.
func (rl *RateLimiter) Restore(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var snap snapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}

	clients := make(map[string]*clientBucket, len(snap.Clients))
	for ip, w := range snap.Clients {
		clients[ip] = clientBucketFromWire(w)
	}

	endpointBuckets := make(map[string]map[string]*clientBucket, len(snap.EndpointBuckets))
	for ep, ipMap := range snap.EndpointBuckets {
		inner := make(map[string]*clientBucket, len(ipMap))
		for ip, w := range ipMap {
			inner[ip] = clientBucketFromWire(w)
		}
		endpointBuckets[ep] = inner
	}

	routes := make(map[string]*routeBucket, len(snap.Routes))
	for r, w := range snap.Routes {
		routes[r] = &routeBucket{
			tokens:       w.Tokens,
			lastRefill:   w.LastRefill,
			requestCount: w.RequestCount,
		}
	}

	rl.mu.Lock()
	rl.clients = clients
	rl.endpointBuckets = endpointBuckets
	rl.routes = routes
	rl.mu.Unlock()
	return nil
}

func clientBucketToWire(b *clientBucket) *clientBucketWire {
	return &clientBucketWire{
		Tokens:       b.tokens,
		LastRefill:   b.lastRefill,
		RequestCount: b.requestCount,
		BlockedCount: b.blockedCount,
		FirstRequest: b.firstRequest,
		LastRequest:  b.lastRequest,
	}
}

func clientBucketFromWire(w *clientBucketWire) *clientBucket {
	return &clientBucket{
		tokens:       w.Tokens,
		lastRefill:   w.LastRefill,
		requestCount: w.RequestCount,
		blockedCount: w.BlockedCount,
		firstRequest: w.FirstRequest,
		lastRequest:  w.LastRequest,
	}
}
