// internal/ml/persist.go
//
// Snapshot/Restore for the ML subsystem — prediction cache, circuit
// breaker, and the client's aggregate latency / error counters.
//
// Cache: persisting it means a hot restart doesn't have to re-call the
// ml-service for every replayed payload. Entries past their TTL at
// restore time are dropped.
//
// Breaker: persisting state means a WAF restart while the breaker is
// open won't immediately resume hammering an unhealthy downstream — we
// re-enter the same state and let cooldown finish.
//
// Stats: persisting counters means dashboards don't reset to zero on
// every WAF bounce.
package ml

import (
	"container/list"
	"encoding/json"
	"time"
)

// =============================================================================
// Prediction cache
// =============================================================================

type cacheSnapshotV1 struct {
	Version int                `json:"version"`
	SavedAt time.Time          `json:"saved_at"`
	Entries []*cacheEntryWire  `json:"entries"`
	Hits    uint64             `json:"hits"`
	Misses  uint64             `json:"misses"`
}

// cacheEntryWire mirrors cacheEntry but exports its fields for JSON.
// Order in the slice reflects LRU position — front (most recent) first,
// matching list.List ordering — so Restore can replay the access order
// faithfully.
type cacheEntryWire struct {
	Key       string           `json:"key"`
	Value     *PredictResponse `json:"value"`
	ExpiresAt time.Time        `json:"expires_at"`
}

// Snapshot exports the LRU cache. If the cache is nil (disabled in
// config) we return (nil, nil) so the snapshotter skips the row.
func (c *predictionCache) Snapshot() ([]byte, error) {
	if c == nil {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	snap := cacheSnapshotV1{
		Version: 1,
		SavedAt: now,
		Hits:    c.hits,
		Misses:  c.misses,
		Entries: make([]*cacheEntryWire, 0, c.ll.Len()),
	}

	for e := c.ll.Front(); e != nil; e = e.Next() {
		ent := e.Value.(*cacheEntry)
		if now.After(ent.expiresAt) {
			continue
		}
		snap.Entries = append(snap.Entries, &cacheEntryWire{
			Key:       ent.key,
			Value:     ent.value,
			ExpiresAt: ent.expiresAt,
		})
	}
	return json.Marshal(&snap)
}

// Restore rebuilds the LRU from the snapshot. Order is preserved so the
// most-recently-used entries stay at the front.
func (c *predictionCache) Restore(data []byte) error {
	if c == nil || len(data) == 0 {
		return nil
	}
	var snap cacheSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}

	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ll = list.New()
	c.index = make(map[string]*list.Element, c.capacity)
	c.hits = snap.Hits
	c.misses = snap.Misses

	for _, w := range snap.Entries {
		if w == nil || w.Value == nil {
			continue
		}
		if !now.Before(w.ExpiresAt) {
			continue
		}
		// PushBack to preserve the saved order (front first → loop adds
		// to the back so the first wire entry ends up at the front
		// after we reverse-walk… simplest: use PushFront, but iterate
		// in reverse to keep the original order).
		ent := &cacheEntry{
			key:       w.Key,
			value:     w.Value,
			expiresAt: w.ExpiresAt,
		}
		el := c.ll.PushBack(ent)
		c.index[w.Key] = el
		if c.ll.Len() >= c.capacity {
			break
		}
	}
	return nil
}

// =============================================================================
// Circuit breaker
// =============================================================================

type breakerSnapshotV1 struct {
	Version  int       `json:"version"`
	SavedAt  time.Time `json:"saved_at"`
	State    int       `json:"state"`
	Failures int       `json:"failures"`
	OpenedAt time.Time `json:"opened_at"`
}

// Snapshot exports the breaker's state. Threshold / cooldown stay in
// config and are not snapshotted — they should follow the running
// binary, not the saved blob.
func (b *circuitBreaker) Snapshot() ([]byte, error) {
	if b == nil {
		return nil, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return json.Marshal(&breakerSnapshotV1{
		Version:  1,
		SavedAt:  time.Now(),
		State:    int(b.state),
		Failures: b.failures,
		OpenedAt: b.openedAt,
	})
}

// Restore loads breaker state. If the saved state is "open" but the
// cooldown elapsed in the gap between save and restore, we collapse to
// half-open so the first request through gets to probe the downstream.
func (b *circuitBreaker) Restore(data []byte) error {
	if b == nil || len(data) == 0 {
		return nil
	}
	var snap breakerSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state = breakerState(snap.State)
	b.failures = snap.Failures
	b.openedAt = snap.OpenedAt
	if b.state == bsOpen && time.Since(b.openedAt) >= b.cooldown {
		b.state = bsHalfOpen
	}
	return nil
}

// =============================================================================
// Client (latency / call counters) — implemented on *Client itself
// =============================================================================

type clientStatsSnapshotV1 struct {
	Version       int    `json:"version"`
	TotalCalls    uint64 `json:"total_calls"`
	TotalErrors   uint64 `json:"total_errors"`
	TotalLatency  int64  `json:"total_latency_ns"`
	LastErrorText string `json:"last_error_text,omitempty"`
}

// SnapshotStats exports the client's cumulative metrics (totalCalls,
// totalErrors, latency sum, last error message). The mutex is held in
// write mode briefly to read the fields atomically.
func (c *Client) SnapshotStats() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(&clientStatsSnapshotV1{
		Version:       1,
		TotalCalls:    c.totalCalls,
		TotalErrors:   c.totalErrors,
		TotalLatency:  int64(c.totalLatency),
		LastErrorText: c.lastErrorText,
	})
}

// RestoreStats loads cumulative counters. Counters monotonically
// increase, so blindly replacing them is fine — there's no race with
// pending requests on boot (Restore is called before serving traffic).
func (c *Client) RestoreStats(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var snap clientStatsSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}
	c.mu.Lock()
	c.totalCalls = snap.TotalCalls
	c.totalErrors = snap.TotalErrors
	c.totalLatency = time.Duration(snap.TotalLatency)
	c.lastErrorText = snap.LastErrorText
	c.mu.Unlock()
	return nil
}

// =============================================================================
// Exposed Snapshotter adapters
//
// statestore wants a single (Snapshot/Restore) interface per section.
// We expose three thin wrapper types here — one per ML section — that
// adapt the underlying components to that interface without leaking
// private fields out of the package.
// =============================================================================

// CacheSnapshotter wraps the client's prediction cache for statestore.
// Returns nil-method behavior when the cache is disabled.
type CacheSnapshotter struct{ c *Client }

func (c *Client) CacheSnapshotter() *CacheSnapshotter { return &CacheSnapshotter{c: c} }
func (s *CacheSnapshotter) Snapshot() ([]byte, error) {
	if s == nil || s.c == nil || s.c.cache == nil {
		return nil, nil
	}
	return s.c.cache.Snapshot()
}
func (s *CacheSnapshotter) Restore(data []byte) error {
	if s == nil || s.c == nil || s.c.cache == nil {
		return nil
	}
	return s.c.cache.Restore(data)
}

// BreakerSnapshotter wraps the client's circuit breaker.
type BreakerSnapshotter struct{ c *Client }

func (c *Client) BreakerSnapshotter() *BreakerSnapshotter { return &BreakerSnapshotter{c: c} }
func (s *BreakerSnapshotter) Snapshot() ([]byte, error) {
	if s == nil || s.c == nil || s.c.breaker == nil {
		return nil, nil
	}
	return s.c.breaker.Snapshot()
}
func (s *BreakerSnapshotter) Restore(data []byte) error {
	if s == nil || s.c == nil || s.c.breaker == nil {
		return nil
	}
	return s.c.breaker.Restore(data)
}

// StatsSnapshotter wraps the client's aggregate counters.
type StatsSnapshotter struct{ c *Client }

func (c *Client) StatsSnapshotter() *StatsSnapshotter { return &StatsSnapshotter{c: c} }
func (s *StatsSnapshotter) Snapshot() ([]byte, error) {
	if s == nil || s.c == nil {
		return nil, nil
	}
	return s.c.SnapshotStats()
}
func (s *StatsSnapshotter) Restore(data []byte) error {
	if s == nil || s.c == nil {
		return nil
	}
	return s.c.RestoreStats(data)
}

