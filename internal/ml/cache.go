// internal/ml/cache.go
//
// Tiny LRU cache with TTL for ML prediction responses. The same gray-zone
// payload often gets replayed (scanners loop, browser retries, etc.), and a
// model round-trip costs ~50–200 ms — caching the last few thousand answers
// keeps p99 latency flat under attack bursts.
package ml

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type cacheEntry struct {
	key       string
	value     *PredictResponse
	expiresAt time.Time
}

type predictionCache struct {
	mu       sync.Mutex
	capacity int
	ttl      time.Duration
	ll       *list.List // front = most recently used
	index    map[string]*list.Element

	hits   uint64
	misses uint64
}

func newPredictionCache(capacity int, ttl time.Duration) *predictionCache {
	if capacity <= 0 {
		return nil
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &predictionCache{
		capacity: capacity,
		ttl:      ttl,
		ll:       list.New(),
		index:    make(map[string]*list.Element, capacity),
	}
}

// hashKey produces a stable, bounded-length cache key for arbitrary text.
// We hash so that very long bodies don't bloat the index.
func hashKey(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:16]) // 32 hex chars; collision risk negligible
}

func (c *predictionCache) Get(text string) (*PredictResponse, bool) {
	if c == nil {
		return nil, false
	}
	key := hashKey(text)

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.index[key]
	if !ok {
		c.misses++
		return nil, false
	}
	ent := el.Value.(*cacheEntry)
	if time.Now().After(ent.expiresAt) {
		c.ll.Remove(el)
		delete(c.index, key)
		c.misses++
		return nil, false
	}
	c.ll.MoveToFront(el)
	c.hits++
	// Return a shallow copy so callers can't mutate the cached map.
	cp := *ent.value
	return &cp, true
}

func (c *predictionCache) Put(text string, resp *PredictResponse) {
	if c == nil || resp == nil {
		return
	}
	key := hashKey(text)

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.index[key]; ok {
		ent := el.Value.(*cacheEntry)
		ent.value = resp
		ent.expiresAt = time.Now().Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}

	ent := &cacheEntry{
		key:       key,
		value:     resp,
		expiresAt: time.Now().Add(c.ttl),
	}
	el := c.ll.PushFront(ent)
	c.index[key] = el

	// Evict oldest when over capacity.
	for c.ll.Len() > c.capacity {
		oldest := c.ll.Back()
		if oldest == nil {
			break
		}
		c.ll.Remove(oldest)
		delete(c.index, oldest.Value.(*cacheEntry).key)
	}
}

// CacheStats is a snapshot of cache counters.
type CacheStats struct {
	Size     int
	Capacity int
	Hits     uint64
	Misses   uint64
	HitRate  float64
}

func (c *predictionCache) Stats() CacheStats {
	if c == nil {
		return CacheStats{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	total := c.hits + c.misses
	var rate float64
	if total > 0 {
		rate = float64(c.hits) / float64(total)
	}
	return CacheStats{
		Size:     c.ll.Len(),
		Capacity: c.capacity,
		Hits:     c.hits,
		Misses:   c.misses,
		HitRate:  rate,
	}
}
