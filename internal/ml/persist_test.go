package ml

import (
	"testing"
	"time"
)

func TestCacheSnapshotRoundTrip(t *testing.T) {
	c := newPredictionCache(10, 5*time.Minute)

	c.Put("payload-1", &PredictResponse{Label: "attack", IsAttack: true, Confidence: 0.9})
	c.Put("payload-2", &PredictResponse{Label: "benign", IsAttack: false, Confidence: 0.95})
	if _, ok := c.Get("payload-1"); !ok {
		t.Fatal("cache put then get failed pre-snapshot")
	}

	blob, err := c.Snapshot()
	if err != nil {
		t.Fatalf("cache Snapshot: %v", err)
	}

	c2 := newPredictionCache(10, 5*time.Minute)
	if err := c2.Restore(blob); err != nil {
		t.Fatalf("cache Restore: %v", err)
	}

	resp, ok := c2.Get("payload-1")
	if !ok {
		t.Errorf("payload-1 missing after restore")
	}
	if resp != nil && !resp.IsAttack {
		t.Errorf("IsAttack lost: %+v", resp)
	}
	if _, ok := c2.Get("payload-2"); !ok {
		t.Errorf("payload-2 missing after restore")
	}
}

// TestCacheExpiredEntriesDropped — entries past TTL at restore time
// must not resurrect.
func TestCacheExpiredEntriesDropped(t *testing.T) {
	c := newPredictionCache(10, 5*time.Minute)
	// Inject an already-expired entry directly.
	c.Put("stale", &PredictResponse{Label: "attack"})
	c.mu.Lock()
	for _, el := range c.index {
		ent := el.Value.(*cacheEntry)
		ent.expiresAt = time.Now().Add(-time.Hour)
	}
	c.mu.Unlock()

	blob, _ := c.Snapshot()
	c2 := newPredictionCache(10, 5*time.Minute)
	c2.Restore(blob)
	if _, ok := c2.Get("stale"); ok {
		t.Errorf("expired entry resurrected via snapshot/restore")
	}
}

func TestBreakerSnapshotRoundTrip(t *testing.T) {
	b := newCircuitBreaker(3, 30*time.Second)
	b.recordFailure()
	b.recordFailure()
	b.recordFailure() // → open

	blob, err := b.Snapshot()
	if err != nil {
		t.Fatalf("breaker Snapshot: %v", err)
	}
	if b.State() != "open" {
		t.Fatalf("pre-snapshot state: %s want open", b.State())
	}

	b2 := newCircuitBreaker(3, 30*time.Second)
	if err := b2.Restore(blob); err != nil {
		t.Fatalf("breaker Restore: %v", err)
	}
	if b2.State() != "open" {
		t.Errorf("breaker state lost: got %s want open", b2.State())
	}
}

// TestBreakerCooldownExpiresDuringRestart — if the breaker was open
// but the cooldown elapsed in the gap, restore collapses to half-open.
func TestBreakerCooldownExpiresDuringRestart(t *testing.T) {
	b := newCircuitBreaker(3, 10*time.Millisecond)
	b.recordFailure()
	b.recordFailure()
	b.recordFailure()
	blob, _ := b.Snapshot()
	time.Sleep(20 * time.Millisecond)

	b2 := newCircuitBreaker(3, 10*time.Millisecond)
	b2.Restore(blob)
	if got := b2.State(); got != "half-open" {
		t.Errorf("cooled-down breaker state: got %s want half-open", got)
	}
}

func TestClientStatsRoundTrip(t *testing.T) {
	c := NewClient(Config{Endpoint: "http://example.invalid", Enabled: true})
	c.recordSuccess(100 * time.Millisecond)
	c.recordError("test error", 50*time.Millisecond)

	blob, err := c.SnapshotStats()
	if err != nil {
		t.Fatalf("SnapshotStats: %v", err)
	}

	c2 := NewClient(Config{Endpoint: "http://example.invalid", Enabled: true})
	if err := c2.RestoreStats(blob); err != nil {
		t.Fatalf("RestoreStats: %v", err)
	}

	s := c2.Stats()
	if s.TotalCalls != 2 {
		t.Errorf("TotalCalls: got %d want 2", s.TotalCalls)
	}
	if s.TotalErrors != 1 {
		t.Errorf("TotalErrors: got %d want 1", s.TotalErrors)
	}
	if s.LastErrorText != "test error" {
		t.Errorf("LastErrorText lost: %q", s.LastErrorText)
	}
}
