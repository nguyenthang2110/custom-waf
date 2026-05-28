package ratelimit

import (
	"testing"
	"time"
)

func TestSnapshotRestore_RoundTrip(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      10,
		EndpointLimits: map[string]LimitConfig{
			"/api/login": {RequestsPerMin: 5, BurstSize: 2},
		},
	})
	defer rl.Stop()

	// Drive a real request through both buckets so internal state
	// is the same shape it would be in prod.
	rl.IsRateLimitedWithRoute("1.2.3.4", "/")
	rl.IsRateLimitedWithRoute("1.2.3.4", "/")
	rl.IsRateLimitedWithRoute("9.9.9.9", "/api/login")
	rl.IsRateLimitedWithRoute("9.9.9.9", "/api/login")

	blob, err := rl.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	rl2 := NewRateLimiter(RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      10,
		EndpointLimits: map[string]LimitConfig{
			"/api/login": {RequestsPerMin: 5, BurstSize: 2},
		},
	})
	defer rl2.Stop()
	if err := rl2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Verify client bucket survived
	rl2.mu.RLock()
	b, ok := rl2.clients["1.2.3.4"]
	rl2.mu.RUnlock()
	if !ok {
		t.Fatal("client 1.2.3.4 missing after restore")
	}
	if b.requestCount != 2 {
		t.Errorf("client requestCount: got %d want 2", b.requestCount)
	}

	// Verify endpoint bucket survived
	rl2.mu.RLock()
	ep, ok := rl2.endpointBuckets["/api/login"]
	rl2.mu.RUnlock()
	if !ok {
		t.Fatal("endpointBuckets[/api/login] missing")
	}
	if _, ok := ep["9.9.9.9"]; !ok {
		t.Errorf("endpoint bucket for 9.9.9.9 missing")
	}
}

// TestRateLimitPersistedAcrossSimulatedRestart proves the security
// property: a client that just got rate-limited keeps its zero-token
// state across a "restart" — they can't reset by triggering a bounce.
func TestRateLimitPersistedAcrossSimulatedRestart(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      3,
	})
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if rl.IsRateLimited("attacker") {
			t.Fatalf("blocked early on iter %d", i)
		}
	}
	// Next request should be blocked (burst exhausted)
	if !rl.IsRateLimited("attacker") {
		t.Fatal("expected rate-limit after burst exhausted")
	}

	blob, err := rl.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Simulate restart: fresh limiter, then restore
	rl2 := NewRateLimiter(RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      3,
	})
	defer rl2.Stop()
	if err := rl2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Tokens should still be at 0 → next request still blocked.
	if !rl2.IsRateLimited("attacker") {
		t.Errorf("rate limit reset by restart — attacker would bypass by triggering restart")
	}
}

func TestRestoreEmptyIsNoop(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{})
	defer rl.Stop()
	if err := rl.Restore(nil); err != nil {
		t.Fatal(err)
	}
	if err := rl.Restore([]byte{}); err != nil {
		t.Fatal(err)
	}
}

func TestRestoreBadVersion(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{})
	defer rl.Stop()
	rl.IsRateLimited("preserve-me")
	if err := rl.Restore([]byte(`{"version":99}`)); err != nil {
		t.Fatal(err)
	}
	rl.mu.RLock()
	_, ok := rl.clients["preserve-me"]
	rl.mu.RUnlock()
	if !ok {
		t.Errorf("unknown-version restore wiped state")
	}
}

func TestSnapshotTimestampsSurvive(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{RequestsPerMin: 60, BurstSize: 5})
	defer rl.Stop()
	before := time.Now()
	rl.IsRateLimited("client-x")
	after := time.Now()

	blob, _ := rl.Snapshot()
	rl2 := NewRateLimiter(RateLimitConfig{RequestsPerMin: 60, BurstSize: 5})
	defer rl2.Stop()
	rl2.Restore(blob)

	rl2.mu.RLock()
	b := rl2.clients["client-x"]
	rl2.mu.RUnlock()
	if b == nil {
		t.Fatal("missing")
	}
	if b.firstRequest.Before(before) || b.firstRequest.After(after) {
		t.Errorf("firstRequest timestamp drifted: %v not in [%v, %v]", b.firstRequest, before, after)
	}
}
