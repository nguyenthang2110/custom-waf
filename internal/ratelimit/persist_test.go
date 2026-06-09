package ratelimit

import (
	"testing"
	"time"
)

func TestSnapshotRestore_RoundTrip(t *testing.T) {
	// Two configured endpoints: an exact-match auth endpoint and a
	// subtree-prefix entry that covers everything under /app/.
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      10,
		EndpointLimits: map[string]LimitConfig{
			"/api/login": {RequestsPerMin: 5, BurstSize: 2},
			"/app/":      {RequestsPerMin: 30, BurstSize: 5},
		},
	})
	defer rl.Stop()

	// Drive requests through both an exact match and a subtree match so
	// the snapshot exercises every code path.
	rl.IsRateLimitedWithRoute("1.2.3.4", "/app/dashboard")
	rl.IsRateLimitedWithRoute("1.2.3.4", "/app/settings")
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
			"/app/":      {RequestsPerMin: 30, BurstSize: 5},
		},
	})
	defer rl2.Stop()
	if err := rl2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Subtree bucket is keyed by the matched pattern, not the request path,
	// so two requests under /app/* share one bucket per IP.
	rl2.mu.RLock()
	appEP, ok := rl2.endpointBuckets["/app/"]
	rl2.mu.RUnlock()
	if !ok {
		t.Fatal("endpointBuckets[/app/] missing after restore")
	}
	b, ok := appEP["1.2.3.4"]
	if !ok {
		t.Fatal("subtree bucket for 1.2.3.4 missing after restore")
	}
	if b.requestCount != 2 {
		t.Errorf("/app/ bucket requestCount for 1.2.3.4: got %d want 2", b.requestCount)
	}

	// Exact-match endpoint bucket
	rl2.mu.RLock()
	loginEP, ok := rl2.endpointBuckets["/api/login"]
	rl2.mu.RUnlock()
	if !ok {
		t.Fatal("endpointBuckets[/api/login] missing")
	}
	if _, ok := loginEP["9.9.9.9"]; !ok {
		t.Errorf("endpoint bucket for 9.9.9.9 missing")
	}
}

// TestRateLimitPersistedAcrossSimulatedRestart proves the security
// property: a client that just got rate-limited keeps its zero-token
// state across a "restart" — they can't reset by triggering a bounce.
// Uses a configured endpoint so the limiter actually engages under the
// new opt-in semantics.
func TestRateLimitPersistedAcrossSimulatedRestart(t *testing.T) {
	cfg := RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      3,
		EndpointLimits: map[string]LimitConfig{
			"/api/login": {RequestsPerMin: 60, BurstSize: 3},
		},
	}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()

	for i := 0; i < 3; i++ {
		if rl.IsRateLimitedWithRoute("attacker", "/api/login") {
			t.Fatalf("blocked early on iter %d", i)
		}
	}
	// Next request should be blocked (burst exhausted)
	if !rl.IsRateLimitedWithRoute("attacker", "/api/login") {
		t.Fatal("expected rate-limit after burst exhausted")
	}

	blob, err := rl.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Simulate restart: fresh limiter, then restore.
	rl2 := NewRateLimiter(cfg)
	defer rl2.Stop()
	if err := rl2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Tokens should still be at 0 → next request still blocked.
	if !rl2.IsRateLimitedWithRoute("attacker", "/api/login") {
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
	rl := NewRateLimiter(RateLimitConfig{
		EndpointLimits: map[string]LimitConfig{
			"/x": {RequestsPerMin: 60, BurstSize: 5},
		},
	})
	defer rl.Stop()
	rl.IsRateLimitedWithRoute("preserve-me", "/x")
	if err := rl.Restore([]byte(`{"version":99}`)); err != nil {
		t.Fatal(err)
	}
	rl.mu.RLock()
	_, ok := rl.endpointBuckets["/x"]["preserve-me"]
	rl.mu.RUnlock()
	if !ok {
		t.Errorf("unknown-version restore wiped state")
	}
}

func TestSnapshotTimestampsSurvive(t *testing.T) {
	cfg := RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      5,
		EndpointLimits: map[string]LimitConfig{
			"/x": {RequestsPerMin: 60, BurstSize: 5},
		},
	}
	rl := NewRateLimiter(cfg)
	defer rl.Stop()
	before := time.Now()
	rl.IsRateLimitedWithRoute("client-x", "/x")
	after := time.Now()

	blob, _ := rl.Snapshot()
	rl2 := NewRateLimiter(cfg)
	defer rl2.Stop()
	rl2.Restore(blob)

	rl2.mu.RLock()
	b := rl2.endpointBuckets["/x"]["client-x"]
	rl2.mu.RUnlock()
	if b == nil {
		t.Fatal("missing")
	}
	if b.firstRequest.Before(before) || b.firstRequest.After(after) {
		t.Errorf("firstRequest timestamp drifted: %v not in [%v, %v]", b.firstRequest, before, after)
	}
}

// TestUnconfiguredRouteIsNotLimited locks in the new opt-in semantics:
// a request whose route doesn't match any EndpointLimits entry passes
// through, and crucially does NOT create a tracking bucket (no memory
// poisoning via random URL spraying).
func TestUnconfiguredRouteIsNotLimited(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		RequestsPerMin: 1,
		BurstSize:      1,
		EndpointLimits: map[string]LimitConfig{
			"/api/login": {RequestsPerMin: 1, BurstSize: 1},
		},
	})
	defer rl.Stop()

	// 100 hits on an unconfigured path — none should be blocked.
	for i := 0; i < 100; i++ {
		if rl.IsRateLimitedWithRoute("client", "/anything/else") {
			t.Fatalf("unconfigured route was rate-limited on hit %d", i)
		}
	}
	rl.mu.RLock()
	clientCount := len(rl.clients)
	epForRandom, hasRandom := rl.endpointBuckets["/anything/else"]
	rl.mu.RUnlock()
	if clientCount != 0 {
		t.Errorf("expected zero clients tracked for unconfigured path, got %d", clientCount)
	}
	if hasRandom && len(epForRandom) > 0 {
		t.Errorf("expected no endpoint bucket for unconfigured path, got %d entries", len(epForRandom))
	}

	// The configured path should still enforce its limit (burst=1 → 2nd
	// request blocked).
	if rl.IsRateLimitedWithRoute("client", "/api/login") {
		t.Fatal("1st /api/login request unexpectedly blocked")
	}
	if !rl.IsRateLimitedWithRoute("client", "/api/login") {
		t.Fatal("2nd /api/login request should have been blocked (burst=1)")
	}
}

// TestSubtreePrefixMatching locks in the "key ends in /" subtree-match
// behavior plus longest-match-wins resolution.
func TestSubtreePrefixMatching(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{
		EndpointLimits: map[string]LimitConfig{
			"/api/":      {RequestsPerMin: 60, BurstSize: 5},
			"/api/auth/": {RequestsPerMin: 6, BurstSize: 1},
		},
	})
	defer rl.Stop()

	// /api/auth/login should resolve to the longer "/api/auth/" pattern
	// (burst=1), not the shorter "/api/" (burst=5).
	if rl.IsRateLimitedWithRoute("c", "/api/auth/login") {
		t.Fatal("1st request unexpectedly blocked")
	}
	if !rl.IsRateLimitedWithRoute("c", "/api/auth/login") {
		t.Fatal("2nd request should be blocked under /api/auth/ (burst=1)")
	}

	// /api/products falls back to "/api/" (burst=5) — should not be
	// blocked by /api/auth/'s exhausted bucket.
	if rl.IsRateLimitedWithRoute("c", "/api/products") {
		t.Fatal("/api/products wrongly tied to /api/auth/'s bucket")
	}
}
