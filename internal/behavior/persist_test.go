package behavior

import (
	"testing"
	"time"
)

// TestSnapshotRestore_RoundTrip verifies that Snapshot followed by
// Restore on a fresh detector reproduces the original counters.
// This is the security-critical property: an attacker can't reset
// brute-force counters by triggering a WAF restart.
func TestSnapshotRestore_RoundTrip(t *testing.T) {
	d := NewDetector(BehaviorConfig{
		BruteForceThreshold: 5,
		BruteForceWindow:    5 * time.Minute,
	})
	defer d.Stop()

	now := time.Now()
	// Populate the detector with state that mirrors what Analyze would
	// produce in a real run: a couple of IPs with mixed counts, a
	// session, a path.
	d.mu.Lock()
	d.ipStats["1.2.3.4"] = &ipStatistics{
		failedAttempts:     4,
		successfulAttempts: 1,
		totalRequests:      5,
		firstAttempt:       now.Add(-2 * time.Minute),
		lastAttempt:        now,
		uniquePaths:        map[string]bool{"/login": true, "/admin": true},
		uniqueUserAgents:   map[string]bool{"curl/7.0": true},
		requestTimestamps:  []time.Time{now.Add(-time.Minute), now},
		suspicionScore:     0.75,
		isSuspicious:       true,
		isBot:              false,
		detectedAttacks:    map[string]int{"sqli": 2, "xss": 1},
	}
	d.ipStats["5.6.7.8"] = &ipStatistics{
		failedAttempts:    0,
		totalRequests:     1,
		firstAttempt:      now,
		lastAttempt:       now,
		uniquePaths:       map[string]bool{"/": true},
		uniqueUserAgents:  map[string]bool{"Mozilla/5.0": true},
		requestTimestamps: []time.Time{now},
		detectedAttacks:   map[string]int{},
	}
	d.sessionStats["sess-1"] = &sessionStatistics{
		sessionID:    "sess-1",
		ipAddress:    "1.2.3.4",
		userAgent:    "curl/7.0",
		createdAt:    now.Add(-5 * time.Minute),
		lastActivity: now,
		requestCount: 5,
	}
	d.pathStats["/login"] = &pathStatistics{
		path:           "/login",
		totalAccess:    10,
		uniqueIPs:      map[string]bool{"1.2.3.4": true, "5.6.7.8": true},
		failedAttempts: 4,
		lastAccess:     now,
	}
	d.mu.Unlock()

	blob, err := d.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot failed: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("Snapshot returned empty blob")
	}

	d2 := NewDetector(BehaviorConfig{})
	defer d2.Stop()
	if err := d2.Restore(blob); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}

	d2.mu.RLock()
	defer d2.mu.RUnlock()

	got, ok := d2.ipStats["1.2.3.4"]
	if !ok {
		t.Fatal("ipStats[1.2.3.4] missing after restore")
	}
	if got.failedAttempts != 4 {
		t.Errorf("failedAttempts: got %d want 4", got.failedAttempts)
	}
	if got.totalRequests != 5 {
		t.Errorf("totalRequests: got %d want 5", got.totalRequests)
	}
	if got.suspicionScore != 0.75 {
		t.Errorf("suspicionScore: got %v want 0.75", got.suspicionScore)
	}
	if !got.isSuspicious {
		t.Errorf("isSuspicious lost")
	}
	if got.detectedAttacks["sqli"] != 2 || got.detectedAttacks["xss"] != 1 {
		t.Errorf("detectedAttacks lost: %v", got.detectedAttacks)
	}
	if !got.uniquePaths["/login"] || !got.uniquePaths["/admin"] {
		t.Errorf("uniquePaths lost: %v", got.uniquePaths)
	}

	if _, ok := d2.sessionStats["sess-1"]; !ok {
		t.Errorf("sessionStats lost")
	}
	if _, ok := d2.pathStats["/login"]; !ok {
		t.Errorf("pathStats lost")
	}
}

// TestRestoreSkipsBadVersion guards against silently zeroing the state
// when we read a future-version blob we don't understand.
func TestRestoreSkipsBadVersion(t *testing.T) {
	d := NewDetector(BehaviorConfig{})
	defer d.Stop()
	d.mu.Lock()
	d.ipStats["1.1.1.1"] = &ipStatistics{
		failedAttempts:    7,
		uniquePaths:       map[string]bool{},
		uniqueUserAgents:  map[string]bool{},
		requestTimestamps: []time.Time{},
		detectedAttacks:   map[string]int{},
	}
	d.mu.Unlock()

	if err := d.Restore([]byte(`{"version":999}`)); err != nil {
		t.Fatalf("Restore(unknown version) returned error: %v", err)
	}
	d.mu.RLock()
	got := d.ipStats["1.1.1.1"]
	d.mu.RUnlock()
	if got == nil || got.failedAttempts != 7 {
		t.Errorf("Unknown-version restore wiped state — got %+v", got)
	}
}

// TestRestoreEmptyIsNoop — receiving an empty blob (no row in DB)
// must not panic.
func TestRestoreEmptyIsNoop(t *testing.T) {
	d := NewDetector(BehaviorConfig{})
	defer d.Stop()
	if err := d.Restore(nil); err != nil {
		t.Fatalf("Restore(nil): %v", err)
	}
	if err := d.Restore([]byte{}); err != nil {
		t.Fatalf("Restore(empty): %v", err)
	}
}

// TestSnapshotCapsRequestTimestamps — paranoia: a hot IP with 10k
// timestamps shouldn't bloat the snapshot blob.
func TestSnapshotCapsRequestTimestamps(t *testing.T) {
	d := NewDetector(BehaviorConfig{})
	defer d.Stop()

	now := time.Now()
	tsList := make([]time.Time, 0, 1000)
	for i := 0; i < 1000; i++ {
		tsList = append(tsList, now.Add(time.Duration(-i)*time.Second))
	}
	d.mu.Lock()
	d.ipStats["9.9.9.9"] = &ipStatistics{
		firstAttempt:      tsList[len(tsList)-1],
		lastAttempt:       tsList[0],
		uniquePaths:       map[string]bool{},
		uniqueUserAgents:  map[string]bool{},
		requestTimestamps: tsList,
		detectedAttacks:   map[string]int{},
	}
	d.mu.Unlock()

	blob, err := d.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	d2 := NewDetector(BehaviorConfig{})
	defer d2.Stop()
	if err := d2.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	d2.mu.RLock()
	got := d2.ipStats["9.9.9.9"]
	d2.mu.RUnlock()
	if got == nil {
		t.Fatal("missing")
	}
	if len(got.requestTimestamps) > requestTimestampsCap {
		t.Errorf("timestamps not capped: got %d > %d", len(got.requestTimestamps), requestTimestampsCap)
	}
}
