package engine

import (
	"testing"
	"time"
)

func TestTrackerSnapshotRoundTrip(t *testing.T) {
	tr := NewTracker()
	defer tr.Stop()

	tr.Incr("ip:login_fail:1.2.3.4", 10*time.Minute)
	tr.Incr("ip:login_fail:1.2.3.4", 10*time.Minute)
	tr.Incr("ip:login_fail:1.2.3.4", 10*time.Minute)
	tr.Incr("ip:scanner:5.5.5.5", 5*time.Minute)

	blob, err := tr.SnapshotState()
	if err != nil {
		t.Fatalf("SnapshotState: %v", err)
	}

	tr2 := NewTracker()
	defer tr2.Stop()
	if err := tr2.RestoreState(blob); err != nil {
		t.Fatalf("RestoreState: %v", err)
	}

	if got := tr2.Get("ip:login_fail:1.2.3.4"); got != 3 {
		t.Errorf("login_fail count: got %d want 3", got)
	}
	if got := tr2.Get("ip:scanner:5.5.5.5"); got != 1 {
		t.Errorf("scanner count: got %d want 1", got)
	}
}

// TestTrackerExpiredDropped — expired entries from the snapshot must
// not resurrect on restore. A snapshot taken minutes ago may carry
// keys whose TTL elapsed in the meantime.
func TestTrackerExpiredDropped(t *testing.T) {
	tr := NewTracker()
	defer tr.Stop()

	tr.mu.Lock()
	tr.data["expired"] = &trackEntry{count: 99, expireAt: time.Now().Add(-time.Hour)}
	tr.data["alive"] = &trackEntry{count: 7, expireAt: time.Now().Add(time.Hour)}
	tr.mu.Unlock()

	blob, _ := tr.SnapshotState()
	tr2 := NewTracker()
	defer tr2.Stop()
	tr2.RestoreState(blob)

	if got := tr2.Get("expired"); got != 0 {
		t.Errorf("expired counter survived snapshot/restore: %d", got)
	}
	if got := tr2.Get("alive"); got != 7 {
		t.Errorf("alive counter lost: got %d", got)
	}
}

func TestTrackerRestoreEmptyIsNoop(t *testing.T) {
	tr := NewTracker()
	defer tr.Stop()
	if err := tr.RestoreState(nil); err != nil {
		t.Fatal(err)
	}
	if err := tr.RestoreState([]byte{}); err != nil {
		t.Fatal(err)
	}
}

// TestRuleMetricsRoundTrip — RuleHitCount and CategoryStats must
// survive a snapshot/restore.
func TestRuleMetricsRoundTrip(t *testing.T) {
	re := NewRuleEngine()

	re.metrics.mu.Lock()
	re.metrics.TotalEvaluations = 100
	re.metrics.TotalMatches = 17
	re.metrics.TotalBlocks = 5
	re.metrics.RuleHitCount["sqli-1"] = 12
	re.metrics.RuleHitCount["xss-2"] = 5
	re.metrics.CategoryStats["sqli"] = 12
	re.metrics.CategoryStats["xss"] = 5
	re.metrics.mu.Unlock()

	blob, err := re.SnapshotMetrics()
	if err != nil {
		t.Fatalf("SnapshotMetrics: %v", err)
	}

	re2 := NewRuleEngine()
	if err := re2.RestoreMetrics(blob); err != nil {
		t.Fatalf("RestoreMetrics: %v", err)
	}
	got := re2.GetMetrics()
	if got.TotalEvaluations != 100 || got.TotalMatches != 17 || got.TotalBlocks != 5 {
		t.Errorf("aggregates wrong: %+v", got)
	}
	if got.RuleHitCount["sqli-1"] != 12 || got.RuleHitCount["xss-2"] != 5 {
		t.Errorf("RuleHitCount lost: %v", got.RuleHitCount)
	}
	if got.CategoryStats["sqli"] != 12 || got.CategoryStats["xss"] != 5 {
		t.Errorf("CategoryStats lost: %v", got.CategoryStats)
	}
}
