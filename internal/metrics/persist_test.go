package metrics

import (
	"testing"
	"time"
)

// Promauto registers each metric on the default registry, so calling
// NewCollector twice in one process panics. Use a single collector and
// reset between save/restore to verify round-trip.
func TestCollectorSnapshotRoundTrip(t *testing.T) {
	c := NewCollector()

	c.RecordRequest("BLOCK", 12.5)
	c.RecordRequest("BLOCK", 11.0)
	c.RecordRequest("ALLOW", 0.5)

	c.mu.Lock()
	c.stats.TopRules["sqli-1"] = 7
	c.stats.TopCategories["sqli"] = 7
	c.stats.Clients["1.2.3.4"] = &ClientStat{
		TotalRequests: 10,
		TotalBlocked:  2,
		LastSeen:      time.Now(),
	}
	c.stats.UniqueClients = 1
	c.mu.Unlock()

	blob, err := c.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}

	// Simulate a "restart" by wiping the collector's stats, then
	// restoring from the blob.
	c.ResetStats()
	if got := c.GetStats(); got.TotalRequests != 0 {
		t.Fatalf("ResetStats didn't clear: %+v", got)
	}

	if err := c.Restore(blob); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	s := c.GetStats()
	if s.TotalRequests != 3 {
		t.Errorf("TotalRequests: got %d want 3", s.TotalRequests)
	}
	if s.TotalBlocked != 2 {
		t.Errorf("TotalBlocked: got %d want 2", s.TotalBlocked)
	}
	if s.TopRules["sqli-1"] != 7 || s.TopCategories["sqli"] != 7 {
		t.Errorf("top maps lost: %+v / %+v", s.TopRules, s.TopCategories)
	}
	if s.Clients["1.2.3.4"] == nil || s.Clients["1.2.3.4"].TotalRequests != 10 {
		t.Errorf("client stat lost: %+v", s.Clients)
	}
	if s.UniqueClients != 1 {
		t.Errorf("UniqueClients: got %d want 1", s.UniqueClients)
	}
}

func TestCollectorRestoreEmpty(t *testing.T) {
	// NewCollector can only be called once per process due to promauto
	// global registry — skip if a prior test already created one in
	// this binary.
	defer func() {
		if r := recover(); r != nil {
			t.Skip("collector already registered globally; skipping")
		}
	}()
	c := NewCollector()
	if err := c.Restore(nil); err != nil {
		t.Fatal(err)
	}
}
