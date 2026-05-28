package decision

import "testing"

func TestDecisionStatsRoundTrip(t *testing.T) {
	de := NewDecisionEngine(DecisionConfig{})

	de.stats.mu.Lock()
	de.stats.TotalDecisions = 1000
	de.stats.AllowCount = 750
	de.stats.BlockCount = 200
	de.stats.ChallengeCount = 30
	de.stats.LogCount = 15
	de.stats.WhitelistHits = 3
	de.stats.BlacklistHits = 2
	de.stats.mu.Unlock()

	blob, err := de.SnapshotStats()
	if err != nil {
		t.Fatalf("SnapshotStats: %v", err)
	}

	de2 := NewDecisionEngine(DecisionConfig{})
	if err := de2.RestoreStats(blob); err != nil {
		t.Fatalf("RestoreStats: %v", err)
	}
	s := de2.GetStats()
	if s.TotalDecisions != 1000 || s.AllowCount != 750 || s.BlockCount != 200 {
		t.Errorf("stats lost: %+v", s)
	}
	if s.ChallengeCount != 30 || s.LogCount != 15 {
		t.Errorf("aux counters lost: %+v", s)
	}
	if s.WhitelistHits != 3 || s.BlacklistHits != 2 {
		t.Errorf("hits lost: %+v", s)
	}
}

func TestDecisionStatsRestoreEmpty(t *testing.T) {
	de := NewDecisionEngine(DecisionConfig{})
	if err := de.RestoreStats(nil); err != nil {
		t.Fatal(err)
	}
}
