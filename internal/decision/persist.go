// internal/decision/persist.go
//
// Snapshot/Restore for the decision engine's lifetime counters
// (TotalDecisions / Allow / Block / Challenge / Log / Whitelist hits /
// Blacklist hits). Without persistence the dashboard "decisions since
// boot" panels reset on every restart.
package decision

import (
	"encoding/json"
	"time"
)

type statsSnapshotV1 struct {
	Version        int       `json:"version"`
	SavedAt        time.Time `json:"saved_at"`
	TotalDecisions int64     `json:"total_decisions"`
	AllowCount     int64     `json:"allow_count"`
	BlockCount     int64     `json:"block_count"`
	ChallengeCount int64     `json:"challenge_count"`
	LogCount       int64     `json:"log_count"`
	WhitelistHits  int64     `json:"whitelist_hits"`
	BlacklistHits  int64     `json:"blacklist_hits"`
}

// SnapshotStats serializes DecisionStats. Held briefly under the stats
// mutex; doesn't block Decide() because Decide updates stats through
// updateStats (which takes the same lock).
func (de *DecisionEngine) SnapshotStats() ([]byte, error) {
	if de == nil || de.stats == nil {
		return nil, nil
	}
	de.stats.mu.RLock()
	defer de.stats.mu.RUnlock()
	return json.Marshal(&statsSnapshotV1{
		Version:        1,
		SavedAt:        time.Now(),
		TotalDecisions: de.stats.TotalDecisions,
		AllowCount:     de.stats.AllowCount,
		BlockCount:     de.stats.BlockCount,
		ChallengeCount: de.stats.ChallengeCount,
		LogCount:       de.stats.LogCount,
		WhitelistHits:  de.stats.WhitelistHits,
		BlacklistHits:  de.stats.BlacklistHits,
	})
}

// RestoreStats replaces DecisionStats.
func (de *DecisionEngine) RestoreStats(data []byte) error {
	if de == nil || de.stats == nil || len(data) == 0 {
		return nil
	}
	var snap statsSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}
	de.stats.mu.Lock()
	de.stats.TotalDecisions = snap.TotalDecisions
	de.stats.AllowCount = snap.AllowCount
	de.stats.BlockCount = snap.BlockCount
	de.stats.ChallengeCount = snap.ChallengeCount
	de.stats.LogCount = snap.LogCount
	de.stats.WhitelistHits = snap.WhitelistHits
	de.stats.BlacklistHits = snap.BlacklistHits
	de.stats.mu.Unlock()
	return nil
}

// StatsSnapshotter adapts DecisionEngine stats to statestore.
type StatsSnapshotter struct{ de *DecisionEngine }

func (de *DecisionEngine) StatsSnapshotter() *StatsSnapshotter {
	return &StatsSnapshotter{de: de}
}
func (s *StatsSnapshotter) Snapshot() ([]byte, error) { return s.de.SnapshotStats() }
func (s *StatsSnapshotter) Restore(data []byte) error { return s.de.RestoreStats(data) }
