// internal/engine/metrics_persist.go
//
// Snapshot/Restore for the rule engine's RuleMetrics. Without this the
// dashboard's per-rule hit counts and category histogram reset to zero
// on every restart — operationally annoying for long-running rules
// that fire only occasionally.
package engine

import (
	"encoding/json"
	"time"
)

type metricsSnapshotV1 struct {
	Version          int              `json:"version"`
	SavedAt          time.Time        `json:"saved_at"`
	TotalEvaluations int64            `json:"total_evaluations"`
	TotalMatches     int64            `json:"total_matches"`
	TotalBlocks      int64            `json:"total_blocks"`
	AverageEvalTime  time.Duration    `json:"average_eval_time"`
	RuleHitCount     map[string]int64 `json:"rule_hit_count"`
	CategoryStats    map[string]int64 `json:"category_stats"`
}

// SnapshotMetrics serializes RuleMetrics. We snapshot through the same
// lock the recorder uses so the read is atomic relative to in-flight
// evaluations.
func (re *RuleEngine) SnapshotMetrics() ([]byte, error) {
	if re == nil || re.metrics == nil {
		return nil, nil
	}
	re.metrics.mu.RLock()
	defer re.metrics.mu.RUnlock()

	snap := metricsSnapshotV1{
		Version:          1,
		SavedAt:          time.Now(),
		TotalEvaluations: re.metrics.TotalEvaluations,
		TotalMatches:     re.metrics.TotalMatches,
		TotalBlocks:      re.metrics.TotalBlocks,
		AverageEvalTime:  re.metrics.AverageEvalTime,
		RuleHitCount:     copyInt64Map(re.metrics.RuleHitCount),
		CategoryStats:    copyInt64Map(re.metrics.CategoryStats),
	}
	return json.Marshal(&snap)
}

// RestoreMetrics replaces the rule engine's metrics. Hit-count rows for
// rule IDs that no longer exist in the active ruleset are kept around —
// rules can be re-added, and dropping the count would lose history.
func (re *RuleEngine) RestoreMetrics(data []byte) error {
	if re == nil || re.metrics == nil || len(data) == 0 {
		return nil
	}
	var snap metricsSnapshotV1
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	if snap.Version != 1 {
		return nil
	}
	re.metrics.mu.Lock()
	re.metrics.TotalEvaluations = snap.TotalEvaluations
	re.metrics.TotalMatches = snap.TotalMatches
	re.metrics.TotalBlocks = snap.TotalBlocks
	re.metrics.AverageEvalTime = snap.AverageEvalTime
	re.metrics.RuleHitCount = copyInt64Map(snap.RuleHitCount)
	re.metrics.CategoryStats = copyInt64Map(snap.CategoryStats)
	re.metrics.mu.Unlock()
	return nil
}

// MetricsSnapshotter adapts RuleEngine metrics to statestore.
type MetricsSnapshotter struct{ re *RuleEngine }

func (re *RuleEngine) MetricsSnapshotter() *MetricsSnapshotter { return &MetricsSnapshotter{re: re} }
func (s *MetricsSnapshotter) Snapshot() ([]byte, error)        { return s.re.SnapshotMetrics() }
func (s *MetricsSnapshotter) Restore(data []byte) error        { return s.re.RestoreMetrics(data) }

// TrackerSnapshotter adapts the tracker counter store to statestore.
type TrackerSnapshotter struct{ t *Tracker }

func (re *RuleEngine) TrackerSnapshotter() *TrackerSnapshotter {
	return &TrackerSnapshotter{t: re.tracker}
}
func (s *TrackerSnapshotter) Snapshot() ([]byte, error) { return s.t.SnapshotState() }
func (s *TrackerSnapshotter) Restore(data []byte) error { return s.t.RestoreState(data) }

func copyInt64Map(m map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
