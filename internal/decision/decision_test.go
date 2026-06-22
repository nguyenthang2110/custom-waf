package decision

import (
	"testing"

	"waf-project/internal/engine"
)

// TestVerdictTiers locks in the two-tier verdict model:
//   - score == 0          → ALLOW   (no rule matched)
//   - 0 < score < block   → MONITOR (matched ≥1 rule, forwarded + flagged)
//   - score >= block      → BLOCK
//
// MonitorThreshold defaults to 0, so any positive score is MONITOR. The ML
// gray-zone clear-to-ALLOW path lives in the middleware (it zeroes the score
// before this layer), so here a zero score is the only ALLOW.
func TestVerdictTiers(t *testing.T) {
	de := NewDecisionEngine(DecisionConfig{BlockThreshold: 5.0}) // MonitorThreshold defaults to 0

	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "ALLOW"},
		{0.1, "MONITOR"},
		{1.0, "MONITOR"},
		{2.9, "MONITOR"},
		{3.0, "MONITOR"},
		{4.9, "MONITOR"},
		{5.0, "BLOCK"},
		{9.9, "BLOCK"},
	}
	for _, c := range cases {
		ev := &engine.EvaluationResult{TotalScore: c.score}
		req := &engine.ParsedRequest{ClientIP: "203.0.113.5", NormalizedPath: "/x"}
		got := de.Decide(ev, req)
		if got != c.want {
			t.Errorf("score %.1f: got %s, want %s", c.score, got, c.want)
		}
	}
}

// TestMonitorThresholdRaisesFloor verifies an operator can raise the monitor
// floor to suppress low-score noise: with MonitorThreshold=3, scores in (0,3)
// fall back to ALLOW.
func TestMonitorThresholdRaisesFloor(t *testing.T) {
	de := NewDecisionEngine(DecisionConfig{BlockThreshold: 5.0, MonitorThreshold: 3.0})

	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "ALLOW"},
		{2.9, "ALLOW"},
		{3.0, "MONITOR"},
		{4.9, "MONITOR"},
		{5.0, "BLOCK"},
	}
	for _, c := range cases {
		ev := &engine.EvaluationResult{TotalScore: c.score}
		req := &engine.ParsedRequest{ClientIP: "203.0.113.5", NormalizedPath: "/x"}
		got := de.Decide(ev, req)
		if got != c.want {
			t.Errorf("score %.1f (floor 3): got %s, want %s", c.score, got, c.want)
		}
	}
}
