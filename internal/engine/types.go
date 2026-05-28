// internal/engine/types.go
//
// Schema v2 — canonical internal representation.
// Loader (loader.go) accepts both v1 and v2 JSON and converts to this.
//
// Public types (ParsedRequest, EvaluationResult, MatchResult, RuleSummary,
// RuleMetrics) are kept backwards-compatible with v1 callers — fields are
// added but never removed/renamed.
package engine

import (
	"regexp"
	"sync"
	"time"
)

// =========================================================================
// Rule v2 — canonical form
// =========================================================================

// Rule is the v2 internal representation of a WAF rule.
// JSON tags reflect the v2 wire format; loader handles v1 input separately.
type Rule struct {
	ID      string `json:"id"`
	Version string `json:"version,omitempty"`
	Enabled bool   `json:"enabled"`

	Info       RuleInfo       `json:"info"`
	When       RuleWhen       `json:"when,omitempty"`
	Inspect    []InputSel     `json:"inspect"`
	Transforms []string       `json:"transforms,omitempty"`
	Detect     RuleDetect     `json:"detect"`
	Action     RuleAction     `json:"action"`
	Except     RuleExcept     `json:"except,omitempty"`

	// --- runtime / compiled ---
	compiled     compiledRule
	compiledOnce sync.Once
}

// RuleInfo — metadata.
type RuleInfo struct {
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	References  []string `json:"references,omitempty"`
	Author      string   `json:"author,omitempty"`
	Created     string   `json:"created,omitempty"`
	Updated     string   `json:"updated,omitempty"`
}

// RuleWhen — pre-filter: must all be satisfied (per-field OR, between fields AND).
type RuleWhen struct {
	Methods        []string `json:"methods,omitempty"`
	PathPrefix     []string `json:"path_prefix,omitempty"`
	PathExclude    []string `json:"path_exclude,omitempty"`
	MinScore       float64  `json:"min_score,omitempty"`
	MaxScore       float64  `json:"max_score,omitempty"`
	RequireLabels  []string `json:"require_labels,omitempty"`
	ExcludeLabels  []string `json:"exclude_labels,omitempty"`
}

// InputSel — one selector (where to read input from).
type InputSel struct {
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
}

// RuleDetect — match logic.
type RuleDetect struct {
	Logic    string    `json:"logic,omitempty"` // "any" (default) | "all"
	Patterns []Pattern `json:"patterns"`
}

// Pattern — one match leaf.
type Pattern struct {
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Values []string `json:"values,omitempty"`
	Flags  string `json:"flags,omitempty"`
	Negate bool   `json:"negate,omitempty"`
}

// RuleAction — what to do when rule matches.
type RuleAction struct {
	Score     float64  `json:"score"`
	Labels    []string `json:"labels,omitempty"`
	Log       bool     `json:"log"`
	Block     bool     `json:"block,omitempty"`
	Challenge bool     `json:"challenge,omitempty"`

	MLConfirm *MLConfirm `json:"ml_confirm,omitempty"`
	Track     *TrackCfg  `json:"track,omitempty"`
}

// MLConfirm — optional ML re-evaluation of a match.
type MLConfirm struct {
	Enabled          bool    `json:"enabled"`
	Input            string  `json:"input,omitempty"`              // body/args/query/uri/headers_all
	MinConfidence    float64 `json:"min_confidence,omitempty"`     // 0..1
	OnAttackAdd      float64 `json:"on_attack_add,omitempty"`
	OnNormalSubtract float64 `json:"on_normal_subtract,omitempty"`
}

// TrackCfg — count rule matches per identity, trigger when threshold hit.
type TrackCfg struct {
	Enabled            bool     `json:"enabled"`
	Scope              string   `json:"scope,omitempty"`               // ip | session | global
	Counter            string   `json:"counter,omitempty"`             // default = rule ID
	TTLMinutes         int      `json:"ttl_minutes,omitempty"`         // default 10
	Threshold          int      `json:"threshold,omitempty"`           // default 5
	OnThresholdScore   float64  `json:"on_threshold_score,omitempty"`  // extra score
	OnThresholdLabels  []string `json:"on_threshold_labels,omitempty"` // extra labels
}

// RuleExcept — whitelist conditions.
type RuleExcept struct {
	IPs           []string `json:"ips,omitempty"`
	Paths         []string `json:"paths,omitempty"`
	PathPrefixes  []string `json:"path_prefixes,omitempty"`
	UserAgents    []string `json:"user_agents,omitempty"`
	Labels        []string `json:"labels,omitempty"`
}

// =========================================================================
// Compilation cache (per-rule, populated once at load)
// =========================================================================

type compiledRule struct {
	// One compiled regex per pattern with Type=="regex". Nil for other types.
	regexes []*regexp.Regexp
	// Lowercase wordlist values for fast match.
	wordlists [][]string
	// Pre-parsed numeric value for entropy_gt/length_gt/length_lt.
	numerics []float64
	// Parsed CIDR networks for ip_match.
	// Stored as raw strings for now — operators.go parses on hot path
	// only if input is non-empty; cheap.

	// Effective severity multiplier (auto from severity).
	sevMul float64
}

// =========================================================================
// Public types kept backwards-compatible with v1 callers
// =========================================================================

// ParsedRequest — unchanged from v1 (callers in middleware/audit/training depend on this).
type ParsedRequest struct {
	RequestID       string
	Timestamp       time.Time
	RawMethod       string
	RawPath         string
	RawQuery        string
	RawBody         []byte
	RawHeaders      map[string][]string
	HeaderCount     int
	ClientIP        string
	Method          string
	Protocol        string
	Host            string
	UserAgent       string
	ContentType     string
	Cookies         map[string]string
	BodySize        int
	NormalizedPath  string
	NormalizedQuery string
	NormalizedBody  string
}

// MatchResult — one rule match. Fields preserved from v1.
type MatchResult struct {
	Matched   bool
	RuleID    string
	RuleName  string
	MatchedOn string
	Pattern   string
	Value     string
	Offset    int
	Timestamp time.Time
	Score     float64
	Severity  string
	Category  string
	// v2 additions:
	Labels []string `json:",omitempty"`
}

// EvaluationResult — overall outcome. v1 fields preserved; v2 additions appended.
type EvaluationResult struct {
	TotalScore     float64
	MatchedRules   []MatchResult
	Decision       string
	DecisionReason string
	EvalTime       time.Duration

	// --- v2 additions (decision engine may use; nil/empty safe for v1 callers) ---
	BucketScores map[string]float64 `json:",omitempty"`
	Labels       []string           `json:",omitempty"`
}

// HasLabel returns true if the request was tagged with the given label.
func (e *EvaluationResult) HasLabel(l string) bool {
	for _, x := range e.Labels {
		if x == l {
			return true
		}
	}
	return false
}

// BucketScore returns the score for a category bucket (0 if absent).
func (e *EvaluationResult) BucketScore(name string) float64 {
	if e.BucketScores == nil {
		return 0
	}
	return e.BucketScores[name]
}

// RuleSummary — lightweight rule view for the API/dashboard.
type RuleSummary struct {
	ID           string   `json:"id"`
	Version      string   `json:"version,omitempty"`
	Enabled      bool     `json:"enabled"`
	Category     string   `json:"category"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Targets      []string `json:"targets,omitempty"` // legacy: inspect sources
	Methods      []string `json:"methods,omitempty"`
	AnomalyScore int      `json:"anomaly_score"`
	PatternCount int      `json:"pattern_count"`
	HitCount     int64    `json:"hit_count"`
}

// RuleMetrics — aggregate stats.
type RuleMetrics struct {
	TotalEvaluations int64
	TotalMatches     int64
	TotalBlocks      int64
	AverageEvalTime  time.Duration
	RuleHitCount     map[string]int64
	CategoryStats    map[string]int64
	mu               sync.RWMutex
}

// =========================================================================
// Severity → score multiplier
// =========================================================================

func severityMultiplier(sev string) float64 {
	switch sev {
	case "critical":
		return 2.0
	case "high":
		return 1.5
	case "medium":
		return 1.0
	case "low":
		return 0.5
	case "info":
		return 0.0
	}
	return 1.0
}
