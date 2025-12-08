package engine

import (
	"regexp"
	"sync"
	"time"
)

type Pattern struct {
	Type      string   `json:"type"`
	Pattern   string   `json:"pattern,omitempty"`
	Flags     string   `json:"flags,omitempty"`
	Tokens    []string `json:"tokens,omitempty"`
	Proximity int      `json:"proximity,omitempty"`
	Order     string   `json:"order,omitempty"`
}

type RuleConditions struct {
	Targets      []string `json:"targets"`
	Methods      []string `json:"methods"`
	PathPatterns []string `json:"path_patterns"`
}

type RuleScoring struct {
	AnomalyScore       int     `json:"anomaly_score"`
	SeverityMultiplier float64 `json:"severity_multiplier"`
}

type RuleExceptions struct {
	IPs        []string `json:"ips"`
	UserAgents []string `json:"user_agents"`
	Paths      []string `json:"paths"`
}

type RuleMetadata struct {
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
}

type Rule struct {
	ID               string         `json:"id"`
	Version          string         `json:"version"`
	Enabled          bool           `json:"enabled"`
	Metadata         RuleMetadata   `json:"metadata"`
	Conditions       RuleConditions `json:"conditions"`
	Transforms       []string       `json:"transforms"`
	Patterns         []Pattern      `json:"patterns"`
	Scoring          RuleScoring    `json:"scoring"`
	Exceptions       RuleExceptions `json:"exceptions"`
	compiledPatterns []*regexp.Regexp
	compiledOnce     sync.Once
}

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

type MatcherFunc func(*Pattern, string) (bool, int)

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
}

type EvaluationResult struct {
	TotalScore     float64
	MatchedRules   []MatchResult
	Decision       string
	DecisionReason string
	EvalTime       time.Duration
}

type RuleMetrics struct {
	TotalEvaluations int64
	TotalMatches     int64
	TotalBlocks      int64
	AverageEvalTime  time.Duration
	RuleHitCount     map[string]int64
	CategoryStats    map[string]int64
	mu               sync.RWMutex
}
