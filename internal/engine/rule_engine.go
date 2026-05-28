// internal/engine/rule_engine.go
//
// V2 rule engine — evaluates parsed HTTP requests against the ruleset.
//
// Evaluation pipeline per rule:
//   1. when         — pre-filter (methods, paths, score gate, labels)
//   2. except       — whitelist (IPs, paths, UAs, labels)
//   3. inspect      — extract input values from request
//   4. transforms   — chain (per rule)
//   5. detect       — boolean tree (any/all) of pattern leaves
//   6. action       — score, labels, log, block, ML confirm, track
//
// Public API surface is preserved from v1 so existing callers
// (middleware/audit/decision) keep working without changes.
package engine

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// =========================================================================
// RuleEngine
// =========================================================================

type RuleEngine struct {
	mu        sync.RWMutex
	rules     []*Rule
	ruleCache map[string]*Rule

	// Thresholds for backwards-compat string Decision (BLOCK/CHALLENGE/LOG/ALLOW).
	// Real block decision is made by internal/decision; engine only computes a hint.
	blockThreshold     float64
	challengeThreshold float64
	logThreshold       float64

	transformFuncs map[string]TransformFunc

	mlPred  MLPredictor
	tracker *Tracker

	metrics *RuleMetrics
}

// NewRuleEngine — preserves v1 constructor signature.
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:              make([]*Rule, 0),
		ruleCache:          make(map[string]*Rule),
		blockThreshold:     10.0,
		challengeThreshold: 5.0,
		logThreshold:       3.0,
		transformFuncs:     builtinTransforms,
		tracker:            NewTracker(),
		metrics: &RuleMetrics{
			RuleHitCount:  make(map[string]int64),
			CategoryStats: make(map[string]int64),
		},
	}
}

// SetMLPredictor — wire ML adapter (call from main before serving).
func (re *RuleEngine) SetMLPredictor(p MLPredictor) {
	re.mu.Lock()
	re.mlPred = p
	re.mu.Unlock()
}

// SetThresholds — for decision hint computation.
func (re *RuleEngine) SetThresholds(block, challenge, logT float64) {
	re.mu.Lock()
	re.blockThreshold = block
	re.challengeThreshold = challenge
	re.logThreshold = logT
	re.mu.Unlock()
}

// Tracker exposes the internal counter store (read-only intent).
func (re *RuleEngine) Tracker() *Tracker { return re.tracker }

// =========================================================================
// Loading (preserves v1 API surface)
// =========================================================================

func (re *RuleEngine) LoadRulesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}
	return re.LoadRulesFromJSON(data)
}

func (re *RuleEngine) LoadRulesFromJSON(data []byte) error {
	rules, err := ParseRules(data)
	if err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}
	for _, r := range rules {
		if err := re.addRule(r); err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	return nil
}

// ValidateRulesJSON returns (validCount, error). Error == nil means all
// rules in the file are valid.
func (re *RuleEngine) ValidateRulesJSON(data []byte) (int, error) {
	rules, err := ParseRules(data)
	if err != nil {
		return 0, fmt.Errorf("invalid JSON format: %w", err)
	}
	if len(rules) == 0 {
		return 0, fmt.Errorf("no rules found in file")
	}
	seen := make(map[string]bool)
	var errs []string
	count := 0
	for i, r := range rules {
		if err := validateRule(r, seen); err != nil {
			errs = append(errs, fmt.Sprintf("rule #%d (%s): %v", i, r.ID, err))
			continue
		}
		count++
	}
	if len(errs) > 0 {
		return count, fmt.Errorf("validation errors: %s", strings.Join(errs, "; "))
	}
	return count, nil
}

// ReloadRules atomically replaces all rules. Hot-reload path.
func (re *RuleEngine) ReloadRules(data []byte) error {
	if _, err := re.ValidateRulesJSON(data); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}
	rules, err := ParseRules(data)
	if err != nil {
		return err
	}
	prepared := make([]*Rule, 0, len(rules))
	cache := make(map[string]*Rule)
	for _, r := range rules {
		compileRule(r)
		prepared = append(prepared, r)
		cache[r.ID] = r
	}
	re.mu.Lock()
	re.rules = prepared
	re.ruleCache = cache
	re.mu.Unlock()
	// Reset per-rule counters
	re.metrics.mu.Lock()
	re.metrics.RuleHitCount = make(map[string]int64)
	re.metrics.CategoryStats = make(map[string]int64)
	re.metrics.mu.Unlock()
	return nil
}

func (re *RuleEngine) addRule(r *Rule) error {
	seen := make(map[string]bool)
	re.mu.RLock()
	for id := range re.ruleCache {
		seen[id] = true
	}
	re.mu.RUnlock()
	if err := validateRule(r, seen); err != nil {
		return err
	}
	compileRule(r)
	re.mu.Lock()
	re.rules = append(re.rules, r)
	re.ruleCache[r.ID] = r
	re.mu.Unlock()
	return nil
}

// =========================================================================
// Validation
// =========================================================================

var (
	validCategories = map[string]bool{
		"sqli": true, "xss": true, "lfi": true, "rce": true, "ssrf": true,
		"xxe": true, "nosqli": true, "scanner": true, "bot": true, "ato": true,
		"dos": true, "info_leak": true, "schema": true, "custom": true,
	}
	validSeverities = map[string]bool{
		"critical": true, "high": true, "medium": true, "low": true, "info": true,
	}
	validTrackScopes = map[string]bool{"ip": true, "session": true, "global": true}
)

func validateRule(r *Rule, seen map[string]bool) error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if seen[r.ID] {
		return fmt.Errorf("duplicate id %q", r.ID)
	}
	seen[r.ID] = true

	if r.Info.Category == "" {
		return fmt.Errorf("info.category is required")
	}
	if !validCategories[r.Info.Category] {
		return fmt.Errorf("info.category %q invalid", r.Info.Category)
	}
	if r.Info.Severity == "" {
		r.Info.Severity = "medium"
	}
	if !validSeverities[r.Info.Severity] {
		return fmt.Errorf("info.severity %q invalid", r.Info.Severity)
	}
	if len(r.Inspect) == 0 {
		return fmt.Errorf("inspect requires at least one selector")
	}
	if len(r.Detect.Patterns) == 0 {
		return fmt.Errorf("detect.patterns requires at least one pattern")
	}
	if r.Detect.Logic == "" {
		r.Detect.Logic = "any"
	}
	if r.Detect.Logic != "any" && r.Detect.Logic != "all" {
		return fmt.Errorf("detect.logic %q must be any or all", r.Detect.Logic)
	}
	if r.Action.Track != nil && r.Action.Track.Enabled {
		if !validTrackScopes[r.Action.Track.Scope] {
			return fmt.Errorf("action.track.scope %q invalid", r.Action.Track.Scope)
		}
		if r.Action.Track.Threshold <= 0 {
			r.Action.Track.Threshold = 5
		}
		if r.Action.Track.TTLMinutes <= 0 {
			r.Action.Track.TTLMinutes = 10
		}
		if r.Action.Track.Counter == "" {
			r.Action.Track.Counter = r.ID
		}
	}
	if r.Action.MLConfirm != nil && r.Action.MLConfirm.Enabled {
		if r.Action.MLConfirm.MinConfidence < 0 || r.Action.MLConfirm.MinConfidence > 1 {
			return fmt.Errorf("action.ml_confirm.min_confidence must be 0..1")
		}
		if r.Action.MLConfirm.Input == "" {
			r.Action.MLConfirm.Input = "body"
		}
	}
	return nil
}

// =========================================================================
// Evaluation
// =========================================================================

// Evaluate runs all enabled rules against the request and returns the
// aggregated result.
func (re *RuleEngine) Evaluate(req *ParsedRequest) *EvaluationResult {
	start := time.Now()

	re.mu.RLock()
	rules := re.rules
	mlPred := re.mlPred
	re.mu.RUnlock()

	result := &EvaluationResult{
		TotalScore:   0,
		MatchedRules: make([]MatchResult, 0),
		Decision:     "ALLOW",
		BucketScores: make(map[string]float64),
		Labels:       []string{},
	}
	labelSet := make(map[string]struct{})

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		// when — pre-filter
		if !matchesWhen(rule, req, result, labelSet) {
			continue
		}
		// except — skip if any whitelist matches
		if matchesExcept(rule, req, labelSet) {
			continue
		}

		// inspect → transform → detect
		hit, matchedOn, matchedPattern, matchedValue, offset := evaluateDetect(rule, req)
		if !hit {
			continue
		}

		// Compute contribution
		score := rule.Action.Score * rule.compiled.sevMul

		// ML confirm
		if rule.Action.MLConfirm != nil && rule.Action.MLConfirm.Enabled {
			delta, extraLabels := runMLConfirm(mlPred, rule.Action.MLConfirm, req)
			score += delta
			for _, l := range extraLabels {
				if _, ok := labelSet[l]; !ok {
					labelSet[l] = struct{}{}
					result.Labels = append(result.Labels, l)
				}
			}
		}

		// Track
		var trackHit bool
		if rule.Action.Track != nil && rule.Action.Track.Enabled {
			t := rule.Action.Track
			id := resolveIdentity(t.Scope, req)
			key := trackKey(t.Scope, t.Counter, id)
			n := re.tracker.Incr(key, time.Duration(t.TTLMinutes)*time.Minute)
			if n >= t.Threshold {
				trackHit = true
				score += t.OnThresholdScore
				for _, l := range t.OnThresholdLabels {
					if _, ok := labelSet[l]; !ok {
						labelSet[l] = struct{}{}
						result.Labels = append(result.Labels, l)
					}
				}
			}
		}

		// Update labels from action.labels
		for _, l := range rule.Action.Labels {
			if _, ok := labelSet[l]; !ok {
				labelSet[l] = struct{}{}
				result.Labels = append(result.Labels, l)
			}
		}

		// Aggregate
		mr := MatchResult{
			Matched:   true,
			RuleID:    rule.ID,
			RuleName:  rule.Info.Description,
			MatchedOn: matchedOn,
			Pattern:   matchedPattern,
			Value:     truncate(matchedValue, 4096),
			Offset:    offset,
			Timestamp: time.Now(),
			Score:     score,
			Severity:  rule.Info.Severity,
			Category:  rule.Info.Category,
			Labels:    rule.Action.Labels,
		}
		result.MatchedRules = append(result.MatchedRules, mr)
		result.TotalScore += score
		result.BucketScores[rule.Info.Category] += score

		// Force block from rule action
		if rule.Action.Block || trackHit && rule.Action.Track != nil && rule.Action.Track.OnThresholdScore >= re.blockThreshold {
			result.Decision = "BLOCK"
		}

		re.updateMetrics(rule.ID, rule.Info.Category)
	}

	// Decision hint (final decision is up to internal/decision)
	if result.Decision != "BLOCK" {
		result.Decision = re.determineDecision(result.TotalScore)
	}
	result.DecisionReason = fmt.Sprintf("Score: %.2f, Threshold: %.2f",
		result.TotalScore, re.blockThreshold)
	result.EvalTime = time.Since(start)

	re.metrics.mu.Lock()
	re.metrics.TotalEvaluations++
	if len(result.MatchedRules) > 0 {
		re.metrics.TotalMatches++
	}
	if result.Decision == "BLOCK" {
		re.metrics.TotalBlocks++
	}
	re.metrics.mu.Unlock()

	return result
}

// =========================================================================
// Filtering
// =========================================================================

func matchesWhen(rule *Rule, req *ParsedRequest, partial *EvaluationResult, labelSet map[string]struct{}) bool {
	w := &rule.When
	if len(w.Methods) > 0 {
		if !containsIgnoreCase(w.Methods, req.Method) {
			return false
		}
	}
	if len(w.PathPrefix) > 0 {
		match := false
		for _, p := range w.PathPrefix {
			if strings.HasPrefix(req.NormalizedPath, p) {
				match = true
				break
			}
		}
		if !match {
			return false
		}
	}
	if len(w.PathExclude) > 0 {
		for _, p := range w.PathExclude {
			if strings.HasPrefix(req.NormalizedPath, p) {
				return false
			}
		}
	}
	// Score gating — use current accumulated score
	if w.MinScore > 0 && partial.TotalScore < w.MinScore {
		return false
	}
	if w.MaxScore > 0 && partial.TotalScore >= w.MaxScore {
		return false
	}
	// Labels
	if len(w.RequireLabels) > 0 {
		for _, l := range w.RequireLabels {
			if _, ok := labelSet[l]; !ok {
				return false
			}
		}
	}
	if len(w.ExcludeLabels) > 0 {
		for _, l := range w.ExcludeLabels {
			if _, ok := labelSet[l]; ok {
				return false
			}
		}
	}
	return true
}

func matchesExcept(rule *Rule, req *ParsedRequest, labelSet map[string]struct{}) bool {
	e := &rule.Except
	if len(e.IPs) > 0 {
		if ipInList(req.ClientIP, e.IPs) {
			return true
		}
	}
	if len(e.Paths) > 0 {
		for _, p := range e.Paths {
			if req.NormalizedPath == p {
				return true
			}
		}
	}
	if len(e.PathPrefixes) > 0 {
		for _, p := range e.PathPrefixes {
			if strings.HasPrefix(req.NormalizedPath, p) {
				return true
			}
		}
	}
	if len(e.UserAgents) > 0 {
		ua := strings.ToLower(req.UserAgent)
		for _, sub := range e.UserAgents {
			if strings.Contains(ua, strings.ToLower(sub)) {
				return true
			}
		}
	}
	if len(e.Labels) > 0 {
		for _, l := range e.Labels {
			if _, ok := labelSet[l]; ok {
				return true
			}
		}
	}
	return false
}

func ipInList(client string, list []string) bool {
	if client == "" {
		return false
	}
	ip := net.ParseIP(client)
	if ip == nil {
		return false
	}
	for _, entry := range list {
		if strings.Contains(entry, "/") {
			_, ipnet, err := net.ParseCIDR(entry)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
		} else if net.ParseIP(entry).Equal(ip) {
			return true
		}
	}
	return false
}

// =========================================================================
// Detect — boolean tree over multiple selectors
// =========================================================================

// evaluateDetect runs inspect→transform→detect.logic across all selectors.
// Returns (hit, matchedOn, pattern, value, offset).
func evaluateDetect(rule *Rule, req *ParsedRequest) (bool, string, string, string, int) {
	inputs := resolveInputs(req, rule.Inspect)
	logic := rule.Detect.Logic
	if logic == "" {
		logic = "any"
	}

	for label, raw := range inputs {
		transformed := applyTransforms(raw, rule.Transforms, builtinTransforms)
		switch logic {
		case "all":
			// all patterns must match against this transformed value
			ok := true
			lastIdx := 0
			var lastDesc string
			for i, p := range rule.Detect.Patterns {
				m, off := matchPattern(rule, i, &p, transformed)
				if !m {
					ok = false
					break
				}
				lastIdx = off
				lastDesc = patternDescriptor(&p)
			}
			if ok {
				return true, label, lastDesc, raw, lastIdx
			}
		default: // "any"
			for i, p := range rule.Detect.Patterns {
				m, off := matchPattern(rule, i, &p, transformed)
				if m {
					return true, label, patternDescriptor(&p), raw, off
				}
			}
		}
	}
	return false, "", "", "", -1
}

func patternDescriptor(p *Pattern) string {
	if p.Value != "" {
		return p.Type + ":" + p.Value
	}
	if len(p.Values) > 0 {
		return p.Type + ":" + strings.Join(p.Values, ",")
	}
	return p.Type
}

// =========================================================================
// Misc
// =========================================================================

func (re *RuleEngine) determineDecision(score float64) string {
	if score >= re.blockThreshold {
		return "BLOCK"
	}
	if score >= re.challengeThreshold {
		return "CHALLENGE"
	}
	if score >= re.logThreshold {
		return "LOG"
	}
	return "ALLOW"
}

func (re *RuleEngine) updateMetrics(ruleID, category string) {
	re.metrics.mu.Lock()
	re.metrics.RuleHitCount[ruleID]++
	re.metrics.CategoryStats[category]++
	re.metrics.mu.Unlock()
}

func (re *RuleEngine) RuleCount() int {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return len(re.rules)
}

// ListRules — preserves v1 API.
func (re *RuleEngine) ListRules() []RuleSummary {
	re.mu.RLock()
	rules := make([]*Rule, len(re.rules))
	copy(rules, re.rules)
	re.mu.RUnlock()

	re.metrics.mu.RLock()
	hits := make(map[string]int64, len(re.metrics.RuleHitCount))
	for k, v := range re.metrics.RuleHitCount {
		hits[k] = v
	}
	re.metrics.mu.RUnlock()

	out := make([]RuleSummary, 0, len(rules))
	for _, r := range rules {
		targets := make([]string, 0, len(r.Inspect))
		for _, s := range r.Inspect {
			targets = append(targets, strings.ToUpper(s.Source))
		}
		out = append(out, RuleSummary{
			ID:           r.ID,
			Version:      r.Version,
			Enabled:      r.Enabled,
			Category:     r.Info.Category,
			Severity:     strings.ToUpper(r.Info.Severity),
			Description:  r.Info.Description,
			Tags:         r.Info.Tags,
			Targets:      targets,
			Methods:      r.When.Methods,
			AnomalyScore: int(r.Action.Score),
			PatternCount: len(r.Detect.Patterns),
			HitCount:     hits[r.ID],
		})
	}
	return out
}

// GetRule returns the full Rule by ID (for the dashboard editor).
func (re *RuleEngine) GetRule(id string) (*Rule, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()
	r, ok := re.ruleCache[id]
	return r, ok
}

// GetRuleJSON returns the rule as JSON (v2 schema).
func (re *RuleEngine) GetRuleJSON(id string) ([]byte, bool) {
	r, ok := re.GetRule(id)
	if !ok {
		return nil, false
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, false
	}
	return b, true
}

// GetMetrics — preserves v1 API.
func (re *RuleEngine) GetMetrics() *RuleMetrics {
	re.metrics.mu.RLock()
	defer re.metrics.mu.RUnlock()
	metrics := &RuleMetrics{
		TotalEvaluations: re.metrics.TotalEvaluations,
		TotalMatches:     re.metrics.TotalMatches,
		TotalBlocks:      re.metrics.TotalBlocks,
		AverageEvalTime:  re.metrics.AverageEvalTime,
		RuleHitCount:     make(map[string]int64),
		CategoryStats:    make(map[string]int64),
	}
	for k, v := range re.metrics.RuleHitCount {
		metrics.RuleHitCount[k] = v
	}
	for k, v := range re.metrics.CategoryStats {
		metrics.CategoryStats[k] = v
	}
	return metrics
}

// =========================================================================
// Utility
// =========================================================================

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func containsIgnoreCase(list []string, val string) bool {
	for _, x := range list {
		if strings.EqualFold(x, val) {
			return true
		}
	}
	return false
}
