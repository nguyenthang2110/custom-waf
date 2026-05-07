package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RuleEngine evaluates rules against requests
type RuleEngine struct {
	rules          []*Rule
	ruleCache      map[string]*Rule
	transformFuncs map[string]TransformFunc
	matcherFuncs   map[string]MatcherFunc

	// Configuration
	blockThreshold     float64
	challengeThreshold float64
	logThreshold       float64

	// Performance
	metrics *RuleMetrics
	mu      sync.RWMutex
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine() *RuleEngine {
	engine := &RuleEngine{
		rules:              make([]*Rule, 0),
		ruleCache:          make(map[string]*Rule),
		transformFuncs:     make(map[string]TransformFunc),
		matcherFuncs:       make(map[string]MatcherFunc),
		blockThreshold:     10.0,
		challengeThreshold: 5.0,
		logThreshold:       3.0,
		metrics: &RuleMetrics{
			RuleHitCount:  make(map[string]int64),
			CategoryStats: make(map[string]int64),
		},
	}

	// Register built-in transforms
	engine.registerTransforms()

	// Register built-in matchers
	engine.registerMatchers()

	return engine
}

// LoadRulesFromFile loads rules from JSON file
func (re *RuleEngine) LoadRulesFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rules file: %w", err)
	}

	return re.LoadRulesFromJSON(data)
}

// LoadRulesFromJSON loads rules from JSON data
func (re *RuleEngine) LoadRulesFromJSON(data []byte) error {
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	for i := range rules {
		if err := re.addRule(&rules[i]); err != nil {
			return fmt.Errorf("failed to add rule %s: %w", rules[i].ID, err)
		}
	}

	return nil
}

// ValidateRulesJSON validates rules JSON without loading them
// Returns the count of valid rules and any errors
func (re *RuleEngine) ValidateRulesJSON(data []byte) (int, error) {
	var rules []Rule
	if err := json.Unmarshal(data, &rules); err != nil {
		return 0, fmt.Errorf("invalid JSON format: %w", err)
	}

	if len(rules) == 0 {
		return 0, fmt.Errorf("no rules found in file")
	}

	// Validate each rule
	validCount := 0
	var validationErrors []string

	for i := range rules {
		if err := re.validateRule(&rules[i]); err != nil {
			validationErrors = append(validationErrors,
				fmt.Sprintf("rule %s: %v", rules[i].ID, err))
		} else {
			validCount++
		}
	}

	if len(validationErrors) > 0 {
		return validCount, fmt.Errorf("validation errors: %s",
			strings.Join(validationErrors, "; "))
	}

	return validCount, nil
}

// ReloadRules atomically replaces all current rules with new ones
// This allows hot-reload without restarting the WAF
func (re *RuleEngine) ReloadRules(data []byte) error {
	// First validate the new rules
	_, err := re.ValidateRulesJSON(data)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Parse rules again (already validated)
	var newRules []Rule
	if err := json.Unmarshal(data, &newRules); err != nil {
		return fmt.Errorf("failed to parse rules: %w", err)
	}

	// Prepare new rules (compile patterns)
	preparedRules := make([]*Rule, 0, len(newRules))
	for i := range newRules {
		newRules[i].compilePatterns()
		preparedRules = append(preparedRules, &newRules[i])
	}

	// Create new cache
	newCache := make(map[string]*Rule)
	for _, rule := range preparedRules {
		newCache[rule.ID] = rule
	}

	// Atomically replace rules (lock for write)
	re.mu.Lock()
	re.rules = preparedRules
	re.ruleCache = newCache
	re.mu.Unlock()

	// Reset metrics for rule hit counts (keep total stats)
	re.metrics.mu.Lock()
	re.metrics.RuleHitCount = make(map[string]int64)
	re.metrics.CategoryStats = make(map[string]int64)
	re.metrics.mu.Unlock()

	return nil
}

// addRule adds a single rule to the engine
func (re *RuleEngine) addRule(rule *Rule) error {
	// Validate rule
	if err := re.validateRule(rule); err != nil {
		return err
	}

	// Compile patterns
	rule.compilePatterns()

	// Add to engine
	re.mu.Lock()
	defer re.mu.Unlock()

	re.rules = append(re.rules, rule)
	re.ruleCache[rule.ID] = rule

	return nil
}

// validateRule validates a rule
func (re *RuleEngine) validateRule(rule *Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}

	if rule.Metadata.Category == "" {
		return fmt.Errorf("rule category is required")
	}

	if len(rule.Patterns) == 0 {
		return fmt.Errorf("rule must have at least one pattern")
	}

	// Validate severity
	validSeverities := map[string]bool{"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true}
	if !validSeverities[rule.Metadata.Severity] {
		return fmt.Errorf("invalid severity: %s", rule.Metadata.Severity)
	}

	return nil
}

// compilePatterns compiles regex patterns in a rule
func (r *Rule) compilePatterns() {
	r.compiledOnce.Do(func() {
		r.compiledPatterns = make([]*regexp.Regexp, len(r.Patterns))

		for i, pattern := range r.Patterns {
			if pattern.Type == "REGEX" {
				flags := pattern.Flags
				regexPattern := pattern.Pattern

				// Apply flags
				if strings.Contains(flags, "i") {
					regexPattern = "(?i)" + regexPattern
				}

				compiled, err := regexp.Compile(regexPattern)
				if err != nil {
					// Log error but don't fail
					continue
				}
				r.compiledPatterns[i] = compiled
			}
		}
	})
}

// Evaluate evaluates all rules against a request
func (re *RuleEngine) Evaluate(req *ParsedRequest) *EvaluationResult {
	startTime := time.Now()

	result := &EvaluationResult{
		TotalScore:   0,
		MatchedRules: make([]MatchResult, 0),
		Decision:     "ALLOW",
	}

	re.mu.RLock()
	rules := re.rules
	re.mu.RUnlock()

	// Evaluate each rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check exceptions
		if re.matchesException(rule, req) {
			continue
		}

		// Check conditions
		if !re.matchesConditions(rule, req) {
			continue
		}

		// Evaluate patterns
		matches := re.evaluatePatterns(rule, req)

		if len(matches) > 0 {
			// Calculate score with severity multiplier
			score := float64(rule.Scoring.AnomalyScore) * rule.Scoring.SeverityMultiplier

			for _, match := range matches {
				match.Score = score
				match.Severity = rule.Metadata.Severity
				match.Category = rule.Metadata.Category
				result.MatchedRules = append(result.MatchedRules, match)
			}

			result.TotalScore += score

			// Update metrics
			re.updateMetrics(rule.ID, rule.Metadata.Category)
		}
	}

	// Determine decision based on threshold
	result.Decision = re.determineDecision(result.TotalScore)
	result.DecisionReason = fmt.Sprintf("Score: %.2f, Threshold: %.2f",
		result.TotalScore, re.blockThreshold)
	result.EvalTime = time.Since(startTime)

	// Update metrics
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

// evaluatePatterns evaluates patterns in a rule
func (re *RuleEngine) evaluatePatterns(rule *Rule, req *ParsedRequest) []MatchResult {
	matches := make([]MatchResult, 0)

	// Get target values based on rule conditions
	targets := re.getTargetValues(rule, req)

	for targetName, targetValue := range targets {
		// Apply transforms
		transformed := re.applyTransforms(targetValue, rule.Transforms)

		// Check each pattern
		for i, pattern := range rule.Patterns {
			var matched bool
			var offset int

			switch pattern.Type {
			case "REGEX":
				if rule.compiledPatterns[i] != nil {
					loc := rule.compiledPatterns[i].FindStringIndex(transformed)
					matched = loc != nil
					if matched {
						offset = loc[0]
					}
				}
			case "TOKEN":
				matched, offset = re.matcherFuncs["TOKEN"](&pattern, transformed)
			case "WORDLIST":
				matched, offset = re.matcherFuncs["WORDLIST"](&pattern, transformed)
			case "ENTROPY":
				matched, offset = re.matcherFuncs["ENTROPY"](&pattern, transformed)
			}

			if matched {
				matches = append(matches, MatchResult{
					Matched:   true,
					RuleID:    rule.ID,
					RuleName:  rule.Metadata.Description,
					MatchedOn: targetName,
					Pattern:   pattern.Pattern,
					Value:     targetValue,
					Offset:    offset,
					Timestamp: time.Now(),
				})
			}
		}
	}

	return matches
}

// getTargetValues extracts target values from request
func (re *RuleEngine) getTargetValues(rule *Rule, req *ParsedRequest) map[string]string {
	targets := make(map[string]string)

	for _, target := range rule.Conditions.Targets {
		switch target {
		case "PATH":
			targets["path"] = req.NormalizedPath
		case "QUERY":
			targets["query"] = req.NormalizedQuery
		case "BODY":
			targets["body"] = req.NormalizedBody
		case "HEADERS":
			var headerStr strings.Builder
			for key, values := range req.RawHeaders {
				for _, value := range values {
					headerStr.WriteString(key + ": " + value + "\n")
				}
			}
			targets["headers"] = headerStr.String()
		case "COOKIES":
			var cookieStr strings.Builder
			for key, value := range req.Cookies {
				cookieStr.WriteString(key + "=" + value + "; ")
			}
			targets["cookies"] = cookieStr.String()
		}
	}

	return targets
}

// applyTransforms applies transform functions
func (re *RuleEngine) applyTransforms(value string, transforms []string) string {
	result := value

	for _, transform := range transforms {
		if fn, exists := re.transformFuncs[transform]; exists {
			result = fn(result)
		}
	}

	return result
}

// matchesConditions checks if request matches rule conditions
func (re *RuleEngine) matchesConditions(rule *Rule, req *ParsedRequest) bool {
	// Check method
	if len(rule.Conditions.Methods) > 0 {
		methodMatch := false
		for _, method := range rule.Conditions.Methods {
			if method == req.Method {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			return false
		}
	}

	// Check path patterns
	if len(rule.Conditions.PathPatterns) > 0 {
		pathMatch := false
		for _, pattern := range rule.Conditions.PathPatterns {
			matched, _ := regexp.MatchString(pattern, req.NormalizedPath)
			if matched {
				pathMatch = true
				break
			}
		}
		if !pathMatch {
			return false
		}
	}

	return true
}

// matchesException checks if request matches rule exception
func (re *RuleEngine) matchesException(rule *Rule, req *ParsedRequest) bool {
	// Check IP exceptions
	for _, ip := range rule.Exceptions.IPs {
		if req.ClientIP == ip {
			return true
		}
	}

	// Check User-Agent exceptions
	for _, ua := range rule.Exceptions.UserAgents {
		if strings.Contains(req.UserAgent, ua) {
			return true
		}
	}

	// Check path exceptions
	for _, path := range rule.Exceptions.Paths {
		if req.NormalizedPath == path {
			return true
		}
	}

	return false
}

// determineDecision determines action based on score
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

// updateMetrics updates rule metrics
func (re *RuleEngine) updateMetrics(ruleID, category string) {
	re.metrics.mu.Lock()
	re.metrics.RuleHitCount[ruleID]++
	re.metrics.CategoryStats[category]++
	re.metrics.mu.Unlock()
}

// RuleCount returns the number of loaded rules
func (re *RuleEngine) RuleCount() int {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return len(re.rules)
}

// RuleSummary is a lightweight, JSON-friendly view of a loaded rule —
// safe to expose via the dashboard API (omits compiled regex internals).
type RuleSummary struct {
	ID            string   `json:"id"`
	Version       string   `json:"version,omitempty"`
	Enabled       bool     `json:"enabled"`
	Category      string   `json:"category"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description,omitempty"`
	Tags          []string `json:"tags,omitempty"`
	Targets       []string `json:"targets,omitempty"`
	Methods       []string `json:"methods,omitempty"`
	AnomalyScore  int      `json:"anomaly_score"`
	PatternCount  int      `json:"pattern_count"`
	HitCount      int64    `json:"hit_count"`
}

// ListRules returns a snapshot of every loaded rule with hit counters
// so the dashboard can render a useful rules table.
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
		out = append(out, RuleSummary{
			ID:           r.ID,
			Version:      r.Version,
			Enabled:      r.Enabled,
			Category:     r.Metadata.Category,
			Severity:     r.Metadata.Severity,
			Description:  r.Metadata.Description,
			Tags:         r.Metadata.Tags,
			Targets:      r.Conditions.Targets,
			Methods:      r.Conditions.Methods,
			AnomalyScore: r.Scoring.AnomalyScore,
			PatternCount: len(r.Patterns),
			HitCount:     hits[r.ID],
		})
	}
	return out
}

// GetMetrics returns a copy of metrics
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
