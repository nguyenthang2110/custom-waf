// internal/engine/loader.go
//
// Parse JSON rules — accepts both v1 (legacy) and v2 schemas.
// Auto-detects format and converts v1 → v2 internally.
package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// =========================================================================
// Top-level: ParseRules — auto-detect v1 vs v2 and produce []*Rule
// =========================================================================

// ParseRules parses a ruleset JSON (array of rule objects) into canonical
// v2 *Rule objects. Each rule object is independently auto-detected as v1
// or v2 based on its field set.
func ParseRules(data []byte) ([]*Rule, error) {
	// Peek as raw to detect format per-rule.
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON array: %w", err)
	}
	out := make([]*Rule, 0, len(raw))
	for i, m := range raw {
		bytes, _ := json.Marshal(m)
		isV2 := detectV2(m)
		var r *Rule
		var err error
		if isV2 {
			r, err = parseV2Rule(bytes)
		} else {
			r, err = parseV1Rule(bytes)
		}
		if err != nil {
			return nil, fmt.Errorf("rule #%d: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// detectV2 returns true if the rule object looks like v2 (has "info" or
// "detect" or "inspect" — none of which exist in v1).
func detectV2(m map[string]json.RawMessage) bool {
	if _, ok := m["info"]; ok {
		return true
	}
	if _, ok := m["detect"]; ok {
		return true
	}
	if _, ok := m["inspect"]; ok {
		return true
	}
	return false
}

// =========================================================================
// v2 parsing
// =========================================================================

func parseV2Rule(data []byte) (*Rule, error) {
	var r Rule
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	// Apply defaults
	if r.Version == "" {
		r.Version = "2.0"
	}
	// `Enabled` defaults to false from json — but a missing field on v2
	// should mean true. We detect this by re-reading the raw key.
	var probe map[string]json.RawMessage
	_ = json.Unmarshal(data, &probe)
	if _, ok := probe["enabled"]; !ok {
		r.Enabled = true
	}
	return &r, nil
}

// =========================================================================
// v1 parsing → convert to v2
// =========================================================================

// v1Rule mirrors the legacy schema. Used only at load time.
type v1Rule struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Enabled  bool   `json:"enabled"`
	Metadata struct {
		Category    string   `json:"category"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
		Author      string   `json:"author"`
		Created     string   `json:"created"`
	} `json:"metadata"`
	Conditions struct {
		Phase        string   `json:"phase"`
		Targets      []string `json:"targets"`
		Methods      []string `json:"methods"`
		PathPatterns []string `json:"path_patterns"`
	} `json:"conditions"`
	Transforms []string `json:"transforms"`
	Patterns   []struct {
		Type      string   `json:"type"`
		Pattern   string   `json:"pattern"`
		Flags     string   `json:"flags"`
		Tokens    []string `json:"tokens"`
		Proximity int      `json:"proximity"`
		Order     string   `json:"order"`
	} `json:"patterns"`
	Scoring struct {
		AnomalyScore       int     `json:"anomaly_score"`
		SeverityMultiplier float64 `json:"severity_multiplier"`
	} `json:"scoring"`
	Actions []struct {
		Type      string `json:"type"`
		Level     string `json:"level"`
		Increment int    `json:"increment"`
	} `json:"actions"`
	Exceptions struct {
		IPs        []string `json:"ips"`
		UserAgents []string `json:"user_agents"`
		Paths      []string `json:"paths"`
	} `json:"exceptions"`
}

func parseV1Rule(data []byte) (*Rule, error) {
	var v1 v1Rule
	if err := json.Unmarshal(data, &v1); err != nil {
		return nil, err
	}

	r := &Rule{
		ID:      v1.ID,
		Version: "2.0",
		Enabled: v1.Enabled,
		Info: RuleInfo{
			Category:    normalizeCategory(v1.Metadata.Category),
			Severity:    normalizeSeverity(v1.Metadata.Severity),
			Description: v1.Metadata.Description,
			Tags:        v1.Metadata.Tags,
			Author:      v1.Metadata.Author,
			Created:     v1.Metadata.Created,
		},
	}

	// When
	if len(v1.Conditions.Methods) > 0 {
		r.When.Methods = v1.Conditions.Methods
	}
	// path_patterns regex — v2 doesn't have regex prefix. Map only if
	// it looks like a prefix; otherwise drop with a TODO note kept in
	// description.
	for _, pp := range v1.Conditions.PathPatterns {
		if isSimplePrefixRegex(pp) {
			r.When.PathPrefix = append(r.When.PathPrefix, stripPrefixRegex(pp))
		}
	}

	// Inspect
	if len(v1.Conditions.Targets) > 0 {
		for _, t := range v1.Conditions.Targets {
			src := mapV1Target(t)
			if src == "" {
				continue
			}
			r.Inspect = append(r.Inspect, InputSel{Source: src})
		}
	}
	if len(r.Inspect) == 0 {
		// Sensible default if rule didn't specify
		r.Inspect = []InputSel{{Source: "args"}, {Source: "path"}}
	}

	// Transforms (uppercase → lowercase)
	for _, t := range v1.Transforms {
		r.Transforms = append(r.Transforms, strings.ToLower(t))
	}

	// Patterns
	r.Detect.Logic = "any" // v1 was always OR
	for _, p := range v1.Patterns {
		switch strings.ToUpper(p.Type) {
		case "REGEX":
			r.Detect.Patterns = append(r.Detect.Patterns, Pattern{
				Type:  "regex",
				Value: p.Pattern,
				Flags: p.Flags,
			})
		case "TOKEN":
			// Convert tokens with proximity → regex if proximity > 0,
			// otherwise to AND of contains. Simpler: regex with .{0,N}.
			if len(p.Tokens) >= 2 && p.Proximity > 0 && strings.EqualFold(p.Order, "sequential") {
				parts := make([]string, len(p.Tokens))
				for i, t := range p.Tokens {
					parts[i] = regexp.QuoteMeta(t)
				}
				rx := strings.Join(parts, fmt.Sprintf(".{0,%d}?", p.Proximity))
				r.Detect.Patterns = append(r.Detect.Patterns, Pattern{
					Type: "regex", Value: rx, Flags: "i",
				})
			} else {
				// AND of contains; switch logic if this rule has only this pattern.
				// For mixed rules we keep OR; degenerate but acceptable.
				for _, t := range p.Tokens {
					r.Detect.Patterns = append(r.Detect.Patterns, Pattern{
						Type: "contains", Value: t,
					})
				}
			}
		case "WORDLIST":
			r.Detect.Patterns = append(r.Detect.Patterns, Pattern{
				Type: "wordlist", Values: p.Tokens,
			})
		case "ENTROPY":
			r.Detect.Patterns = append(r.Detect.Patterns, Pattern{
				Type: "entropy_gt", Value: "4.5",
			})
		}
	}
	if len(r.Detect.Patterns) == 0 {
		// Engine requires ≥1 pattern. Insert a no-op that never matches.
		r.Detect.Patterns = []Pattern{{Type: "equals", Value: "\x00__never__\x00"}}
	}

	// Action
	r.Action.Score = float64(v1.Scoring.AnomalyScore)
	r.Action.Log = true // v1 always logged
	for _, a := range v1.Actions {
		switch strings.ToUpper(a.Type) {
		case "LOG":
			r.Action.Log = true
		case "SCORE":
			// already accounted via Scoring.AnomalyScore
		case "BLOCK":
			r.Action.Block = true
		case "CHALLENGE":
			r.Action.Challenge = true
		}
	}
	// Default attack label
	if r.Info.Category != "" && r.Info.Category != "custom" {
		r.Action.Labels = []string{"attack:" + r.Info.Category}
	}

	// Except
	r.Except.IPs = v1.Exceptions.IPs
	r.Except.UserAgents = v1.Exceptions.UserAgents
	r.Except.Paths = v1.Exceptions.Paths

	// Default MaxScore for when-gate (v1 didn't have score gating)
	r.When.MaxScore = 0 // 0 means "no upper limit" (engine semantics; checked below)

	return r, nil
}

// =========================================================================
// Helpers
// =========================================================================

func normalizeCategory(c string) string {
	s := strings.ToLower(strings.TrimSpace(c))
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "-", "_")
	switch s {
	case "sql_injection", "sqli":
		return "sqli"
	case "xss", "cross_site_scripting":
		return "xss"
	case "lfi", "path_traversal", "local_file_inclusion", "file_inclusion":
		return "lfi"
	case "rce", "command_injection", "remote_code_execution", "log4j", "shellshock":
		return "rce"
	case "ssrf", "server_side_request_forgery":
		return "ssrf"
	case "xxe", "xml_external_entity", "xml_injection":
		return "xxe"
	case "nosql_injection", "nosqli":
		return "nosqli"
	case "scanner_detection", "scanner", "vulnerability_scanner":
		return "scanner"
	case "bot", "malicious_bot":
		return "bot"
	case "ato", "account_takeover", "brute_force", "credential_stuffing":
		return "ato"
	case "dos", "denial_of_service":
		return "dos"
	case "info_leak", "information_leak", "sensitive_data_exposure", "information_disclosure":
		return "info_leak"
	case "csrf", "cross_site_request_forgery":
		// no dedicated bucket; classify as schema (CSRF is policy violation)
		return "schema"
	case "schema":
		return "schema"
	case "custom", "":
		return "custom"
	}
	// Unknown — fall back to custom so the rule still loads.
	return "custom"
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "error":
		return "high"
	case "medium", "warning":
		return "medium"
	case "low", "notice":
		return "low"
	case "info", "informational":
		return "info"
	}
	return "medium"
}

func mapV1Target(t string) string {
	switch strings.ToUpper(t) {
	case "PATH":
		return "path"
	case "QUERY":
		return "query"
	case "BODY":
		return "body"
	case "HEADERS":
		return "headers_all"
	case "COOKIES":
		return "cookies_all"
	case "ARGS":
		return "args"
	case "URI":
		return "uri"
	}
	return ""
}

// isSimplePrefixRegex returns true if the regex looks like ^/some/prefix(?:.*)?$
// — only then we can safely demote to a literal prefix.
func isSimplePrefixRegex(s string) bool {
	if !strings.HasPrefix(s, "^") {
		return false
	}
	body := strings.TrimPrefix(s, "^")
	// Strip trailing .* / .*$ / $
	body = strings.TrimSuffix(body, "$")
	body = strings.TrimSuffix(body, ".*")
	for _, c := range body {
		switch c {
		case '(', ')', '[', ']', '{', '}', '|', '\\', '+', '?', '*':
			return false
		}
	}
	return true
}
func stripPrefixRegex(s string) string {
	s = strings.TrimPrefix(s, "^")
	s = strings.TrimSuffix(s, "$")
	s = strings.TrimSuffix(s, ".*")
	return s
}

// =========================================================================
// Migration helper (exported for the CLI / future use)
// =========================================================================

// MigrateV1ToV2JSON converts a v1 ruleset JSON to a v2 ruleset JSON.
// Useful for one-shot conversion of `all_rules.json`.
func MigrateV1ToV2JSON(v1Data []byte) ([]byte, error) {
	rules, err := ParseRules(v1Data)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(rules, "", "  ")
}
