// internal/engine/operators.go
//
// Pattern operators — atomic match leaves. Each operator answers
//   match(input, pattern, rule_index) → (matched bool, offset int)
//
// Operators are stateless; precompiled regex/wordlist lives in rule.compiled.
package engine

import (
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// matchPattern runs a single pattern leaf against `input`.
// rule.compiled supplies precompiled regex / wordlist when applicable.
// patIdx is the position of this pattern in rule.Detect.Patterns so we can
// look up the precompiled slot.
func matchPattern(rule *Rule, patIdx int, p *Pattern, input string) (bool, int) {
	var matched bool
	var offset int

	switch p.Type {
	case "regex":
		matched, offset = opRegex(rule, patIdx, input)
	case "contains":
		matched, offset = opContains(p.Value, input)
	case "starts_with":
		matched, offset = opStartsWith(p.Value, input)
	case "ends_with":
		matched, offset = opEndsWith(p.Value, input)
	case "equals":
		matched, offset = opEquals(p.Value, input)
	case "wordlist":
		matched, offset = opWordlist(rule, patIdx, input)
	case "entropy_gt":
		matched, offset = opEntropyGT(rule, patIdx, input)
	case "length_gt":
		matched, offset = opLengthGT(rule, patIdx, input)
	case "length_lt":
		matched, offset = opLengthLT(rule, patIdx, input)
	case "ip_match":
		matched, offset = opIPMatch(p, input)
	default:
		return false, -1
	}

	if p.Negate {
		matched = !matched
		if matched {
			offset = 0
		} else {
			offset = -1
		}
	}
	return matched, offset
}

// =========================================================================
// String operators
// =========================================================================

func opRegex(rule *Rule, idx int, input string) (bool, int) {
	if idx >= len(rule.compiled.regexes) || rule.compiled.regexes[idx] == nil {
		return false, -1
	}
	loc := rule.compiled.regexes[idx].FindStringIndex(input)
	if loc == nil {
		return false, -1
	}
	return true, loc[0]
}

func opContains(needle, input string) (bool, int) {
	if needle == "" {
		return false, -1
	}
	i := strings.Index(input, needle)
	if i < 0 {
		return false, -1
	}
	return true, i
}

func opStartsWith(prefix, input string) (bool, int) {
	if prefix == "" {
		return false, -1
	}
	if strings.HasPrefix(input, prefix) {
		return true, 0
	}
	return false, -1
}

func opEndsWith(suffix, input string) (bool, int) {
	if suffix == "" {
		return false, -1
	}
	if strings.HasSuffix(input, suffix) {
		return true, len(input) - len(suffix)
	}
	return false, -1
}

func opEquals(want, input string) (bool, int) {
	if want == input {
		return true, 0
	}
	return false, -1
}

// =========================================================================
// Wordlist (multiple words with word boundary)
// =========================================================================

func opWordlist(rule *Rule, idx int, input string) (bool, int) {
	if idx >= len(rule.compiled.wordlists) {
		return false, -1
	}
	words := rule.compiled.wordlists[idx]
	for _, w := range words {
		if w == "" {
			continue
		}
		i := strings.Index(input, w)
		if i < 0 {
			continue
		}
		if isWordBoundary(input, i, len(w)) {
			return true, i
		}
		// Continue scanning for non-boundary occurrences with later positions.
		for {
			next := strings.Index(input[i+1:], w)
			if next < 0 {
				break
			}
			i = i + 1 + next
			if isWordBoundary(input, i, len(w)) {
				return true, i
			}
		}
	}
	return false, -1
}

func isWordBoundary(s string, start, length int) bool {
	if start > 0 && isAlnum(s[start-1]) {
		return false
	}
	end := start + length
	if end < len(s) && isAlnum(s[end]) {
		return false
	}
	return true
}

func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

// =========================================================================
// Numeric operators
// =========================================================================

func opEntropyGT(rule *Rule, idx int, input string) (bool, int) {
	if idx >= len(rule.compiled.numerics) {
		return false, -1
	}
	thresh := rule.compiled.numerics[idx]
	e := shannonEntropy(input)
	if e > thresh {
		return true, 0
	}
	return false, -1
}

func opLengthGT(rule *Rule, idx int, input string) (bool, int) {
	if idx >= len(rule.compiled.numerics) {
		return false, -1
	}
	if float64(len(input)) > rule.compiled.numerics[idx] {
		return true, 0
	}
	return false, -1
}

func opLengthLT(rule *Rule, idx int, input string) (bool, int) {
	if idx >= len(rule.compiled.numerics) {
		return false, -1
	}
	if float64(len(input)) < rule.compiled.numerics[idx] {
		return true, 0
	}
	return false, -1
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}
	var e float64
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// =========================================================================
// IP match (CIDR / exact)
// =========================================================================

func opIPMatch(p *Pattern, input string) (bool, int) {
	if input == "" {
		return false, -1
	}
	ip := net.ParseIP(input)
	if ip == nil {
		return false, -1
	}
	candidates := p.Values
	if len(candidates) == 0 && p.Value != "" {
		candidates = []string{p.Value}
	}
	for _, c := range candidates {
		if strings.Contains(c, "/") {
			_, ipnet, err := net.ParseCIDR(c)
			if err == nil && ipnet.Contains(ip) {
				return true, 0
			}
		} else {
			if net.ParseIP(c).Equal(ip) {
				return true, 0
			}
		}
	}
	return false, -1
}

// =========================================================================
// Compilation (called once per rule at load)
// =========================================================================

func compileRule(r *Rule) {
	r.compiledOnce.Do(func() {
		n := len(r.Detect.Patterns)
		r.compiled.regexes = make([]*regexp.Regexp, n)
		r.compiled.wordlists = make([][]string, n)
		r.compiled.numerics = make([]float64, n)
		r.compiled.sevMul = severityMultiplier(r.Info.Severity)

		for i, p := range r.Detect.Patterns {
			switch p.Type {
			case "regex":
				rx := p.Value
				if strings.Contains(p.Flags, "i") || strings.Contains(p.Flags, "m") || strings.Contains(p.Flags, "s") {
					prefix := "(?"
					if strings.Contains(p.Flags, "i") {
						prefix += "i"
					}
					if strings.Contains(p.Flags, "m") {
						prefix += "m"
					}
					if strings.Contains(p.Flags, "s") {
						prefix += "s"
					}
					prefix += ")"
					rx = prefix + rx
				}
				if c, err := regexp.Compile(rx); err == nil {
					r.compiled.regexes[i] = c
				}
			case "wordlist":
				vals := p.Values
				if len(vals) == 0 && p.Value != "" {
					// allow comma-separated single-string fallback
					for _, v := range strings.Split(p.Value, ",") {
						v = strings.TrimSpace(v)
						if v != "" {
							vals = append(vals, v)
						}
					}
				}
				// pre-lowercase for case-insensitive match (caller usually applies lowercase transform too)
				lc := make([]string, 0, len(vals))
				for _, v := range vals {
					lc = append(lc, strings.ToLower(v))
				}
				r.compiled.wordlists[i] = lc
			case "entropy_gt", "length_gt", "length_lt":
				if n, err := strconv.ParseFloat(p.Value, 64); err == nil {
					r.compiled.numerics[i] = n
				}
			}
		}
	})
}
