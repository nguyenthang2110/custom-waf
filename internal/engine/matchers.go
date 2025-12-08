// ============================================================================
// internal/engine/matchers.go
// ============================================================================
package engine

import (
	"math"
	"regexp"
	"strings"
)

// registerMatchers registers all matcher functions
func (re *RuleEngine) registerMatchers() {
	re.matcherFuncs["REGEX"] = matchRegex
	re.matcherFuncs["TOKEN"] = matchToken
	re.matcherFuncs["WORDLIST"] = matchWordlist
	re.matcherFuncs["ENTROPY"] = matchEntropy
}

func matchRegex(pattern *Pattern, input string) (bool, int) {
	re, err := regexp.Compile(pattern.Pattern)
	if err != nil {
		return false, -1
	}
	loc := re.FindStringIndex(input)
	if loc == nil {
		return false, -1
	}
	return true, loc[0]
}

func matchToken(pattern *Pattern, input string) (bool, int) {
	if len(pattern.Tokens) == 0 {
		return false, -1
	}

	positions := make(map[string][]int)
	for _, token := range pattern.Tokens {
		token = strings.ToLower(token)
		idx := 0
		for {
			pos := strings.Index(strings.ToLower(input[idx:]), token)
			if pos == -1 {
				break
			}
			actualPos := idx + pos
			positions[token] = append(positions[token], actualPos)
			idx = actualPos + 1
		}
		if len(positions[token]) == 0 {
			return false, -1
		}
	}

	if pattern.Order == "sequential" {
		return matchTokensSequential(positions, pattern.Tokens, pattern.Proximity)
	}
	return matchTokensProximity(positions, pattern.Tokens, pattern.Proximity)
}

func matchTokensSequential(positions map[string][]int, tokens []string, proximity int) (bool, int) {
	if len(tokens) == 0 {
		return false, -1
	}

	firstToken := strings.ToLower(tokens[0])
	for _, startPos := range positions[firstToken] {
		currentPos := startPos
		matched := true

		for i := 1; i < len(tokens); i++ {
			token := strings.ToLower(tokens[i])
			found := false

			for _, pos := range positions[token] {
				if pos > currentPos && (proximity == 0 || pos-currentPos <= proximity) {
					currentPos = pos
					found = true
					break
				}
			}

			if !found {
				matched = false
				break
			}
		}

		if matched {
			return true, startPos
		}
	}

	return false, -1
}

func matchTokensProximity(positions map[string][]int, tokens []string, proximity int) (bool, int) {
	if len(tokens) == 0 {
		return false, -1
	}

	var allPositions []int
	for _, token := range tokens {
		token = strings.ToLower(token)
		if len(positions[token]) == 0 {
			return false, -1
		}
		allPositions = append(allPositions, positions[token]...)
	}

	if len(allPositions) == 0 {
		return false, -1
	}

	minPos := allPositions[0]
	maxPos := allPositions[0]

	for _, pos := range allPositions {
		if pos < minPos {
			minPos = pos
		}
		if pos > maxPos {
			maxPos = pos
		}
	}

	if proximity == 0 || maxPos-minPos <= proximity {
		return true, minPos
	}

	return false, -1
}

func matchWordlist(pattern *Pattern, input string) (bool, int) {
	if len(pattern.Tokens) == 0 {
		return false, -1
	}

	inputLower := strings.ToLower(input)

	for _, word := range pattern.Tokens {
		wordLower := strings.ToLower(word)
		idx := strings.Index(inputLower, wordLower)
		if idx != -1 {
			if isWordBoundary(inputLower, idx, len(wordLower)) {
				return true, idx
			}
		}
	}

	return false, -1
}

func isWordBoundary(input string, start, length int) bool {
	end := start + length

	if start > 0 {
		prevChar := input[start-1]
		if isAlphanumeric(prevChar) {
			return false
		}
	}

	if end < len(input) {
		nextChar := input[end]
		if isAlphanumeric(nextChar) {
			return false
		}
	}

	return true
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func matchEntropy(pattern *Pattern, input string) (bool, int) {
	entropy := calculateEntropy(input)
	threshold := 4.5

	if entropy > threshold {
		return true, 0
	}

	return false, -1
}

func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}

	var entropy float64
	length := float64(len(s))

	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}
