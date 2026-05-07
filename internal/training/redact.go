package training

import "regexp"

// Sensitive key/value patterns that must be masked out before a record
// touches the training file. Order matters — keep the more specific rules first.
var redactPatterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// JSON-ish "password": "..." / "token": "..." / "secret": "..."
	{regexp.MustCompile(`(?i)("(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|jwt)"\s*:\s*")[^"]*(")`),
		"$1***$2"},
	// Form / query: password=foo&...
	{regexp.MustCompile(`(?i)((?:^|[?&;])(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|authorization|jwt)=)[^&\s#]*`),
		"${1}***"},
	// Authorization: Bearer xxx
	{regexp.MustCompile(`(?i)(authorization\s*:\s*bearer\s+)\S+`),
		"${1}***"},
	// Basic auth header
	{regexp.MustCompile(`(?i)(authorization\s*:\s*basic\s+)\S+`),
		"${1}***"},
	// Set-Cookie / Cookie session-ish keys
	{regexp.MustCompile(`(?i)((?:cookie|set-cookie)\s*:\s*[^=]*=)[^;\s]+`),
		"${1}***"},
}

// Redact returns s with passwords, tokens and similar secrets replaced by ***.
// It is intentionally conservative: false positives (over-masking) are fine,
// false negatives (leaking a secret into the training file) are not.
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, p := range redactPatterns {
		out = p.re.ReplaceAllString(out, p.repl)
	}
	return out
}
