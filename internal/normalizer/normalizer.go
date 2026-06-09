package normalizer

import (
	"net/url"
	pathpkg "path"
	"strings"

	"waf-project/internal/engine"
)

// Normalizer handles request normalization before rule evaluation.
type Normalizer struct {
	maxDecodeRounds int
}

// NewNormalizer returns a normalizer with sane defaults.
func NewNormalizer() *Normalizer {
	return &Normalizer{
		maxDecodeRounds: 3,
	}
}

// Normalize populates normalized fields on the parsed request.
func (n *Normalizer) Normalize(req *engine.ParsedRequest) error {
	req.NormalizedPath = n.Path(req.RawPath)
	req.NormalizedQuery = n.Query(req.RawQuery)

	if len(req.RawBody) > 0 {
		req.NormalizedBody = string(req.RawBody)
	} else {
		req.NormalizedBody = ""
	}

	return nil
}

// Path canonicalises the request path so downstream code (rule engine,
// bypass-path matcher, IsHealthCheckPath, static-asset check) all see the
// same resolved form. Order matters:
//
//  1. multi URL-decode — catches double/triple-encoded `%2e%2e%2f` etc.
//  2. backslash → forward slash — some clients send Windows-style separators.
//  3. path.Clean — resolves `..` and `.` segments and collapses `//`.
//
// Step 3 is what plugs the `/health/../waf-api/auth/users` bypass: the
// raw path matches `HasPrefix("/health")` but `path.Clean` rewrites it
// to `/waf-api/auth/users` so the bypass check sees the real target.
// Rules that need to inspect the *raw* (pre-clean) path should match
// against req.RawPath, not NormalizedPath.
func (n *Normalizer) Path(p string) string {
	if p == "" {
		return ""
	}
	p = multiDecode(p, n.maxDecodeRounds)
	p = strings.ReplaceAll(p, "\\", "/")
	// path.Clean("") returns "." — we handle empty above so this is fine.
	// Clean strips a trailing slash on non-root paths; that's acceptable
	// for prefix matching since "/foo/" and "/foo" should bypass alike.
	return pathpkg.Clean(p)
}

// Query performs multi URL decode.
func (n *Normalizer) Query(q string) string {
	return multiDecode(q, n.maxDecodeRounds)
}

func multiDecode(s string, rounds int) string {
	for i := 0; i < rounds; i++ {
		decoded, err := url.QueryUnescape(s)
		if err != nil || decoded == s {
			break
		}
		s = decoded
	}
	return s
}
