package normalizer

import (
	"net/url"
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

// Path performs simple normalization: multi URL decode and collapse slashes.
func (n *Normalizer) Path(p string) string {
	p = multiDecode(p, n.maxDecodeRounds)
	p = strings.ReplaceAll(p, "\\", "/")
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
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
