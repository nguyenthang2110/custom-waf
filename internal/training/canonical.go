// Canonical full-request text builder used by the v5+ ML model.
//
// This is the input format the DistilBERT classifier was *actually trained on*
// (see model_v5/final_model_v5/label_config.json — "input_format": "WAF
// canonical").  BuildMLText (text.go) historically produced a different,
// looser shape — match.Value joined by " | " or a small bag of normalized
// fields — which causes train/serve skew at inference time.
//
// The canonical shape is:
//
//	METHOD PATH
//	Host: ...
//	User-Agent: ...
//	Content-Type: ...
//	Referer: ...
//	X-Forwarded-For: ...
//	X-Real-IP: ...
//	X-Requested-With: ...
//	Origin: ...
//	Cookie: ...                  ← redacted to summary by Redact()
//	Authorization: scheme ***    ← scheme only
//
//	<body>
//
// Headers absent from the request are omitted (no empty lines). The list
// above is the WHITE-LIST — every other header is dropped to keep the input
// reproducible across user agents.
//
// Two normalisations are applied before composition:
//   - the path/query/body are URL-decoded **one layer** so obfuscated payloads
//     (Log4j as `%24%7Bjndi%3A...`, SSTI as `%7B%25...%25%7D`) reach the
//     tokenizer in their canonical form. Double-decoding is intentionally
//     avoided — it changes the meaning of `/files/foo%2Fbar` and causes
//     false positives in path-traversal detection.
//   - text is truncated to maxLen bytes after composition (DistilBERT caps at
//     256 BPE tokens anyway; the byte budget is just an IO guardrail).
//
// IMPORTANT: any change here MUST be mirrored in the training preprocess
// (canonical_compose in the train folder) or the model degrades. See
// train_export/retrain_v6_instructions.md for the matching Python.
package training

import (
	"net/url"
	"strings"

	"waf-project/internal/engine"
)

// canonicalHeaderOrder is the whitelist of headers included in the canonical
// text, in the order they appear. Keep this list in sync with the train
// pipeline's HEADER_ORDER constant.
var canonicalHeaderOrder = []string{
	"Host",
	"User-Agent",
	"Content-Type",
	"Referer",
	"X-Forwarded-For",
	"X-Real-IP",
	"X-Requested-With",
	"Origin",
	"Cookie",
	"Authorization",
}

// BuildCanonicalText composes the v5+ canonical input. evalResult is unused
// today but kept in the signature so callers don't need updating if a future
// model wants matched-rule labels appended.
func BuildCanonicalText(req *engine.ParsedRequest, _ *engine.EvaluationResult, maxLen int) string {
	if req == nil {
		return ""
	}
	if maxLen <= 0 {
		maxLen = MaxTextLenDefault
	}

	method := req.Method
	if method == "" {
		method = req.RawMethod
	}
	if method == "" {
		method = "GET"
	}

	// Path + query — URL-decoded one layer. Prefer the normalized form when
	// available (lower-cased, dot-segments resolved), fall back to raw.
	path := req.NormalizedPath
	if path == "" {
		path = req.RawPath
	}
	query := req.NormalizedQuery
	if query == "" {
		query = req.RawQuery
	}
	path = decodeOnce(path)
	query = decodeOnce(query)

	pathWithQuery := path
	if query != "" {
		pathWithQuery = path + "?" + query
	}

	var b strings.Builder
	b.Grow(maxLen)
	b.WriteString(strings.ToUpper(method))
	b.WriteByte(' ')
	b.WriteString(pathWithQuery)

	// Headers — only those in the whitelist, in fixed order, deduped on first
	// value (multi-valued headers concatenate with ", " like RFC 7230 §3.2.2).
	for _, name := range canonicalHeaderOrder {
		v := canonicalHeaderValue(req, name)
		if v == "" {
			continue
		}
		b.WriteByte('\n')
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(v)
	}

	// Body. URL-decoded one layer for form / JSON-ish content; binary uploads
	// are passed through (utf8-trimmed by the parser already).
	body := req.NormalizedBody
	if body == "" && len(req.RawBody) > 0 {
		body = string(req.RawBody)
	}
	if body != "" {
		body = decodeOnce(body)
		b.WriteString("\n\n")
		b.WriteString(body)
	}

	return truncate(b.String(), maxLen)
}

// canonicalHeaderValue resolves a header in a case-insensitive way, applying
// the same "scheme-only" / "len=N,n=M" summaries we want in the training file.
func canonicalHeaderValue(req *engine.ParsedRequest, name string) string {
	lower := strings.ToLower(name)
	switch lower {
	case "host":
		if req.Host != "" {
			return req.Host
		}
	case "user-agent":
		if req.UserAgent != "" {
			return truncate(req.UserAgent, 256)
		}
	case "content-type":
		if req.ContentType != "" {
			return req.ContentType
		}
	case "authorization":
		if v := firstHeader(req, "authorization"); v != "" {
			return summariseAuth(v)
		}
		return ""
	case "cookie":
		if v := firstHeader(req, "cookie"); v != "" {
			// Keep the structural cookie info — Redact() will scrub values.
			return v
		}
		return ""
	}
	if v := firstHeader(req, lower); v != "" {
		return truncate(v, 256)
	}
	return ""
}

// decodeOnce performs a single layer of percent-decoding. Errors fall through
// returning the input unchanged — partial / malformed escapes shouldn't take
// down the inference path. We intentionally do NOT recurse on double-encoded
// inputs; path-traversal rules depend on `%2F` staying `%2F` after one decode.
func decodeOnce(s string) string {
	if s == "" || !strings.ContainsRune(s, '%') {
		return s
	}
	dec, err := url.QueryUnescape(s)
	if err != nil {
		// Try the path-style decoder (it's stricter on `+`) as a fallback —
		// some inputs (path components) shouldn't treat `+` as space.
		if dec2, err2 := url.PathUnescape(s); err2 == nil {
			return dec2
		}
		return s
	}
	return dec
}
