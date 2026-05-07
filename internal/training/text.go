// Package training writes one JSONL record per inspected request in the
// exact shape consumed by the ML service: a single "text" field, optionally
// joined from matched-rule payloads or normalized request fields.
//
// The intent is that downstream training pipelines can treat each line as a
// drop-in {"text": ...} payload. We attach a weak label (allow/block) derived
// from the rule engine's decision so the file is usable as a starting dataset
// — final labels can still be overridden downstream.
package training

import (
	"strings"

	"waf-project/internal/engine"
)

// Headers we promote into the structured Record.Headers field. Sensitive
// values (cookie / authorization) are summarised, never stored verbatim.
var capturedHeaders = []string{
	"user-agent",
	"referer",
	"accept",
	"accept-language",
	"accept-encoding",
	"content-type",
	"host",
	"origin",
	"x-forwarded-for",
	"x-real-ip",
	"x-requested-with",
}

// MaxTextLenDefault matches the ML service's truncation budget (1000 bytes).
// The model itself caps at 256 BPE tokens; longer strings just waste IO.
const MaxTextLenDefault = 1000

// BuildMLText reproduces, byte-for-byte, the input the live decision engine
// sends to /predict. Keeping these two implementations in lockstep is what
// lets the resulting JSONL be replayed against the model without surprise.
//
// Selection order:
//  1. If any rule matched, join the unique match.Value strings with " | ".
//     These are the smoking-gun substrings from the request — usually the
//     most informative slice for an ML classifier too.
//  2. Otherwise, fall back to NormalizedPath + NormalizedQuery + NormalizedBody
//     plus a short header tail (UA + Referer). Headers in the tail are what
//     lets the model learn header-borne attacks (Log4j-in-UA, Shellshock,
//     host-header injection) that wouldn't otherwise appear in the text when
//     no rule matched.
func BuildMLText(req *engine.ParsedRequest, evalResult *engine.EvaluationResult, maxLen int) string {
	if maxLen <= 0 {
		maxLen = MaxTextLenDefault
	}

	if evalResult != nil && len(evalResult.MatchedRules) > 0 {
		var b strings.Builder
		seen := make(map[string]bool, len(evalResult.MatchedRules))
		for _, m := range evalResult.MatchedRules {
			if m.Value == "" || seen[m.Value] {
				continue
			}
			seen[m.Value] = true
			if b.Len() > 0 {
				b.WriteString(" | ")
			}
			b.WriteString(m.Value)
			if b.Len() >= maxLen {
				break
			}
		}
		if b.Len() > 0 {
			return truncate(b.String(), maxLen)
		}
	}

	if req == nil {
		return ""
	}
	parts := make([]string, 0, 5)
	if req.NormalizedPath != "" {
		parts = append(parts, req.NormalizedPath)
	}
	if req.NormalizedQuery != "" {
		parts = append(parts, req.NormalizedQuery)
	}
	if req.NormalizedBody != "" {
		parts = append(parts, req.NormalizedBody)
	}
	// Header tail — keep it short so it doesn't crowd out body content.
	if ua := firstHeader(req, "user-agent"); ua != "" {
		parts = append(parts, "UA: "+truncate(ua, 200))
	}
	if ref := firstHeader(req, "referer"); ref != "" {
		parts = append(parts, "Referer: "+truncate(ref, 200))
	}
	return truncate(strings.Join(parts, " "), maxLen)
}

// CaptureHeaders returns a redacted, structured snapshot of the request
// headers we want in the training record. Cookie and Authorization values
// are summarised (length / type) instead of stored verbatim — see Redact().
func CaptureHeaders(req *engine.ParsedRequest) map[string]string {
	if req == nil || len(req.RawHeaders) == 0 {
		return nil
	}
	out := make(map[string]string, len(capturedHeaders)+2)
	for _, name := range capturedHeaders {
		if v := firstHeader(req, name); v != "" {
			out[name] = truncate(v, 256)
		}
	}
	// Cookie: only length + count; never the value (PII / session token).
	if cookie := firstHeader(req, "cookie"); cookie != "" {
		out["cookie"] = summariseCookie(cookie)
	}
	// Authorization: scheme only.
	if auth := firstHeader(req, "authorization"); auth != "" {
		out["authorization"] = summariseAuth(auth)
	}
	return out
}

func firstHeader(req *engine.ParsedRequest, name string) string {
	if req == nil {
		return ""
	}
	// Try the canonical and lower-cased forms — net/http normalises but
	// our parser may pass either.
	if vs, ok := req.RawHeaders[name]; ok && len(vs) > 0 {
		return vs[0]
	}
	for k, vs := range req.RawHeaders {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	switch strings.ToLower(name) {
	case "user-agent":
		return req.UserAgent
	case "host":
		return req.Host
	case "content-type":
		return req.ContentType
	}
	return ""
}

func summariseCookie(v string) string {
	n := 1
	for i := 0; i < len(v); i++ {
		if v[i] == ';' {
			n++
		}
	}
	return formatLenN(len(v), n)
}

func summariseAuth(v string) string {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ' '); i > 0 {
		return v[:i] + " ***"
	}
	return "***"
}

func formatLenN(length, n int) string {
	// "len=234,n=4" — keeps the field machine-parseable.
	var b strings.Builder
	b.WriteString("len=")
	b.WriteString(itoa(length))
	b.WriteString(",n=")
	b.WriteString(itoa(n))
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	return s[:n]
}
