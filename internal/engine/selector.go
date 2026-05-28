// internal/engine/selector.go
//
// Extract input values from a ParsedRequest based on InputSel.
// Output is a map[label]value so MatchResult.MatchedOn carries useful info.
package engine

import (
	"net/url"
	"strings"
)

// resolveInputs returns label→value pairs for all selectors in a rule.
// `label` is a short tag like "args", "body", "header:User-Agent".
func resolveInputs(req *ParsedRequest, sels []InputSel) map[string]string {
	out := make(map[string]string, len(sels))
	for _, s := range sels {
		label, val := extractSelector(req, s)
		if label != "" {
			out[label] = val
		}
	}
	return out
}

func extractSelector(req *ParsedRequest, s InputSel) (string, string) {
	switch s.Source {
	case "path":
		return "path", req.NormalizedPath
	case "query":
		return "query", req.NormalizedQuery
	case "uri":
		uri := req.NormalizedPath
		if req.NormalizedQuery != "" {
			uri += "?" + req.NormalizedQuery
		}
		return "uri", uri
	case "body":
		return "body", req.NormalizedBody
	case "args":
		return "args", collectArgs(req)
	case "args_names":
		return "args_names", collectArgNames(req)
	case "header":
		if s.Name == "" {
			return "", ""
		}
		key := canonicalHeader(s.Name)
		vals := req.RawHeaders[key]
		return "header:" + s.Name, strings.Join(vals, "; ")
	case "headers_all":
		return "headers_all", concatHeaders(req)
	case "header_names":
		names := make([]string, 0, len(req.RawHeaders))
		for k := range req.RawHeaders {
			names = append(names, k)
		}
		return "header_names", strings.Join(names, " ")
	case "cookie":
		if s.Name == "" {
			return "", ""
		}
		v, ok := req.Cookies[s.Name]
		if !ok {
			return "cookie:" + s.Name, ""
		}
		return "cookie:" + s.Name, v
	case "cookies_all":
		return "cookies_all", concatCookies(req)
	case "ip":
		return "ip", req.ClientIP
	case "user_agent":
		return "user_agent", req.UserAgent
	}
	return "", ""
}

// =========================================================================
// Aggregators
// =========================================================================

// collectArgs concatenates GET query values, form body values, and JSON body
// values into a single string. JSON keys + leaf string values are flattened.
func collectArgs(req *ParsedRequest) string {
	var b strings.Builder
	b.WriteString(req.NormalizedQuery)
	if req.NormalizedBody != "" {
		// If the body looks like form-urlencoded, decode keys+values.
		ct := strings.ToLower(req.ContentType)
		if strings.Contains(ct, "application/x-www-form-urlencoded") {
			if vals, err := url.ParseQuery(req.NormalizedBody); err == nil {
				for k, vs := range vals {
					for _, v := range vs {
						b.WriteByte(' ')
						b.WriteString(k)
						b.WriteByte('=')
						b.WriteString(v)
					}
				}
			} else {
				b.WriteByte(' ')
				b.WriteString(req.NormalizedBody)
			}
		} else {
			// JSON / multipart / raw — just append entire body. Matches
			// behaviour of CRS @rx on REQUEST_BODY for those types.
			b.WriteByte(' ')
			b.WriteString(req.NormalizedBody)
		}
	}
	return b.String()
}

func collectArgNames(req *ParsedRequest) string {
	var names []string
	// GET names
	if vals, err := url.ParseQuery(req.NormalizedQuery); err == nil {
		for k := range vals {
			names = append(names, k)
		}
	}
	// POST form names
	ct := strings.ToLower(req.ContentType)
	if strings.Contains(ct, "application/x-www-form-urlencoded") && req.NormalizedBody != "" {
		if vals, err := url.ParseQuery(req.NormalizedBody); err == nil {
			for k := range vals {
				names = append(names, k)
			}
		}
	}
	return strings.Join(names, " ")
}

func concatHeaders(req *ParsedRequest) string {
	var b strings.Builder
	for k, vs := range req.RawHeaders {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func concatCookies(req *ParsedRequest) string {
	var b strings.Builder
	for k, v := range req.Cookies {
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
	}
	return b.String()
}

func canonicalHeader(name string) string {
	// HTTP headers are case-insensitive; net/http canonicalises them.
	// Try direct lookup first; fall back to manual title-case.
	return strings.TrimSpace(name)
}
