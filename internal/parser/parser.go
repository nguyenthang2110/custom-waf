// internal/parser/parser.go
package parser

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"waf-project/internal/engine"

	"github.com/google/uuid"
)

// HTTPParser parses HTTP requests and extracts all relevant components
type HTTPParser struct {
	maxBodySize    int64
	trustedProxies []string
}

// NewHTTPParser creates a new HTTP parser with the given max body size
func NewHTTPParser(maxBodySize int64) *HTTPParser {
	return &HTTPParser{
		maxBodySize:    maxBodySize,
		trustedProxies: []string{}, // Can be configured to trust specific proxy IPs
	}
}

// Parse extracts all components from HTTP request
func (p *HTTPParser) Parse(r *http.Request) (*engine.ParsedRequest, error) {
	// Generate unique request ID
	requestID := uuid.New().String()

	// Create parsed request structure
	parsed := &engine.ParsedRequest{
		RequestID:   requestID,
		Timestamp:   time.Now(),
		RawMethod:   r.Method,
		RawPath:     r.URL.Path,
		RawQuery:    r.URL.RawQuery,
		RawHeaders:  r.Header,
		ClientIP:    p.extractClientIP(r),
		Method:      r.Method,
		Protocol:    r.Proto,
		Host:        r.Host,
		UserAgent:   r.Header.Get("User-Agent"),
		ContentType: r.Header.Get("Content-Type"),
		Cookies:     p.extractCookies(r),
		HeaderCount: len(r.Header),
	}

	// Parse body with size limit (prevent memory exhaustion attacks)
	if r.Body != nil && r.ContentLength > 0 {
		body, err := io.ReadAll(io.LimitReader(r.Body, p.maxBodySize))
		if err != nil {
			return nil, err
		}
		parsed.RawBody = body
		parsed.BodySize = len(body)

		// Restore body for upstream (important for proxying)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	return parsed, nil
}

// extractClientIP gets the real client IP from headers or connection
// Checks multiple headers in order of priority
func (p *HTTPParser) extractClientIP(r *http.Request) string {
	// Priority 1: X-Forwarded-For (standard proxy header)
	// Format: "client, proxy1, proxy2"
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP (leftmost = client)
		ips := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(ips[0])
		if clientIP != "" {
			return clientIP
		}
	}

	// Priority 2: X-Real-IP (nginx standard)
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Priority 3: CF-Connecting-IP (Cloudflare)
	cfIP := r.Header.Get("CF-Connecting-IP")
	if cfIP != "" {
		return cfIP
	}

	// Priority 4: True-Client-IP (Akamai, Cloudflare)
	tcIP := r.Header.Get("True-Client-IP")
	if tcIP != "" {
		return tcIP
	}

	// Priority 5: X-Client-IP (Apache, others)
	xcIP := r.Header.Get("X-Client-IP")
	if xcIP != "" {
		return xcIP
	}

	// Fallback: Direct connection RemoteAddr
	// Format: "IP:port" - we only want the IP
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		return remoteIP[:idx]
	}
	return remoteIP
}

// extractCookies parses all cookies from request into a map
func (p *HTTPParser) extractCookies(r *http.Request) map[string]string {
	cookies := make(map[string]string)

	// Extract all cookies from request
	for _, cookie := range r.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}

	return cookies
}

// SetTrustedProxies configures which proxy IPs to trust for X-Forwarded-For
func (p *HTTPParser) SetTrustedProxies(proxies []string) {
	p.trustedProxies = proxies
}

// isTrustedProxy checks if an IP is in the trusted proxy list
func (p *HTTPParser) isTrustedProxy(ip string) bool {
	for _, trustedIP := range p.trustedProxies {
		if ip == trustedIP {
			return true
		}
	}
	return false
}

// GetQueryParams extracts query parameters as a map
func (p *HTTPParser) GetQueryParams(r *http.Request) map[string][]string {
	return r.URL.Query()
}

// GetHeader safely gets a header value (case-insensitive)
func (p *HTTPParser) GetHeader(r *http.Request, name string) string {
	return r.Header.Get(name)
}

// GetAllHeaders returns all headers as a map
func (p *HTTPParser) GetAllHeaders(r *http.Request) map[string][]string {
	return r.Header
}

// HasHeader checks if a header exists
func (p *HTTPParser) HasHeader(r *http.Request, name string) bool {
	_, exists := r.Header[name]
	return exists
}

// GetContentLength returns the content length of the request
func (p *HTTPParser) GetContentLength(r *http.Request) int64 {
	return r.ContentLength
}

// IsMultipart checks if request is multipart/form-data
func (p *HTTPParser) IsMultipart(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.HasPrefix(contentType, "multipart/form-data")
}

// IsJSON checks if request content type is JSON
func (p *HTTPParser) IsJSON(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

// IsXML checks if request content type is XML
func (p *HTTPParser) IsXML(r *http.Request) bool {
	contentType := r.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/xml") ||
		strings.Contains(contentType, "text/xml")
}

// ExtractAuthToken extracts bearer token from Authorization header
func (p *HTTPParser) ExtractAuthToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// GetReferer returns the referer header
func (p *HTTPParser) GetReferer(r *http.Request) string {
	return r.Header.Get("Referer")
}

// GetOrigin returns the origin header
func (p *HTTPParser) GetOrigin(r *http.Request) string {
	return r.Header.Get("Origin")
}

// GetAcceptLanguage returns accepted languages
func (p *HTTPParser) GetAcceptLanguage(r *http.Request) string {
	return r.Header.Get("Accept-Language")
}

// GetAcceptEncoding returns accepted encodings
func (p *HTTPParser) GetAcceptEncoding(r *http.Request) string {
	return r.Header.Get("Accept-Encoding")
}

// IsSecureConnection checks if request came over HTTPS
func (p *HTTPParser) IsSecureConnection(r *http.Request) bool {
	// Check direct TLS
	if r.TLS != nil {
		return true
	}

	// Check proxy headers
	if r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}

	if r.Header.Get("X-Forwarded-Ssl") == "on" {
		return true
	}

	return false
}

// GetRequestSize returns total request size estimation
func (p *HTTPParser) GetRequestSize(r *http.Request) int64 {
	size := int64(0)

	// Method + Path + Protocol
	size += int64(len(r.Method) + len(r.URL.String()) + len(r.Proto))

	// Headers
	for key, values := range r.Header {
		size += int64(len(key))
		for _, value := range values {
			size += int64(len(value))
		}
	}

	// Body
	size += r.ContentLength

	return size
}

// IsSuspiciousUserAgent checks for suspicious user agents
func (p *HTTPParser) IsSuspiciousUserAgent(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))

	// List of suspicious patterns
	suspiciousPatterns := []string{
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
		"nessus",
		"openvas",
		"acunetix",
		"burp",
		"zgrab",
		"python-requests",
		"curl",
		"wget",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(ua, pattern) {
			return true
		}
	}

	return false
}

// GetASN would extract ASN information (requires GeoIP database)
// Placeholder for future implementation
func (p *HTTPParser) GetASN(ip string) string {
	// TODO: Implement GeoIP lookup
	return ""
}

// GetCountry would extract country information (requires GeoIP database)
// Placeholder for future implementation
func (p *HTTPParser) GetCountry(ip string) string {
	// TODO: Implement GeoIP lookup
	return ""
}
