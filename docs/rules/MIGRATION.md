# Migration v1 → v2

Tài liệu chuyển rule từ schema v1 (`configs/rules/all_rules.json` hiện tại) sang v2.

---

## Bảng map field

| v1 | v2 | Ghi chú |
|---|---|---|
| `id` | `id` | Giữ nguyên. Lưu ý: v2 reject duplicate ID |
| `version` | `version` | |
| `enabled` | `enabled` | |
| `metadata.category` | `info.category` | Đổi sang lowercase canonical (`"SQL Injection"` → `"sqli"`) |
| `metadata.severity` | `info.severity` | Đổi sang lowercase (`"CRITICAL"` → `"critical"`) |
| `metadata.description` | `info.description` | |
| `metadata.tags` | `info.tags` | |
| `metadata.author` | `info.author` | |
| `metadata.created` | `info.created` | |
| `conditions.phase` | – | Bỏ. v2 chỉ phase REQUEST. |
| `conditions.targets` | `inspect[].source` | Map enum, xem dưới |
| `conditions.methods` | `when.methods` | |
| `conditions.path_patterns` | `when.path_prefix` hoặc dùng custom rule | v1 dùng regex, v2 chỉ prefix. Đa số chỉ cần prefix. |
| `transforms` | `transforms` | Đổi sang lowercase (`"URL_DECODE"` → `"url_decode"`) |
| `patterns[type=REGEX]` | `detect.patterns[type=regex]` | |
| `patterns[type=TOKEN]` | `detect.logic="all"` + nhiều `contains` | Xem ví dụ dưới |
| `patterns[type=WORDLIST]` | `detect.patterns[type=wordlist]` | |
| `patterns[type=ENTROPY]` | `detect.patterns[type=entropy_gt]` | Hardcode threshold 4.5 → giờ phải set `value` |
| `scoring.anomaly_score` | `action.score` | |
| `scoring.severity_multiplier` | – | Auto từ `info.severity` |
| `actions[type=LOG]` | `action.log: true` | |
| `actions[type=SCORE]` | Gộp vào `action.score` | Tránh trùng lặp |
| `exceptions.ips` | `except.ips` | v2 hỗ trợ CIDR |
| `exceptions.user_agents` | `except.user_agents` | |
| `exceptions.paths` | `except.paths` (exact) hoặc `except.path_prefixes` | Tách rõ |

## Map enum

### `conditions.targets` → `inspect[].source`

| v1 | v2 |
|---|---|
| `"PATH"` | `{"source": "path"}` |
| `"QUERY"` | `{"source": "query"}` |
| `"BODY"` | `{"source": "body"}` |
| `"HEADERS"` | `{"source": "headers_all"}` |
| `"COOKIES"` | `{"source": "cookies_all"}` |

### `metadata.category` → `info.category`

| v1 | v2 |
|---|---|
| `"SQL Injection"` | `"sqli"` |
| `"XSS"` / `"Cross-Site Scripting"` | `"xss"` |
| `"LFI"` / `"Path Traversal"` | `"lfi"` |
| `"RCE"` / `"Command Injection"` | `"rce"` |
| `"SSRF"` | `"ssrf"` |
| `"XXE"` | `"xxe"` |
| `"NoSQL Injection"` | `"nosqli"` |
| `"Scanner Detection"` | `"scanner"` |
| `"Log4j"` | `"rce"` + tag `"cve-2021-44228"` |

### `metadata.severity` → `info.severity`

| v1 | v2 |
|---|---|
| `"CRITICAL"` | `"critical"` |
| `"HIGH"` | `"high"` |
| `"MEDIUM"` / `"WARNING"` | `"medium"` |
| `"LOW"` / `"NOTICE"` | `"low"` |

### `transforms` → `transforms`

| v1 | v2 |
|---|---|
| `"URL_DECODE"` | `"url_decode"` |
| `"LOWERCASE"` | `"lowercase"` |
| `"HTML_DECODE"` | `"html_decode"` |
| `"BASE64_DECODE"` | `"base64_decode"` |
| `"REMOVE_NULLS"` | `"remove_nulls"` |
| `"REMOVE_WHITESPACE"` | `"remove_whitespace"` |
| `"COMPRESS_WHITESPACE"` | `"compress_whitespace"` |

---

## Ví dụ migrate

### Trường hợp 1: Rule REGEX đơn giản

**v1**:
```json
{
  "id": "WAF-006-XSS-SCRIPT",
  "version": "1.0",
  "enabled": true,
  "metadata": {
    "category": "XSS",
    "severity": "HIGH",
    "tags": ["xss", "script-tag"],
    "description": "Detects <script> tags"
  },
  "conditions": {
    "phase": "REQUEST",
    "targets": ["QUERY", "BODY"],
    "methods": ["GET", "POST"],
    "path_patterns": []
  },
  "transforms": ["URL_DECODE", "LOWERCASE", "HTML_DECODE"],
  "patterns": [
    { "type": "REGEX", "pattern": "<script[\\s>]", "flags": "i" }
  ],
  "scoring": { "anomaly_score": 4, "severity_multiplier": 1.5 },
  "actions": [
    { "type": "LOG", "level": "WARNING" },
    { "type": "SCORE", "increment": 4 }
  ],
  "exceptions": { "ips": [], "user_agents": [], "paths": [] }
}
```

**v2**:
```json
{
  "id": "WAF-006-XSS-SCRIPT",
  "version": "2.0",
  "enabled": true,
  "info": {
    "category": "xss",
    "severity": "high",
    "description": "Detects <script> tags",
    "tags": ["xss", "script-tag"]
  },
  "when": {
    "methods": ["GET", "POST"]
  },
  "inspect": [
    { "source": "query" },
    { "source": "body" }
  ],
  "transforms": ["url_decode", "lowercase", "html_decode"],
  "detect": {
    "patterns": [
      { "type": "regex", "value": "<script[\\s>]" }
    ]
  },
  "action": {
    "score": 4,
    "labels": ["attack:xss"],
    "log": true
  }
}
```

### Trường hợp 2: Rule có TOKEN (xa proximity)

**v1**:
```json
"patterns": [
  { "type": "TOKEN", "tokens": ["union", "select"], "proximity": 20, "order": "sequential" }
]
```

**v2**: dùng regex thay vì TOKEN (đơn giản, ít lỗi hơn):
```json
"detect": {
  "patterns": [
    { "type": "regex", "value": "\\bunion\\b[\\s\\S]{0,20}\\bselect\\b" }
  ]
}
```

Hoặc nếu chỉ cần cả 2 từ xuất hiện (không quan tâm khoảng cách):
```json
"detect": {
  "logic": "all",
  "patterns": [
    { "type": "contains", "value": "union" },
    { "type": "contains", "value": "select" }
  ]
}
```

### Trường hợp 3: Rule WORDLIST

**v1**:
```json
"patterns": [
  { "type": "WORDLIST", "tokens": ["sqlmap", "nikto", "nmap"] }
]
```

**v2**:
```json
"detect": {
  "patterns": [
    { "type": "wordlist", "values": ["sqlmap", "nikto", "nmap"] }
  ]
}
```

### Trường hợp 4: Rule ENTROPY

**v1**:
```json
"patterns": [
  { "type": "ENTROPY" }
]
```
(threshold hardcode 4.5 trong matcher)

**v2**:
```json
"detect": {
  "patterns": [
    { "type": "entropy_gt", "value": 4.5 }
  ]
}
```

### Trường hợp 5: Path patterns regex

**v1**:
```json
"conditions": {
  "path_patterns": ["^/api/v1/.*"]
}
```

**v2** (nếu chỉ là prefix):
```json
"when": {
  "path_prefix": ["/api/v1/"]
}
```

**v2** (nếu thật sự cần regex phức tạp, dùng custom rule thay vì path_pattern):
```json
"when": {
  "path_prefix": ["/api/"]
},
"inspect": [{"source": "path"}],
"detect": {
  "logic": "all",
  "patterns": [
    { "type": "regex", "value": "^/api/v\\d+/" },
    { "type": "regex", "value": "..." }
  ]
}
```

---

## Auto-migration script (gợi ý implement)

Engine có thể cung cấp CLI:

```
go run ./cmd/waf migrate-rules \
    --in  configs/rules/all_rules.json \
    --out configs/rules/all_rules_v2.json
```

Logic chính:

```go
func MigrateV1ToV2(v1Bytes []byte) ([]byte, error) {
    var v1Rules []V1Rule
    if err := json.Unmarshal(v1Bytes, &v1Rules); err != nil { return nil, err }

    v2Rules := make([]V2Rule, 0, len(v1Rules))
    seenIDs := map[string]int{}

    for _, r := range v1Rules {
        // De-duplicate IDs
        if n, ok := seenIDs[r.ID]; ok {
            r.ID = fmt.Sprintf("%s-DUP%d", r.ID, n+1)
            seenIDs[r.ID] = n + 1
        } else {
            seenIDs[r.ID] = 1
        }

        v2 := V2Rule{
            ID: r.ID,
            Version: "2.0",
            Enabled: r.Enabled,
            Info: V2Info{
                Category:    canonicalCategory(r.Metadata.Category),
                Severity:    strings.ToLower(r.Metadata.Severity),
                Description: r.Metadata.Description,
                Tags:        r.Metadata.Tags,
                Author:      r.Metadata.Author,
                Created:     r.Metadata.Created,
            },
            When: V2When{
                Methods: r.Conditions.Methods,
                // path_patterns regex không tự convert được — manual review
            },
            Inspect:    mapTargets(r.Conditions.Targets),
            Transforms: mapTransforms(r.Transforms),
            Detect:     mapDetect(r.Patterns),
            Action: V2Action{
                Score:  r.Scoring.AnomalyScore,
                Labels: []string{"attack:" + canonicalCategory(r.Metadata.Category)},
                Log:    true,
            },
            Except: V2Except{
                IPs:         r.Exceptions.IPs,
                UserAgents:  r.Exceptions.UserAgents,
                Paths:       r.Exceptions.Paths,
            },
        }
        v2Rules = append(v2Rules, v2)
    }

    return json.MarshalIndent(v2Rules, "", "  ")
}
```

Script này cần manual review sau khi chạy:
- `conditions.path_patterns` (regex) → cần đánh giá có chuyển được sang `path_prefix` đơn giản không.
- TOKEN pattern → cân nhắc dùng regex hay `logic: "all"`.
- Duplicate ID → quyết định rename hay bỏ rule trùng.

---

## Checklist sau migration

- [ ] Mọi ID unique
- [ ] Mọi `info.category`/`severity` đã lowercase canonical
- [ ] Đã review `path_patterns` của v1 — chọn `path_prefix` hoặc đưa vào regex `detect`
- [ ] Đã review TOKEN pattern — chọn regex hoặc `logic: "all"`
- [ ] Đã bỏ rule trùng lặp logic (vd WAF-015-SQLI-OR-BYPASS có thể trùng với WAF-002-SQLI-BOOLEAN)
- [ ] Đã quyết định rule nào bật `ml_confirm` (chỉ rule có FP cao)
- [ ] Đã quyết định rule nào bật `track` (chỉ rule signature có giá trị đếm: SQLi/XSS/scanner)
- [ ] Đã chạy validator trên file mới
- [ ] Test với traffic mẫu (test_results/ có sẵn) → score tương đương v1
