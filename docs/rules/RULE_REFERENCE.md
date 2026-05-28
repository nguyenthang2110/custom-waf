# Rule Reference — Schema v2

Tài liệu tra cứu **đầy đủ** mọi field. Dành cho khi bạn đã biết rule là gì và chỉ cần tra cú pháp. Để học từ đầu: [RULE_GUIDE.md](./RULE_GUIDE.md).

---

## File format

Một file rule là **mảng JSON** các rule object:

```json
[
  { /* rule 1 */ },
  { /* rule 2 */ }
]
```

Engine load mọi file `.json` trong `configs/rules/` (không tính `backups/`).

---

## Rule object — Top-level fields

| Field | Type | Bắt buộc | Default | Mô tả |
|---|---|---|---|---|
| `id` | string | ✓ | — | Định danh duy nhất, format `WAF-<số>-<loại>-<biến_thể>` |
| `version` | string | – | `"1.0"` | Phiên bản rule (semver hoặc số đơn) |
| `enabled` | bool | – | `true` | Bật/tắt rule không cần xoá |
| `info` | object | ✓ | — | Metadata, xem [§info](#info) |
| `when` | object | – | `{}` | Điều kiện áp dụng, xem [§when](#when) |
| `inspect` | array | ✓ | — | Selector, xem [§inspect](#inspect) |
| `transforms` | string[] | – | `[]` | Transform chain, xem [§transforms](#transforms) |
| `detect` | object | ✓ | — | Pattern logic, xem [§detect](#detect) |
| `action` | object | – | `{ "score": 0, "log": true }` | Khi match làm gì, xem [§action](#action) |
| `except` | object | – | `{}` | Whitelist, xem [§except](#except) |

---

## §info

```jsonc
"info": {
  "category":    "sqli",        // string, bắt buộc
  "severity":    "critical",    // enum, bắt buộc
  "description": "...",         // string
  "tags":        ["..."],       // string[]
  "references":  ["..."],       // string[] (URL/CVE)
  "author":      "...",         // string
  "created":     "2026-05-13",  // ISO date
  "updated":     "2026-05-13"   // ISO date
}
```

### `info.category` — enum

| Giá trị | Loại |
|---|---|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `lfi` | Local File Inclusion / Path Traversal |
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity |
| `nosqli` | NoSQL Injection |
| `scanner` | Scanner / fingerprinting |
| `bot` | Bot bất thường |
| `ato` | Account Takeover |
| `dos` | Denial of Service |
| `info_leak` | Lộ thông tin |
| `schema` | Vi phạm schema/positive model |
| `custom` | Khác |

### `info.severity` — enum

| Giá trị | Multiplier mặc định |
|---|---|
| `critical` | 2.0 |
| `high` | 1.5 |
| `medium` | 1.0 |
| `low` | 0.5 |
| `info` | 0.0 |

---

## §when

Pre-filter: rule chỉ chạy `inspect → detect` nếu mọi điều kiện thoả. Tất cả field optional.

```jsonc
"when": {
  "methods":        ["GET", "POST"],
  "path_prefix":    ["/api/"],
  "path_exclude":   ["/health"],
  "min_score":      0,
  "max_score":      9999,
  "require_labels": [],
  "exclude_labels": []
}
```

| Field | Type | Default | Mô tả |
|---|---|---|---|
| `methods` | string[] | `[]` | HTTP method. `[]` = tất cả |
| `path_prefix` | string[] | `[]` | Path bắt đầu bằng. `[]` = tất cả |
| `path_exclude` | string[] | `[]` | Bỏ qua nếu path bắt đầu bằng |
| `min_score` | number | `0` | Score hiện tại ≥ ngưỡng |
| `max_score` | number | `9999` | Score hiện tại < ngưỡng |
| `require_labels` | string[] | `[]` | Request phải có tất cả label |
| `exclude_labels` | string[] | `[]` | Bỏ qua nếu request có bất kỳ label |

> `path_prefix` và `path_exclude` cùng tồn tại: rule chạy nếu `prefix` match VÀ `exclude` không match.

---

## §inspect

Mảng selector. Engine match trên **mọi** selector, 1 match là đủ.

```jsonc
"inspect": [
  { "source": "args" },
  { "source": "header", "name": "User-Agent" }
]
```

### Source enum

| Source | Trả về | `name` cần thiết? |
|---|---|---|
| `path` | URL path (đã normalize) | – |
| `query` | Query string | – |
| `uri` | path + `?` + query | – |
| `body` | Body raw (capped 1MB) | – |
| `args` | Mọi tham số (query + form + JSON keys) | – |
| `header` | Một header | ✓ |
| `headers_all` | Toàn bộ header concat | – |
| `cookie` | Một cookie | ✓ |
| `cookies_all` | Toàn bộ cookie | – |
| `ip` | IP nguồn (dùng với `ip_match`) | – |
| `user_agent` | Header `User-Agent` (shortcut) | – |

---

## §transforms

Mảng transform chạy tuần tự cho mỗi selector value.

```jsonc
"transforms": ["url_decode", "lowercase", "compress_whitespace"]
```

### Transform list

| Transform | Tác dụng |
|---|---|
| `url_decode` | URL decode (iterative, max 3 lần) |
| `lowercase` | → lowercase |
| `uppercase` | → uppercase |
| `html_decode` | `&lt;` → `<` |
| `base64_decode` | Decode base64 (std + URL-safe) |
| `hex_decode` | `\x41` → `A` |
| `remove_nulls` | Xoá `\x00`, `%00`, `\\0` |
| `remove_whitespace` | Xoá hết whitespace |
| `compress_whitespace` | Multi-space → single |
| `replace_comments` | `/* */` → space |
| `cmd_normalize` | `c"m"d`, `c^md`, `cmd\\t` → `cmd` |
| `normalize_path` | `..`, `//`, `./` → canonical |
| `trim` | Strip leading/trailing whitespace |

---

## §detect

Boolean tree match.

```jsonc
"detect": {
  "logic":    "any",      // "any" | "all"
  "patterns": [
    { "type": "regex", "value": "...", "flags": "i", "negate": false }
  ]
}
```

### `detect.logic`

| Giá trị | Ý nghĩa |
|---|---|
| `"any"` (default) | 1 pattern match → rule match (OR) |
| `"all"` | mọi pattern phải match → rule match (AND) |

### Pattern object

| Field | Type | Bắt buộc | Mô tả |
|---|---|---|---|
| `type` | string | ✓ | Loại pattern (xem dưới) |
| `value` | string/number | tùy type | Giá trị so sánh |
| `values` | array | tùy type | Mảng giá trị (cho `wordlist`, `ip_match`) |
| `flags` | string | – | Flag cho `regex`: `i`/`m`/`s` |
| `negate` | bool | – | Đảo kết quả, default `false` |

### `pattern.type` enum

| `type` | Cần | Mô tả |
|---|---|---|
| `regex` | `value`, `flags?` | Regex Go RE2 |
| `contains` | `value` | Substring (nhanh) |
| `starts_with` | `value` | Tiền tố |
| `ends_with` | `value` | Hậu tố |
| `equals` | `value` | Bằng chính xác |
| `wordlist` | `values` | Một trong các từ (word boundary) |
| `entropy_gt` | `value` (số) | Shannon entropy > N |
| `length_gt` | `value` (số) | Độ dài > N |
| `length_lt` | `value` (số) | Độ dài < N |
| `ip_match` | `values` | IP/CIDR (dùng source `ip`) |

---

## §action

Hành động khi rule match.

```jsonc
"action": {
  "score":  5,
  "labels": [],
  "log":    true,
  "block":  false,
  "challenge": false,

  "ml_confirm": { ... },
  "track":      { ... }
}
```

### Top-level action fields

| Field | Type | Default | Mô tả |
|---|---|---|---|
| `score` | number | `0` | Điểm cộng (sẽ × `severity_multiplier`) |
| `labels` | string[] | `[]` | Tag request cho rule sau / decision engine |
| `log` | bool | `true` | Ghi audit log |
| `block` | bool | `false` | Force block bất kể tổng score |
| `challenge` | bool | `false` | Gửi CAPTCHA/PoW thay vì block |

### `action.ml_confirm`

Gọi ML service để xác nhận match.

```jsonc
"ml_confirm": {
  "enabled":            true,
  "input":              "body",
  "min_confidence":     0.7,
  "on_attack_add":      3,
  "on_normal_subtract": 2
}
```

| Field | Type | Default | Mô tả |
|---|---|---|---|
| `enabled` | bool | `false` | Bật ML confirm |
| `input` | string | `"body"` | Source gửi ML: `body`/`args`/`query`/`uri`/`headers_all` |
| `min_confidence` | number | `0.7` | ML confidence < ngưỡng → bỏ qua kết quả |
| `on_attack_add` | number | `0` | ML nói "attack" → cộng thêm score |
| `on_normal_subtract` | number | `0` | ML nói "normal" → trừ score |

Engine config: timeout ML, cache, breaker — đã có trong `internal/ml`, không cần đặt trong rule.

### `action.track`

Đếm số lần match theo scope, kích hoạt action khi vượt ngưỡng.

```jsonc
"track": {
  "enabled":            true,
  "scope":              "ip",
  "counter":            "sqli_attempts",
  "ttl_minutes":        10,
  "threshold":          5,
  "on_threshold_score": 5,
  "on_threshold_labels": ["repeat:sqli"]
}
```

| Field | Type | Default | Mô tả |
|---|---|---|---|
| `enabled` | bool | `false` | Bật tracking |
| `scope` | string | `"ip"` | `ip` / `session` / `global` |
| `counter` | string | rule ID | Tên counter (shared được nếu các rule khác nhau dùng cùng tên) |
| `ttl_minutes` | number | `10` | TTL counter — không match trong N phút → reset |
| `threshold` | number | `5` | Số lần để trigger |
| `on_threshold_score` | number | `0` | Khi counter ≥ threshold, cộng thêm điểm |
| `on_threshold_labels` | string[] | `[]` | Thêm label khi vượt ngưỡng |

---

## §except

Whitelist — match `except` → bỏ qua rule.

```jsonc
"except": {
  "ips":           ["10.0.0.1", "192.168.0.0/16"],
  "paths":         ["/admin/sql-console"],
  "path_prefixes": ["/internal/"],
  "user_agents":   ["HealthCheck", "Pingdom"],
  "labels":        ["bypass:internal-scan"]
}
```

| Field | Type | Match kiểu |
|---|---|---|
| `ips` | string[] | IP exact hoặc CIDR |
| `paths` | string[] | Exact path |
| `path_prefixes` | string[] | Path prefix |
| `user_agents` | string[] | UA substring (case-insensitive) |
| `labels` | string[] | Request có label |

---

## Validation rules (engine enforce)

Engine reject toàn ruleset nếu:

| Lỗi | Mô tả |
|---|---|
| Duplicate `id` | Hai rule cùng ID |
| `info.severity` không hợp lệ | Phải ∈ enum |
| `info.category` rỗng | Bắt buộc |
| `inspect` rỗng | Cần ít nhất 1 selector |
| `detect.patterns` rỗng | Cần ít nhất 1 pattern |
| `inspect[].source = "header"/"cookie"` thiếu `name` | Bắt buộc |
| Regex compile fail | RE2 syntax error |
| `track.scope` không hợp lệ | Phải ∈ {`ip`, `session`, `global`} |
| `ml_confirm.input` không hợp lệ | Source không tồn tại |

Có thể bật chế độ `lenient: true` ở config — engine sẽ skip rule lỗi thay vì reject toàn bộ.

---

## Score formula

```
score_thật = action.score × severity_multiplier(info.severity)
```

Sau đó engine có thể adjust thêm bằng:
- `ml_confirm` (cộng/trừ theo ML verdict)
- `track` (cộng `on_threshold_score` khi counter vượt threshold)

Tổng score = Σ(score_thật của mọi rule match).

Decision (config global, không phải rule):
- Tổng ≥ `block_threshold` (default 10) → BLOCK
- Tổng ≥ `challenge_threshold` (default 5) → CHALLENGE
- Tổng ≥ `log_threshold` (default 3) → LOG
- Khác → ALLOW

Một rule có `action.block: true` → force BLOCK bất kể tổng.
