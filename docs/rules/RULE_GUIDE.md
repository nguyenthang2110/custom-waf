# Hướng dẫn viết Rule

> Đây là tài liệu **hướng dẫn từng bước**. Sau khi đọc xong, bạn sẽ biết cách viết một rule mới từ con số 0. Tham khảo bộ luật thật ở [`configs/rules/all_rules.json`](../../configs/rules/all_rules.json).

---

## Mục lục

1. [Tư duy chung: rule WAF làm gì?](#1-tư-duy-chung-rule-waf-làm-gì)
2. [Bố cục một rule](#2-bố-cục-một-rule)
3. [Bước 1 — Định danh & metadata](#3-bước-1--định-danh--metadata-id--info)
4. [Bước 2 — Khi nào áp dụng rule (`when`)](#4-bước-2--khi-nào-áp-dụng-rule-when)
5. [Bước 3 — Lấy data từ request (`inspect`)](#5-bước-3--lấy-data-từ-request-inspect)
6. [Bước 4 — Chuẩn hoá data (`transforms`)](#6-bước-4--chuẩn-hoá-data-transforms)
7. [Bước 5 — Pattern nhận diện (`detect`)](#7-bước-5--pattern-nhận-diện-detect)
8. [Bước 6 — Khi match làm gì (`action`)](#8-bước-6--khi-match-làm-gì-action)
9. [Bước 7 — Loại trừ (`except`)](#9-bước-7--loại-trừ-except)
10. [Gộp lại: rule hoàn chỉnh](#10-gộp-lại-rule-hoàn-chỉnh)
11. [3 pattern hay dùng](#11-3-pattern-hay-dùng)
12. [Sai lầm thường gặp](#12-sai-lầm-thường-gặp)

---

## 1. Tư duy chung: rule WAF làm gì?

Một rule WAF trả lời 3 câu hỏi:

> **(1) Tôi đang nhìn vào cái gì?** — phần nào của HTTP request?
> **(2) Tôi đang tìm cái gì?** — pattern nào báo hiệu tấn công?
> **(3) Tìm thấy rồi thì làm gì?** — log, cộng điểm, block, gọi ML?

Schema v2 ánh xạ 3 câu hỏi này thành 3 phần: `inspect` → `detect` → `action`.

Đi kèm là metadata (`info`), điều kiện áp dụng (`when`), chuẩn hoá data (`transforms`) và whitelist (`except`).

**Mô hình điểm số (anomaly scoring)**

WAF không quyết định block ngay khi 1 rule match. Mỗi rule chỉ cộng vào một **tổng điểm** của request:

```
Rule WAF-001 match → +5 điểm
Rule WAF-007 match → +3 điểm
Rule WAF-024 match → +2 điểm
─────────────────────────────
Tổng:                 10 điểm  →  BLOCK (vì ≥ threshold 10)
```

Threshold là cấu hình toàn cục, không phải của từng rule. Một rule "yếu" chỉ cộng 2 điểm, nhiều rule yếu cộng dồn mới chặn — giúp giảm false positive so với "1 rule match = block".

---

## 2. Bố cục một rule

```jsonc
{
  "id":         "WAF-001-SQLI-UNION",
  "version":    "2.0",
  "enabled":    true,

  "info":       { /* §3 */ },
  "when":       { /* §4 */ },
  "inspect":    [ /* §5 */ ],
  "transforms": [ /* §6 */ ],
  "detect":     { /* §7 */ },
  "action":     { /* §8 */ },
  "except":     { /* §9 */ }
}
```

3 field bắt buộc: `id`, `inspect`, `detect`. Còn lại có default hợp lý nếu omit.

---

## 3. Bước 1 — Định danh & metadata (`id` + `info`)

```jsonc
{
  "id":      "WAF-001-SQLI-UNION",
  "version": "2.0",
  "enabled": true,

  "info": {
    "category":    "sqli",
    "severity":    "critical",
    "description": "Phát hiện SQL Injection kiểu UNION-based",
    "tags":        ["sqli", "owasp-a03", "cwe-89"],
    "author":      "NHT",
    "created":     "2026-05-13"
  }
}
```

### Quy ước đặt `id`

`WAF-<số>-<loại>-<biến_thể>`. Ví dụ:
- `WAF-001-SQLI-UNION` — UNION-based SQLi
- `WAF-007-XSS-EVENTHANDLER` — XSS qua event handler
- `WAF-103-ATO-BRUTE-LOGIN` — credential stuffing trên endpoint /login

**ID phải duy nhất** trong toàn ruleset. Engine reject load nếu trùng (đây là một bug ở schema v1, đã sửa ở v2).

### `info.category`

Giá trị chuẩn (canonical):

| Category | Ý nghĩa |
|---|---|
| `sqli` | SQL Injection |
| `xss` | Cross-Site Scripting |
| `lfi` | Local File Inclusion / Path Traversal |
| `rce` | Remote Code Execution |
| `ssrf` | Server-Side Request Forgery |
| `xxe` | XML External Entity |
| `nosqli` | NoSQL Injection |
| `scanner` | Scanner / fingerprinting tool |
| `bot` | Bot hành vi bất thường |
| `ato` | Account Takeover (brute force, credential stuffing) |
| `dos` | Denial of Service (request size, slow, flood) |
| `info_leak` | Lộ thông tin |
| `schema` | Vi phạm schema API/positive model |

### `info.severity`

| Severity | Score multiplier mặc định | Khi nào dùng |
|---|---|---|
| `critical` | × 2.0 | Tấn công nghiêm trọng, payload rõ ràng (UNION SELECT, log4shell) |
| `high` | × 1.5 | Pattern đặc trưng nhưng có thể FP (boolean SQLi `or 1=1`) |
| `medium` | × 1.0 | Heuristic (UA scanner, ký tự lạ) |
| `low` | × 0.5 | Tín hiệu yếu (thiếu Accept-Language, body lớn) |
| `info` | × 0 | Chỉ tag/log, không cộng điểm |

> Score thật cộng vào tổng = `action.score × severity_multiplier`. Xem §8.

### `info.tags`

Tag dùng để **lọc/thống kê/loại trừ**. Quy ước `namespace:value`:

- `attack:sqli` — loại tấn công
- `owasp-a03` — OWASP Top 10
- `cwe-89` — CWE
- `cve-2021-44228` — virtual patch CVE
- `language:php` — chỉ PHP app (có thể disable cho .NET app)

---

## 4. Bước 2 — Khi nào áp dụng rule (`when`)

`when` là **bộ lọc trước**: nếu không khớp, engine bỏ qua rule, không chạy match. Mục đích: tránh quét pattern SQLi trên request GET `/health`.

```jsonc
"when": {
  "methods":        ["GET", "POST", "PUT"],
  "path_prefix":    ["/api/", "/admin/"],
  "path_exclude":   ["/api/health", "/api/metrics"],

  "min_score":      0,
  "max_score":      9999,

  "require_labels": [],
  "exclude_labels": []
}
```

| Field | Mặc định | Ý nghĩa |
|---|---|---|
| `methods` | `[]` = tất cả | HTTP method được áp dụng |
| `path_prefix` | `[]` = tất cả | Chỉ áp dụng nếu path **bắt đầu bằng** một trong các giá trị |
| `path_exclude` | `[]` | Loại trừ nếu path bắt đầu bằng (override `path_prefix`) |
| `min_score` | `0` | Chỉ chạy nếu score hiện tại của request ≥ ngưỡng |
| `max_score` | `9999` | Chỉ chạy nếu score hiện tại < ngưỡng |
| `require_labels` | `[]` | Chỉ chạy nếu request đã có **tất cả** label này |
| `exclude_labels` | `[]` | Bỏ qua nếu request có **bất kỳ** label này |

### Khi nào dùng `min_score`/`max_score`?

Đây là tinh tuý: cho phép viết **rule amplifier** chỉ kích hoạt khi đã có nghi ngờ.

```jsonc
{
  "id": "WAF-ML-GRAYZONE",
  "when": { "min_score": 3, "max_score": 7 },   // chỉ chạy ở "gray zone"
  ...
  "action": { "ml_confirm": { "enabled": true, ... } }
}
```

Ý nghĩa: rule này chỉ gọi ML khi score đã ở vùng "lưng chừng" (3-7) — score < 3 thì chắc chắn benign, score ≥ 7 thì chắc chắn attack, không cần phí gọi ML.

### `require_labels` / `exclude_labels`

Rule A tag request, rule B đọc tag:

```jsonc
// Rule A: signature SQLi → tag
{
  "id": "WAF-001-SQLI-SIGNATURE",
  "action": { "labels": ["sig:sqli"] }
}

// Rule B: chỉ chạy khi đã có signature tag
{
  "id": "WAF-002-SQLI-AMPLIFIER",
  "when": { "require_labels": ["sig:sqli"] },
  "action": { "ml_confirm": { "enabled": true } }
}
```

→ Tạo workflow: detect → confirm → amplify.

---

## 5. Bước 3 — Lấy data từ request (`inspect`)

Một mảng selector. Engine sẽ chạy match trên **mỗi** selector → 1 match là đủ trigger rule.

```jsonc
"inspect": [
  { "source": "path" },
  { "source": "query" },
  { "source": "body" },
  { "source": "args" },                       // tất cả tham số (GET + POST + JSON keys)
  { "source": "header", "name": "User-Agent" },
  { "source": "header", "name": "Referer" },
  { "source": "headers_all" },                // tất cả header (cho rule như log4shell)
  { "source": "cookie",  "name": "session" },
  { "source": "cookies_all" },
  { "source": "uri" },                        // path + query
  { "source": "ip" },                         // dùng với detect.ip_match
  { "source": "user_agent" }                  // shortcut của header User-Agent
]
```

### Bảng source

| Source | Trả về | Ghi chú |
|---|---|---|
| `path` | URL path (đã normalize) | `/users/123` |
| `query` | Query string | `id=1&name=foo` |
| `uri` | path + query | |
| `body` | Body raw | Capped 1MB (config) |
| `args` | Tất cả param (GET + POST form + JSON keys) | Khuyến nghị dùng cho SQLi/XSS rule |
| `header` | Một header cụ thể (chỉ định `name`) | |
| `headers_all` | Toàn bộ header gộp thành 1 string | Cho rule scan toàn bộ |
| `cookie` | Một cookie cụ thể | |
| `cookies_all` | Toàn bộ cookie | |
| `ip` | IP nguồn | Dùng với pattern type `ip_match` |
| `user_agent` | Shortcut header UA | |

### Mẹo chọn source

- **SQLi/XSS**: dùng `args` (bao trùm GET + POST + JSON) thay vì phải khai báo riêng `query` + `body`.
- **Path traversal**: dùng `path` và `args` (tham số `?file=...` cũng có thể chứa `../`).
- **Log4Shell**: dùng `headers_all` + `body` + `args` (payload có thể nằm ở mọi nơi).
- **Scanner UA**: dùng `user_agent`.

---

## 6. Bước 4 — Chuẩn hoá data (`transforms`)

Trước khi match, engine chạy chain transform để **vô hiệu hoá các kỹ thuật né tránh**. Ví dụ attacker viết `UNION%20SELECT` thay vì `UNION SELECT` — phải `url_decode` trước.

```jsonc
"transforms": ["url_decode", "lowercase", "compress_whitespace"]
```

Chain chạy **tuần tự** theo thứ tự khai báo.

### Bảng transform

| Transform | Tác dụng | Khi nào dùng |
|---|---|---|
| `url_decode` | `%20` → space | Hầu như luôn cần |
| `lowercase` | `UNION` → `union` | Khi pattern không có `flags: "i"` |
| `html_decode` | `&lt;` → `<` | Chống XSS encode HTML entity |
| `base64_decode` | Decode base64 | Payload giấu trong base64 |
| `remove_nulls` | Xoá `\x00`, `%00` | Chống null-byte truncation |
| `remove_whitespace` | Xoá hết khoảng trắng | Khi pattern không có space |
| `compress_whitespace` | Nhiều space → 1 space | Chống `UNION\t\n  SELECT` |
| `replace_comments` | `/* */` → space | Chống SQLi `UN/**/ION` |
| `cmd_normalize` | Xử lý `c^md`, `c"m"d`, `c\\md` | Chống command injection evasion |
| `normalize_path` | `..`, `//`, `./` → canonical | Chống path traversal evasion |
| `trim` | Strip leading/trailing space | |

### Mẹo

- **Mọi rule signature**: ít nhất `url_decode` + `lowercase`.
- **SQLi**: thêm `compress_whitespace` + `replace_comments`.
- **XSS**: thêm `html_decode`.
- **RCE shell command**: thêm `cmd_normalize`.
- **LFI**: thêm `normalize_path`.

---

## 7. Bước 5 — Pattern nhận diện (`detect`)

```jsonc
"detect": {
  "logic": "any",                                // any (OR) | all (AND)
  "patterns": [
    { "type": "regex",    "value": "union\\s+select", "flags": "i", "negate": false },
    { "type": "contains", "value": "1=1" },
    { "type": "wordlist", "values": ["sleep(", "benchmark("] }
  ]
}
```

### `logic`

- `"any"` (mặc định): **một** pattern match là đủ → OR.
- `"all"`: **mọi** pattern phải match → AND.

Ví dụ AND:

```jsonc
"detect": {
  "logic": "all",
  "patterns": [
    { "type": "contains", "value": "<script" },
    { "type": "contains", "value": "alert("  }
  ]
}
```

→ Chỉ trigger khi có **cả hai** `<script` VÀ `alert(`.

### Bảng pattern `type`

| `type` | Field cần | Mô tả |
|---|---|---|
| `regex` | `value`, `flags?` | Regex (Go RE2). `flags`: `"i"` = case-insensitive |
| `contains` | `value` | Substring đơn giản (nhanh hơn regex) |
| `starts_with` | `value` | Bắt đầu bằng |
| `ends_with` | `value` | Kết thúc bằng |
| `equals` | `value` | Bằng chính xác |
| `wordlist` | `values: [...]` | Một trong danh sách từ — match word boundary |
| `entropy_gt` | `value` (số) | Shannon entropy > N (phát hiện base64/random string) |
| `length_gt` | `value` (số) | Độ dài > N |
| `length_lt` | `value` (số) | Độ dài < N |
| `ip_match` | `values: [...]` | IP/CIDR (dùng với source `ip`) |

### `negate`

Đảo kết quả. Ví dụ:

```jsonc
{ "type": "starts_with", "value": "application/json", "negate": true }
```

→ Match khi Content-Type **không** bắt đầu bằng `application/json`. Dùng cho positive security model (allowlist).

### `flags` cho `regex`

- `i` — case-insensitive
- `m` — multiline (`^`/`$` khớp đầu/cuối dòng)
- `s` — `.` khớp cả newline

---

## 8. Bước 6 — Khi match làm gì (`action`)

```jsonc
"action": {
  "score":   5,
  "labels":  ["attack:sqli"],
  "log":     true,
  "block":   false,

  "ml_confirm": {
    "enabled":            false,
    "input":              "body",
    "min_confidence":     0.7,
    "on_attack_add":      3,
    "on_normal_subtract": 2
  },

  "track": {
    "enabled":           false,
    "scope":             "ip",
    "counter":           "sqli_attempts",
    "ttl_minutes":       10,
    "threshold":         5,
    "on_threshold_score": 5
  }
}
```

### `score` — Cộng điểm

Số điểm thô. Engine sẽ nhân với `severity_multiplier` (auto từ `info.severity`).

- Score `5` + severity `critical` (×2.0) = **10 điểm thật**.
- Score `3` + severity `medium` (×1.0) = **3 điểm thật**.

Khuyến nghị giá trị `score`:

| Loại rule | Score gợi ý |
|---|---|
| Pattern đặc trưng (UNION SELECT, log4shell) | 5 |
| Pattern thường (1=1, `<script`) | 3 |
| Heuristic (UA scanner, header lạ) | 2 |
| Tín hiệu yếu (thiếu Accept-Language) | 1 |
| Pure tagging (không muốn cộng điểm) | 0 |

### `labels` — Tag request

Mảng string. Tag tồn tại đến hết request, **rule sau** đọc qua `when.require_labels`.

Use case:
1. **Workflow**: rule signature → tag → rule ML confirm
2. **Decision routing**: decision engine đọc label thay vì list matched_rules
3. **Whitelist động**: rule internal scanner → tag `bypass:scan` → rule khác `exclude_labels: ["bypass:scan"]`

Quy ước:
- `attack:<type>` — loại tấn công đã xác nhận
- `sig:<name>` — signature đã match
- `ml:<verdict>` — kết quả ML
- `bypass:<reason>` — đánh dấu bỏ qua
- `bot:<heuristic>` — bot indicator

### `log` / `block`

| Field | Ý nghĩa |
|---|---|
| `log` | Ghi vào audit log với severity từ `info.severity`. Mặc định `true`. |
| `block` | **Force block** ngay cả khi score chưa tới threshold. Dùng cho rule "thấy là chặn" (vd log4shell payload). |

Quy tắc:
- 99% rule chỉ cần `log: true, block: false` — để score model quyết định.
- Chỉ set `block: true` khi rule **rất chắc chắn** (vd CVE virtual patch).

### `ml_confirm` — Gọi ML xác nhận

Dùng để **giảm false positive** của rule signature.

```jsonc
"ml_confirm": {
  "enabled":            true,
  "input":              "body",        // source nào gửi ML
  "min_confidence":     0.7,           // confidence tối thiểu để tin ML
  "on_attack_add":      3,             // nếu ML đồng ý attack → cộng thêm 3
  "on_normal_subtract": 2              // nếu ML nói normal → trừ 2
}
```

Cơ chế:
1. Rule signature match → cộng `score`.
2. Engine gọi `ml-service` với data từ `input`.
3. ML trả `(label, confidence)`.
4. Nếu `confidence < min_confidence` → bỏ qua kết quả ML (không adjust).
5. Nếu ML nói "attack" → cộng thêm `on_attack_add` (củng cố).
6. Nếu ML nói "normal" → trừ `on_normal_subtract` (rule có thể là FP).

→ Rule signature cho **recall** (bắt nhiều), ML cho **precision** (lọc FP). Cuối cùng score chính xác hơn nhiều so với chỉ dùng signature.

`input` có thể là: `body`, `args`, `query`, `uri`, `headers_all`.

### `track` — Đếm số lần match

Cho phép rule đếm số lần match theo IP/session, kích hoạt hành động khi vượt ngưỡng. Đây là cách triển khai detection brute-force / scanner / repeated attempts ngay trong rule.

```jsonc
"track": {
  "enabled":            true,
  "scope":              "ip",            // ip | session | global
  "counter":            "sqli_attempts", // tên counter (unique per rule hoặc shared)
  "ttl_minutes":        10,              // counter reset sau N phút không hoạt động
  "threshold":          5,               // khi counter >= N
  "on_threshold_score": 5                // → cộng thêm bao nhiêu điểm
}
```

Ví dụ ý nghĩa: "Nếu cùng IP match rule SQLi quá 5 lần trong 10 phút → cộng thêm 5 điểm (likely persistent attacker, không phải FP)".

`scope`:
- `ip` — counter theo IP nguồn
- `session` — counter theo session cookie / token
- `global` — counter chung cho mọi IP (vd: "tổng số lần endpoint /admin bị scan")

---

## 9. Bước 7 — Loại trừ (`except`)

Whitelist: nếu match → skip rule này (không match, không cộng điểm).

```jsonc
"except": {
  "ips":           ["10.0.0.1", "192.168.0.0/16"],
  "paths":         ["/admin/sql-console"],
  "path_prefixes": ["/internal/"],
  "user_agents":   ["HealthCheck", "Pingdom"],
  "labels":        ["bypass:internal-scan"]
}
```

| Field | Match kiểu | Ghi chú |
|---|---|---|
| `ips` | IP hoặc CIDR | `10.0.0.1` exact, `10.0.0.0/8` range |
| `paths` | Exact match | Cho endpoint cụ thể |
| `path_prefixes` | Prefix | Cho dải endpoint |
| `user_agents` | Substring | UA chứa chuỗi |
| `labels` | Có label | Request đã được rule khác tag |

> `except` áp dụng riêng cho **từng rule**. Nếu muốn whitelist toàn cục, dùng tính năng **Whitelist** ở dashboard (đã có sẵn module).

---

## 10. Gộp lại: rule hoàn chỉnh

Một rule SQLi UNION-based tích hợp đủ ML + tracking:

```jsonc
{
  "id":      "WAF-001-SQLI-UNION",
  "version": "2.0",
  "enabled": true,

  "info": {
    "category":    "sqli",
    "severity":    "critical",
    "description": "UNION-based SQL injection với ML confirmation + tracking repeat offenders",
    "tags":        ["sqli", "owasp-a03", "cwe-89"],
    "author":      "NHT",
    "created":     "2026-05-13"
  },

  "when": {
    "methods":      ["GET", "POST", "PUT"],
    "path_exclude": ["/health", "/metrics"]
  },

  "inspect": [
    { "source": "args" },
    { "source": "path" },
    { "source": "uri" }
  ],

  "transforms": [
    "url_decode",
    "lowercase",
    "compress_whitespace",
    "replace_comments"
  ],

  "detect": {
    "logic": "any",
    "patterns": [
      { "type": "regex",    "value": "\\bunion\\b[\\s\\S]{0,40}\\bselect\\b", "flags": "i" },
      { "type": "wordlist", "values": ["union all select", "union select"] }
    ]
  },

  "action": {
    "score":  5,
    "labels": ["attack:sqli", "sig:union"],
    "log":    true,
    "block":  false,

    "ml_confirm": {
      "enabled":            true,
      "input":              "body",
      "min_confidence":     0.7,
      "on_attack_add":      3,
      "on_normal_subtract": 2
    },

    "track": {
      "enabled":            true,
      "scope":              "ip",
      "counter":            "sqli_attempts",
      "ttl_minutes":        10,
      "threshold":          5,
      "on_threshold_score": 5
    }
  },

  "except": {
    "ips":           [],
    "paths":         [],
    "path_prefixes": [],
    "user_agents":   ["HealthCheck"],
    "labels":        ["bypass:admin"]
  }
}
```

---

## 11. 3 pattern hay dùng

### Pattern 1: Signature đơn giản (90% trường hợp)

Chỉ cần `inspect` + `detect` + `action.score`. Bỏ trống `ml_confirm` và `track`.

```jsonc
{
  "id": "WAF-XSS-SCRIPT-TAG",
  "info": { "category": "xss", "severity": "high" },
  "inspect": [{ "source": "args" }, { "source": "body" }],
  "transforms": ["url_decode", "lowercase", "html_decode"],
  "detect": {
    "patterns": [{ "type": "regex", "value": "<script[\\s>]" }]
  },
  "action": { "score": 4, "labels": ["attack:xss"] }
}
```

### Pattern 2: Signature + ML confirm (giảm FP)

Thêm `ml_confirm` cho rule có khả năng FP cao (vd boolean SQLi `or 1=1` — chuỗi này có thể xuất hiện trong content lành tính).

```jsonc
{
  "id": "WAF-SQLI-BOOLEAN",
  "info": { "category": "sqli", "severity": "high" },
  "inspect": [{ "source": "args" }],
  "transforms": ["url_decode", "lowercase"],
  "detect": {
    "patterns": [{ "type": "regex", "value": "\\b(or|and)\\b\\s+\\d+\\s*=\\s*\\d+" }]
  },
  "action": {
    "score": 3,
    "ml_confirm": {
      "enabled": true,
      "input": "args",
      "on_attack_add": 4,
      "on_normal_subtract": 3,
      "min_confidence": 0.75
    }
  }
}
```

### Pattern 3: Behavioral / tracking (brute force, scanner)

Rule không signature cụ thể, chỉ đếm số lần một hành vi xảy ra.

```jsonc
{
  "id": "WAF-ATO-LOGIN-BRUTE",
  "info": { "category": "ato", "severity": "high" },
  "when": {
    "methods": ["POST"],
    "path_prefix": ["/login", "/api/login"]
  },
  "inspect": [{ "source": "path" }],
  "detect": {
    "patterns": [{ "type": "starts_with", "value": "/login" }]
  },
  "action": {
    "score": 0,
    "track": {
      "enabled": true,
      "scope": "ip",
      "counter": "login_attempts",
      "ttl_minutes": 5,
      "threshold": 10,
      "on_threshold_score": 8
    },
    "labels": ["attack:brute-force"]
  }
}
```

→ Mỗi POST `/login` → counter +1. Khi counter ≥ 10 trong 5 phút → cộng 8 điểm → score đủ block.

---

## 12. Sai lầm thường gặp

### ❌ Quên `url_decode`

```jsonc
// Pattern này KHÔNG match `?q=union%20select`
"transforms": ["lowercase"],
"detect": { "patterns": [{ "type": "regex", "value": "union select" }] }
```

**Sửa**: luôn có `url_decode` cho rule signature.

### ❌ Regex case-sensitive nhưng có `lowercase` transform

```jsonc
// REDUNDANT — đã lowercase rồi mà còn dùng flag "i"
"transforms": ["url_decode", "lowercase"],
"detect": { "patterns": [{ "type": "regex", "value": "union", "flags": "i" }] }
```

**Sửa**: chọn 1. Nếu pattern dùng `flags: "i"` thì bỏ `lowercase` (và ngược lại). Khuyến nghị bỏ `flags: "i"` và giữ `lowercase` — pattern dễ đọc hơn.

### ❌ Score quá cao, single rule cũng block

```jsonc
"info": { "severity": "critical" },     // × 2.0
"action": { "score": 10 }               // → 20 điểm thật, một rule cũng vượt threshold 10
```

**Sửa**: trừ phi đó là CVE virtual patch (log4shell etc.), giữ `score` trong khoảng 2-5. Để score model làm việc.

### ❌ Block trong rule có khả năng FP

```jsonc
"detect": { "patterns": [{ "type": "contains", "value": "select" }] },
"action": { "block": true }    // sẽ block mọi request có chữ "select"
```

**Sửa**: chỉ `block: true` khi pattern **rất đặc trưng**. Pattern chung thì để score model quyết.

### ❌ Lạm dụng `ml_confirm`

ML round-trip ~200-800ms. Bật `ml_confirm` cho mọi rule → mỗi request gọi ML 30 lần → 24 giây latency.

**Sửa**: chỉ bật `ml_confirm` cho rule có FP cao. Hoặc tạo 1 rule "ML gateway" duy nhất với `when.min_score: 3, max_score: 7` để chỉ gọi ML khi cần.

### ❌ `track.scope: "global"` cho rule cá nhân hoá

```jsonc
"track": { "scope": "global", "counter": "login_fail", "threshold": 100 }
```

→ Đếm chung cho mọi IP, không có ý nghĩa "ai đang brute force tôi".

**Sửa**: dùng `scope: "ip"` hoặc `"session"`. `global` chỉ dùng cho metric kiểu "total attack volume" hiếm khi đưa vào rule action.

### ❌ Quên cập nhật `version`/`updated` khi sửa rule

Pháp lý audit khó truy: rule đã được sửa lúc nào, ai sửa.

**Sửa**: mỗi lần edit rule, tăng `version` và update `info.updated`.

---

## Bước tiếp theo

- Xem bộ luật thật đang chạy: [`configs/rules/all_rules.json`](../../configs/rules/all_rules.json) (78 rule, schema v2) để tham khảo cách viết thực tế từng field.
- Định nghĩa struct rule (v1 + v2) ở `internal/engine/types.go` và `loader.go`.
