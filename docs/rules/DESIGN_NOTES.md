# Design Notes — Vì sao schema được thiết kế như vậy

Tài liệu này giải thích **các quyết định thiết kế** của schema v2. Phù hợp đọc khi báo cáo đồ án hoặc giải trình cho người review.

---

## 1. Bối cảnh

WAF của đồ án đã có:
- 36 rule schema v1 (`configs/rules/all_rules.json`)
- ML service (DistilBERT v7, 10-class: normal/sqli/xss/cmdi/path_traversal/ssrf/xxe/log4shell/ssti/nosqli)
- Behavior detector (in-memory, theo IP)
- Decision engine (threshold-based)
- Dashboard quản lý rule

Schema v1 được viết sớm khi chưa tích hợp ML/behavior. Nó chỉ là "signature + score". Vấn đề:
- Không tận dụng ML có sẵn (ML chạy bên ngoài engine, hardcode trong middleware)
- Không tận dụng behavior detector
- Cứng nhắc: nhiều pattern luôn là OR, không AND
- Một số bug structural (duplicate ID, action không nhất quán)

Mục tiêu schema v2: **tận dụng những module đã có, fix bug v1, vẫn giữ độ phức tạp ở mức đồ án**.

---

## 2. Nguyên tắc thiết kế

### 2.1. Tránh kitchen sink

Đã khảo sát rule format của OWASP CRS, AWS WAF, Cloudflare, Coraza, Suricata. Các format này có rất nhiều tính năng:

| Tính năng | Có trong format khác? | Đưa vào schema v2? |
|---|---|---|
| Phase 1-5 (request → response → logging) | CRS, Coraza | ❌ Đồ án chỉ inspect REQUEST. Response/logging chưa cần. |
| Paranoia level | CRS | ❌ Quá tinh xảo cho 78 rule. Khi nào có 500+ rule mới cần. |
| Chain (CRS-style AND xuyên rule) | CRS | ❌ Đã có `detect.logic: "all"` cho AND trong cùng rule. Chain xuyên rule rối, dùng `labels` đủ. |
| libinjection (`@detectSQLi`/`@detectXSS`) | CRS, Coraza | ❌ Cần cgo hoặc Go port. Đồ án dùng regex + ML đã đủ. |
| Persistent state Redis | CRS | ❌ Behavior detector của đồ án đang in-memory, đủ với scale đồ án. |
| JSONPath / XPath selector | Cloudflare | ❌ Đa số attack pattern không cần selector chính xác mức field. |
| Skip-after markers | CRS | ❌ Phức tạp. Optimization hơn là feature. |
| Multi-file ruleset | CRS, Coraza | ❌ 78 rule chưa cần tách file. Single file dễ quản lý. |
| Sets manager (IP set, wordlist) | CRS | ⚠️ Đã có Blacklist/Whitelist riêng. Không nhân đôi. |
| Boolean combinators (AND/OR/NOT) | AWS WAF | ✓ Đơn giản hoá: `detect.logic` + `pattern.negate` |
| Labels (tag → consume) | AWS WAF | ✓ Đơn giản, mạnh, low overhead |
| Rate limit in-rule | AWS WAF | ✓ Tích hợp vào `action.track` |
| Capture group | CRS, Coraza | ❌ Chưa cần ở scope đồ án — có thể thêm sau qua `pattern.capture: true` |
| ML như operator | – | ✓ **Đặc thù đồ án này**, không format nào có |

→ Schema v2 chỉ thêm những thứ **trực tiếp giải quyết vấn đề của đồ án**: ML integration, behavior tracking, negate, AND/OR, labels.

### 2.2. Backward compatibility

Schema v2 không cố gắng tương thích **JSON-level** với v1. Lý do:
- Mới có 36 rule, migrate tay không tốn nhiều.
- Backward compat làm schema rối (vd phải support cả `conditions.targets` và `inspect`).

Thay vào đó cung cấp [MIGRATION.md](./MIGRATION.md) + script convert.

### 2.3. Field naming

Quy ước:

| v2 | Lý do |
|---|---|
| `info` thay `metadata` | Ngắn hơn, không gây nhầm với metadata HTTP |
| `when` thay `conditions` | Đọc tự nhiên: "when ... → do ..." |
| `inspect` thay `targets` | "Inspect" tả rõ hành động hơn "targets" |
| `detect` thay `patterns` | Bao trùm cả `logic` + `patterns` |
| `action` (singular) thay `actions` | Vì action giờ là object có cấu trúc, không phải array |
| `except` thay `exceptions` | Ngắn hơn |
| `score` thay `anomaly_score` | Đỡ rườm rà, vì đã có context |
| Snake case (`min_score`) | Đồng nhất, không mix camelCase |

### 2.4. Default sensible

Mọi field optional đều có default hợp lý. Một rule **tối thiểu** chỉ cần:

```json
{
  "id": "WAF-X",
  "info": { "category": "sqli", "severity": "high" },
  "inspect": [{"source": "args"}],
  "detect": {"patterns": [{"type": "regex", "value": "..."}]}
}
```

Engine fill: `enabled: true`, `transforms: []`, `action: {score: 0, log: true, ...}`, `except: {}`, `when: {}`.

---

## 3. Các quyết định cụ thể

### 3.1. Vì sao tách `when` khỏi `detect`?

`when` chạy **trước**, không tính match. Lý do:
- **Performance**: rule không liên quan path `/health` thì không cần gọi regex, không cần parse body.
- **Rõ ý đồ**: tách "khi nào áp dụng" (cấu hình) khỏi "tìm cái gì" (logic match).

v1 trộn cả 2 vào `conditions` (methods + path_patterns + targets), khó đọc.

### 3.2. Vì sao `inspect` là array of objects mà không phải array of strings?

v1:
```json
"targets": ["PATH", "QUERY", "BODY"]
```

v2:
```json
"inspect": [
  {"source": "path"},
  {"source": "header", "name": "User-Agent"}
]
```

Lý do: cần object để truyền tham số như `name` (cho header/cookie cụ thể). String đơn giản không scale.

### 3.3. Vì sao `detect.logic` chỉ có `any`/`all`, không có `none`?

`none` (= không pattern nào match) hiếm khi cần và dễ nhầm. Thay vào đó dùng `pattern.negate: true` trên từng pattern.

Vd "request không phải JSON":
```json
{"type": "starts_with", "value": "application/json", "negate": true}
```

Đủ rõ, không cần `logic: "none"`.

### 3.4. Vì sao `action.score` là điểm thô, không phải điểm cuối?

v1 có `anomaly_score` (thô) + `severity_multiplier` (nhân riêng từng rule).

v2 giữ ý tưởng nhưng đơn giản hoá: `severity_multiplier` **auto** lấy từ `info.severity`. Người viết rule không cần nhớ map severity → multiplier.

Có cần override? — Hiếm. Khi cần, có thể thêm field `action.score_multiplier_override` ở tương lai.

### 3.5. Vì sao `ml_confirm` là phần của `action`, không phải `detect`?

Ban đầu định cho ML là một loại `pattern.type` (operator match). Nhưng:
- ML round-trip 200-800ms, gọi mỗi pattern check là không thực tế.
- Logic thường là "**sau khi** signature match → mới gọi ML để confirm". Tức ML là **action**, không phải condition.

→ Đặt vào `action`. Rule signature match nhanh (regex local) → trigger → mới gọi ML adjust score.

### 3.6. Vì sao có cả `action.block: true` và score-based block?

Schema CRS thuần score-based — không có rule "block đơn lẻ". Nhưng có trường hợp cần block dứt khoát:
- CVE virtual patch (log4shell): payload đặc trưng, không có FP, phải block ngay.
- Rule whitelist-fail (positive model): vi phạm hard requirement.

→ `action.block: true` cho phép skip score model cho những case này.

### 3.7. Vì sao `track` đơn giản (in-memory) chứ không Redis?

Behavior detector hiện tại của đồ án đang in-memory. Đồ án single-instance, không cần shared state. Thêm Redis dependency:
- Tăng độ phức tạp deploy
- Tăng latency mỗi request
- Vượt scope đồ án

Khi nào nâng cấp Redis: khi multi-instance deploy (load balancer phân tán). Schema không cần đổi — chỉ implementation thay backend.

### 3.8. Vì sao `labels` chứ không phải `tags`?

`tags` đã được dùng trong `info.tags` (metadata, static). `labels` là **dynamic** (gắn vào request runtime). Tách tên để tránh nhầm.

Inspiration: AWS WAF dùng "labels" cùng nghĩa.

### 3.9. Vì sao chỉ có 3 scope cho `track`?

`ip` / `session` / `global` đủ cover:
- IP: brute force, scanner (1 IP nhiều request)
- Session: ATO sau khi đã login
- Global: pattern toàn site (vd "có ai đó đang dò /admin/" trên toàn thế giới)

Còn `user_id`, `country`, `tuple(ip+ua)` — hiếm khi cần ở scope đồ án. Có thể mở rộng sau bằng cách thêm enum.

---

## 4. Cái gì KHÔNG có trong schema (và lý do)

| Tính năng | Lý do bỏ |
|---|---|
| Multi-phase (response/logging phase) | Đồ án chưa inspect response. Khi cần thêm `info.phase: "request" \| "response"`. |
| Capture groups + variable interpolation `${capture.0}` | Phức tạp parser. Đồ án log toàn payload là đủ. |
| Chain rule (AND xuyên rule) | `labels` giải quyết tương đương. Chain dễ tạo cycle, khó debug. |
| Persistent state Redis | Single-instance, in-memory đủ. |
| libinjection | Cần cgo binding, deploy phức tạp. Regex + ML đủ tốt. |
| GeoIP | Cần data MaxMind, license issue, vượt scope. |
| JA3/JA4 TLS fingerprint | WAF chạy sau TLS termination, không có raw handshake. |
| OpenAPI schema validation | Cần parse OpenAPI spec, viết validator riêng. Vượt scope. |
| Rate-based statement riêng | Đã có `action.track` + module rate limit có sẵn. |
| Sets manager | Đã có Blacklist/Whitelist module. Không nhân đôi. |
| YAML format | JSON đủ. YAML thêm dependency parser, dễ ambiguous. |

Các tính năng bỏ trên đều có thể thêm sau **không breaking change** nếu tương lai cần.

---

## 5. Các engine bug v1 đã fix

| Bug v1 | Fix ở v2 |
|---|---|
| Duplicate rule ID (WAF-015..024 trùng) | Validator reject duplicate khi load |
| Regex không pre-compile, compile mỗi request | Compile lúc load, lưu trong rule object |
| `matchTokensProximity` logic sai (min/max của all positions) | Bỏ TOKEN type; thay bằng `detect.logic: "all"` + nhiều `contains` |
| `actions` không nhất quán (có rule có, có rule không) | `action` thành object có schema cố định, default rõ ràng |
| `exceptions.paths` chỉ exact match | Tách `paths` (exact) + `path_prefixes` (prefix) |
| `entropy` threshold hardcode 4.5 | Pattern `entropy_gt` lấy `value` từ rule |
| Transform chain không có size cap | Engine cap input length trước transform (config) |

---

## 6. Tương tác với module có sẵn

| Module | Tương tác |
|---|---|
| `internal/ml/client.go` | `action.ml_confirm` gọi qua `Client.Predict()`. Schema không quản lý cache/breaker — đã có sẵn. |
| `internal/behavior/detector.go` | `action.track` gọi qua API counter của detector (cần thêm method `Incr(scope, counter, ttl)` nếu chưa có). |
| `internal/decision/decision.go` | Đọc `labels` từ EvaluationResult để quyết định nâng cao (vd "có label `cve:log4shell` → BLOCK ngay"). |
| `internal/configstore` | Validator của v2 tích hợp vào `ValidateRulesJSON`. Hot-reload giữ nguyên cơ chế. |
| `internal/api/rules.go` | Dashboard upload rule v2 — endpoint giữ nguyên, chỉ schema phía sau khác. |

---

## 7. Future work (ngoài scope đồ án)

Nếu sau đồ án muốn nâng cấp lên production:

1. **Capture + interpolation** — log chính xác payload đã match thay vì toàn body.
2. **Chain rule** — workflow phức tạp hơn `labels`.
3. **Multi-phase** — inspect response để chống info leak.
4. **Redis state backend** — multi-instance deployment.
5. **libinjection** — dùng `corazawaf/libinjection-go` (pure Go port).
6. **FTW compatibility** — chạy được CRS test suite chính thức.
7. **Rule UI builder** — visual editor cho `detect` tree.
8. **A/B testing** — `info.experiment` field để chia request giữa rule cũ/mới.

Tất cả đều **additive** (thêm field optional), không breaking schema v2.

---

## 8. Tóm tắt: 4 nguyên tắc

1. **Phù hợp scope đồ án** — không thêm tính năng để cho đẹp, chỉ thêm khi giải quyết vấn đề thực tế.
2. **Tận dụng module có sẵn** — ML, behavior, decision đã có → schema design để tích hợp, không xây lại.
3. **Đơn giản hoá so với OWASP CRS** — bỏ phase, paranoia, chain, persistent collections. Giữ idea anomaly score và transform chain.
4. **Sẵn sàng mở rộng** — mọi quyết định bỏ tính năng đều có path nâng cấp sau, không breaking.
