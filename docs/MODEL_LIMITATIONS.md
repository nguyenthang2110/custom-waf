# Bất lợi của ML model 10-class hiện tại (v7)

Tài liệu này phân tích **giới hạn** của ML classifier (DistilBERT v7, 10-class: `normal | sqli | xss | cmdi | path_traversal | ssrf | xxe | log4shell | ssti | nosqli`) trong project và **chuyện gì xảy ra khi gặp attack ngoài 10 class**.

---

## 1. Mô hình hiện tại — recap nhanh

- **Backend**: FastAPI (`ml-service/`) + DistilBERT (base: `distilbert-base-uncased`, `max_length` 256) fine-tuned trên dataset gồm 10 lớp:
  - `normal` (request bình thường)
  - `sqli`
  - `xss`
  - `cmdi` (command injection)
  - `path_traversal`
  - `ssrf`
  - `xxe`
  - `log4shell`
  - `ssti`
  - `nosqli`
- **Inference**: model trả `(label, confidence)` cho 1 chuỗi text (body / args / uri…).
- **Vai trò trong WAF**: chạy "gray-zone consult" — khi rule score nằm trong dải `[3.0, 5.0)` (tức 3.0 ≤ score < 5.0), gọi ML để cộng/trừ điểm; ngoài ra rule v2 có thể bật `ml_confirm` để gọi ML xác nhận signature match.

→ Model **phân biệt được 9 loại attack đã train** (cộng class `normal`).

---

## 2. Vấn đề: 9 class attack vẫn chưa phủ hết OWASP Top 10

OWASP Top 10 (2021) gồm 10 nhóm rủi ro. Model 10-class (v7) trực tiếp cover phần lớn nhóm thiên về payload:

| OWASP rank | Tên | 10-class model bắt được? |
|---|---|---|
| A01 | Broken Access Control (IDOR, path traversal, file access) | ✓ Path traversal — phần; IDOR/business-logic thì không (không phải payload) |
| A02 | Cryptographic Failures | ✗ Không phải payload-pattern, model không có dữ liệu |
| A03 | Injection (SQLi, XSS, command injection, NoSQLi, LDAP, XPath, SSTI, ORM) | ✓ SQLi/XSS/cmdi/NoSQLi/SSTI — **chưa** cover LDAP, XPath, ORM injection |
| A04 | Insecure Design | ✗ Logic-level, không phải payload |
| A05 | Security Misconfiguration (XXE, default creds, verbose errors) | ✓ XXE đã có class riêng — default creds/verbose error thì không |
| A06 | Vulnerable Components (Log4Shell, Spring4Shell) | ✓ Log4Shell đã có class `log4shell` — các CVE khác (vd Spring4Shell) vẫn dựa rule |
| A07 | Identification & Authentication Failures (brute force, credential stuffing) | ✗ Behavioral, không phải single-request payload |
| A08 | Software/Data Integrity Failures (insecure deserialization) | ✗ Payload base64-ish lạ, không train |
| A09 | Logging & Monitoring | ✗ — |
| A10 | SSRF | ✓ Đã có class `ssrf` |

→ Với v7, model đã trực tiếp cover phần payload của **A01 (phần), A03 (phần lớn), A05 (XXE), A06 (Log4Shell), A10 (SSRF)**. Các nhóm còn lại — thiên về logic, hành vi, cấu hình hoặc CVE ngoài training — vẫn **phải dựa vào rule signature**.

---

## 3. Chuyện gì xảy ra khi gặp attack ngoài 9 class attack

Lưu ý: SSRF, XXE, Log4Shell, NoSQLi và SSTI **đã** có class riêng trong v7, nên các kịch bản dưới đây phản ánh **các khoảng trống còn lại** (attack không nằm trong 9 class, hoặc biến thể obfuscate vượt ngoài phân phối training).

### 3.1. Hiện trạng (failure modes)

**Kịch bản 1: Log4Shell obfuscate nặng `${${::-j}${::-n}${::-d}${::-i}:...}`**
- v7 có class `log4shell`, bắt tốt dạng chuẩn `${jndi:ldap://...}`.
- Nhưng với dạng obfuscate lồng nhiều lớp `${...}` rất lạ so với training → ML có thể tụt confidence hoặc classify nhầm thành `normal`.
- Nếu rule `WAF-035-RCE-LOG4SHELL` cũng không match dạng obfuscate này → score = 0 → ALLOW.
- ML gray-zone không kích hoạt (score = 0, dưới ngưỡng dưới 3.0 của dải `[3.0, 5.0)`) → ML không được gọi.
- **Kết quả**: payload đi qua WAF → backend bị tấn công.

**Kịch bản 2: LDAP / XPath injection**
- v7 cover SQLi/NoSQLi nhưng **không** có class cho LDAP injection (`*)(uid=*))(|(uid=*`) hay XPath injection (`' or '1'='1`).
- ML thấy payload "lạ" → có thể classify thành `normal` hoặc nhầm sang `sqli`.
- **Kết quả**: defense in depth cho LDAP/XPath chỉ còn rule signature.

**Kịch bản 3: SSRF obfuscate vượt phân phối**
- Rule `WAF-041-SSRF-CLOUD-METADATA` + class `ssrf` của v7 bắt tốt dạng `http://169.254.169.254/latest/meta-data/`.
- Nhưng dạng obfuscate (`http://[::ffff:169.254.169.254]`, `http://2852039166/`, DNS rebinding…) có thể vượt ngoài phân phối training → ML tụt confidence, không cộng điểm.
- **Kết quả**: defense in depth lại phụ thuộc chủ yếu vào rule.

**Kịch bản 4: Insecure deserialization / business-logic / IDOR**
- Các attack này **không có trong training set** (deserialization payload base64-ish lạ; IDOR/business-logic là logic-level, không phải pattern payload).
- Output: thường `normal` với confidence cao.
- → Nếu rule yếu hoặc không có, model **tích cực gây hại** (trừ điểm khi đáng ra phải cộng).

### 3.2. Tóm tắt 2 loại failure

| Failure | Hậu quả | Mức nghiêm trọng |
|---|---|---|
| **False negative** — ML nói `normal` cho attack thật | Bypass khi rule yếu / không có | Cao — attack thành công |
| **ML "hại defense in depth"** — ML trừ điểm hợp pháp khỏi signature match | Rule signature đúng nhưng bị ghi đè | Cao — paradox: model làm WAF yếu đi |

---

## 4. Tại sao ML 10-class **vẫn có giá trị** dù còn hạn chế

1. **Tăng precision cho các class chính**: SQLi và XSS là 60-80% traffic attack thực tế trên web app phổ thông; v7 còn cover thêm cmdi/path/ssrf/xxe/log4shell/ssti/nosqli. Cover tốt → giảm FP rule signature đáng kể.
2. **Confidence-aware**: rule v2 `ml_confirm.min_confidence` giúp **bỏ qua ML khi nó không tự tin** — phần nào hạn chế failure mode #2.
3. **Train được thêm**: dataset có thể mở rộng tiếp — v7 đã 10-class, có thể bổ sung thêm các loại injection khác trong tương lai.
4. **Không phải single point of defense**: rule signature + behavior detector + score model = defense in depth. ML chỉ là 1 lớp.

---

## 5. Cách giảm thiểu (mitigation đã có / nên thêm)

### 5.1. Đã có trong project hiện tại

| Cơ chế | Tác dụng |
|---|---|
| **Rule signature 78 rules** (13 nhóm OWASP-aligned) cover SSRF, XXE, NoSQLi, SSTI, log4shell, sensitive paths… | Bù trừ những gì ML không biết |
| **`ml_confirm.min_confidence: 0.7-0.8`** | ML không đủ tự tin → bỏ qua, không trừ điểm rule |
| **`action.block: true` cho CVE virtual patch** | Skip score model + ML, block dứt khoát |
| **Behavior detector** | Bắt brute force / scanner — pattern-blind, không cần ML |

### 5.2. Nên thêm (xếp theo ưu tiên)

**Ưu tiên 1: Mở rộng training set cho các khoảng trống còn lại của v7**

v7 đã cover ssrf/xxe/nosqli/ssti/log4shell. Các class còn thiếu nên bổ sung:
- `ldap_injection` — `*)(uid=*))(|(uid=*`, filter LDAP
- `xpath_injection` — `' or '1'='1`, `count(/*)`
- `deserialization` — payload Java/PHP/Python serialized (base64-ish, magic bytes)

Dataset: scrape từ PortSwigger labs, HackTricks, OWASP CRS test corpus.

Ngoài payload, các khoảng trống không thuộc dạng single-request payload (IDOR/business-logic, brute force/credential stuffing, evasion/obfuscation) cần hướng tiếp cận khác — xem các ưu tiên dưới.

**Ưu tiên 2: Anomaly-detection model song song**

Train 1 model thứ 2 (autoencoder hoặc isolation forest) trên **chỉ traffic bình thường**:
- Input: feature vector từ request (length, entropy, header count, special chars ratio, …)
- Output: anomaly score (0..1)
- Rule v2 mới dùng anomaly score như input: `inspect: [{"source":"ml_anomaly"}]`, `match: [{"type":"gt","value":0.8}]`

Lợi: bắt được **mọi attack lạ** mà không cần train từng class.

**Ưu tiên 3: Confidence-based fallback**

Khi ML confidence thấp (< 0.5 cho mọi class), engine **không** trừ điểm rule. Hiện schema v2 đã có `min_confidence`, nhưng default 0.7 — nên hạ xuống 0.6 hoặc 0.65 ở rule có FP cao.

**Ưu tiên 4: Multi-model ensemble**

- DistilBERT v7 (signature-aware) cho 9 class injection đã train
- Char-level CNN (anomaly) cho mọi text
- Score = trọng số ensemble

Quá phức tạp cho thesis nhưng là hướng production.

**Ưu tiên 5: Black-list / Threat intel feeds**

- IP reputation (Spamhaus, AbuseIPDB)
- Known malicious payloads (Emerging Threats)
- Update qua cron job, lưu vào `configs/rules/sets/`

---

## 6. Roadmap rút gọn

| Giai đoạn | Việc | Hiệu quả |
|---|---|---|
| **Đã xong (v7)** | DistilBERT 10-class (đã bao gồm ssrf, xxe, nosqli, log4shell, ssti) | Cover thêm A05/A06/A10 + NoSQLi/SSTI |
| **Tuần 1** | Mở rộng dataset cho khoảng trống còn lại (ldap/xpath injection, deserialization) | FN giảm cho các loại injection chưa train |
| **Tuần 2** | Thêm anomaly autoencoder, expose qua endpoint thứ 2 | Bắt được attack lạ / evasion-obfuscation |
| **Tuần 3** | Engine v2 mở rộng pattern type `ml_anomaly_gt` | Rule có thể dùng anomaly score |
| **Tuần 4+** | Threat intel feed integration | Block known-bad IPs/payloads |

---

## 7. Kết luận

ML 10-class (v7) **không phải là silver bullet**. Nó cover phần payload của nhiều nhóm OWASP (A01 phần, A03 phần lớn, A05 XXE, A06 Log4Shell, A10 SSRF) và rất tốt cho việc **giảm FP** trên các class đã biết — đạt accuracy 0.9968 và macro-F1 0.9959 trên tập test **cùng phân phối training (in-distribution, dữ liệu synthetic)**, không phải bảo chứng cho khả năng tổng quát hóa với traffic thật. Ngoài phạm vi đó:

1. Model **failed silently** (predict `normal` với confidence cao).
2. Trong tình huống xấu, model **chủ động làm yếu WAF** bằng cách trừ điểm rule signature.
3. **Rule signature là tuyến phòng thủ chính** cho các class ngoài training (LDAP/XPath injection, deserialization, IDOR/business-logic, brute force, evasion/obfuscation).
4. **Mở rộng training set + anomaly model** là path nâng cấp rõ ràng.

→ **Đề xuất cho thesis**: trình bày ML như "thành phần hỗ trợ giảm FP cho các class đã biết" thay vì "phát hiện tấn công đa năng". Defense in depth chính = rule signature (78 rules / 13 nhóm OWASP-aligned, schema v2) + behavior detector + decision engine score model.
