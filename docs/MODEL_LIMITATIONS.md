# Bất lợi của ML model 4-class hiện tại

Tài liệu này phân tích **giới hạn** của ML classifier (DistilBERT, 5-class: `normal | sqli | xss | cmdi | path_traversal`) trong project và **chuyện gì xảy ra khi gặp attack ngoài 4 class**.

---

## 1. Mô hình hiện tại — recap nhanh

- **Backend**: FastAPI (`ml-service/`) + DistilBERT fine-tuned trên dataset gồm 5 lớp:
  - `normal` (request bình thường)
  - `sqli`
  - `xss`
  - `cmdi` (command injection)
  - `path_traversal`
- **Inference**: model trả `(label, confidence)` cho 1 chuỗi text (body / args / uri…).
- **Vai trò trong WAF**: chạy "gray-zone consult" — khi rule score lửng (3 ≤ score < 7), gọi ML để cộng/trừ điểm; ngoài ra rule v2 có thể bật `ml_confirm` để gọi ML xác nhận signature match.

→ Model **chỉ phân biệt được 4 loại attack đã train**.

---

## 2. Vấn đề: 4 class không đủ phủ OWASP Top 10

OWASP Top 10 (2021) gồm 10 nhóm rủi ro. Model 4-class chỉ trực tiếp cover **3** trong số đó:

| OWASP rank | Tên | 4-class model bắt được? |
|---|---|---|
| A01 | Broken Access Control (IDOR, path traversal, file access) | ✓ Path traversal — phần |
| A02 | Cryptographic Failures | ✗ Không phải payload-pattern, model không có dữ liệu |
| A03 | Injection (SQLi, XSS, command injection, NoSQLi, LDAP, XPath, SSTI, ORM) | ✓ chỉ SQLi/XSS/cmdi — không cover NoSQLi, SSTI, LDAP, XPath |
| A04 | Insecure Design | ✗ Logic-level, không phải payload |
| A05 | Security Misconfiguration (XXE, default creds, verbose errors) | ✗ XXE không nằm trong 4 class |
| A06 | Vulnerable Components (Log4Shell, Spring4Shell) | ✗ Bypass cả 4 class (payload `${jndi:...}` lạ) |
| A07 | Identification & Authentication Failures (brute force, credential stuffing) | ✗ Behavioral, không phải single-request payload |
| A08 | Software/Data Integrity Failures (insecure deserialization) | ✗ Payload base64-ish lạ, không train |
| A09 | Logging & Monitoring | ✗ — |
| A10 | SSRF | ✗ Không train |

→ **Chỉ 2-3 trên 10 nhóm** OWASP được model trực tiếp cover. 7 nhóm còn lại **phải dựa hoàn toàn vào rule signature**.

---

## 3. Chuyện gì xảy ra khi gặp attack ngoài 4 class

### 3.1. Hiện trạng (failure modes)

**Kịch bản 1: Log4Shell `${jndi:ldap://...}`**
- Model thấy chuỗi này → train data không có → **classify nhầm thành `normal`** với confidence cao (thường > 0.9).
- Nếu rule `WAF-035-RCE-LOG4SHELL` không match (vd attacker obfuscate `${${::-j}${::-n}${::-d}${::-i}:...}`) → score = 0 → ALLOW.
- ML gray-zone không kích hoạt (score = 0, dưới `MinScore` 3) → ML không được gọi.
- **Kết quả**: payload đi qua WAF → backend bị tấn công.

**Kịch bản 2: SSRF `http://169.254.169.254/latest/meta-data/`**
- Rule `WAF-041-SSRF-CLOUD-METADATA` bắt được (signature đặc trưng).
- Nhưng nếu attacker dùng dạng obfuscate (`http://[::ffff:169.254.169.254]`, `http://2852039166/`, DNS rebinding…) → có thể bypass rule.
- ML thấy URL "lạ" → classify thành `normal` (vì không phải SQLi/XSS/cmdi/path).
- **Kết quả**: defense in depth chỉ còn rule.

**Kịch bản 3: NoSQL injection `{"$ne": null, "$where": "this.password.length > 0"}`**
- Rule `WAF-060-NOSQLI-MONGO-OPERATORS` match qua `$where`/`$ne` regex.
- ML thấy JSON object → có thể classify `normal` (training data có nhiều JSON) hoặc nhầm sang `sqli` (vì có chữ "where").
- **Hệ quả**: nếu ML nói `normal` confidence cao, `ml_confirm.on_normal_subtract` trừ điểm rule → request có thể được ALLOW dù đã match rule.

**Kịch bản 4: XXE / XML bombs / SSTI / deserialization**
- Cả 4 đều **không có trong training set** → ML hoàn toàn không hiểu.
- Output: `normal` với confidence ~0.95.
- → Nếu rule v1 yếu, model **tích cực gây hại** (trừ điểm khi nó nên cộng).

### 3.2. Tóm tắt 2 loại failure

| Failure | Hậu quả | Mức nghiêm trọng |
|---|---|---|
| **False negative** — ML nói `normal` cho attack thật | Bypass khi rule yếu / không có | Cao — attack thành công |
| **ML "hại defense in depth"** — ML trừ điểm hợp pháp khỏi signature match | Rule signature đúng nhưng bị ghi đè | Cao — paradox: model làm WAF yếu đi |

---

## 4. Tại sao ML 4-class **vẫn có giá trị** dù hạn chế

1. **Tăng precision cho 3 class chính**: SQLi và XSS là 60-80% traffic attack thực tế trên web app phổ thông. Cover tốt → giảm FP rule signature đáng kể.
2. **Confidence-aware**: rule v2 `ml_confirm.min_confidence` giúp **bỏ qua ML khi nó không tự tin** — phần nào hạn chế failure mode #2.
3. **Train được thêm**: dataset có thể mở rộng → 5-class hôm nay, 8-10 class tương lai.
4. **Không phải single point of defense**: rule signature + behavior detector + score model = defense in depth. ML chỉ là 1 lớp.

---

## 5. Cách giảm thiểu (mitigation đã có / nên thêm)

### 5.1. Đã có trong project hiện tại

| Cơ chế | Tác dụng |
|---|---|
| **Rule signature 45 rules** (bộ mới) cover SSRF, XXE, NoSQLi, SSTI, log4shell, sensitive paths | Bù trừ ML không biết |
| **`ml_confirm.min_confidence: 0.7-0.8`** | ML không đủ tự tin → bỏ qua, không trừ điểm rule |
| **`action.block: true` cho CVE virtual patch** | Skip score model + ML, block dứt khoát |
| **Behavior detector** | Bắt brute force / scanner — pattern-blind, không cần ML |

### 5.2. Nên thêm (xếp theo ưu tiên)

**Ưu tiên 1: Mở rộng training set**

Thêm class mới cho ML:
- `ssrf` — payload URL nội bộ, cloud metadata
- `xxe` — XML với DOCTYPE/ENTITY ngoài
- `nosqli` — Mongo operators, JSON `$where`
- `ssti` — `{{...}}`, `${T(...)}`, `__class__`
- `log4j` — `${jndi:...}`

Dataset: scrape từ PortSwigger labs, HackTricks, OWASP CRS test corpus.

**Ưu tiên 2: Anomaly-detection model song song**

Train 1 model thứ 2 (autoencoder hoặc isolation forest) trên **chỉ traffic bình thường**:
- Input: feature vector từ request (length, entropy, header count, special chars ratio, …)
- Output: anomaly score (0..1)
- Rule v2 mới dùng anomaly score như input: `inspect: [{"source":"ml_anomaly"}]`, `match: [{"type":"gt","value":0.8}]`

Lợi: bắt được **mọi attack lạ** mà không cần train từng class.

**Ưu tiên 3: Confidence-based fallback**

Khi ML confidence thấp (< 0.5 cho mọi class), engine **không** trừ điểm rule. Hiện schema v2 đã có `min_confidence`, nhưng default 0.7 — nên hạ xuống 0.6 hoặc 0.65 ở rule có FP cao.

**Ưu tiên 4: Multi-model ensemble**

- DistilBERT (signature-aware) cho SQLi/XSS/cmdi/path
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
| **Tuần 1** | Mở rộng dataset thêm 4 class (ssrf, xxe, nosqli, log4j) | Cover thêm 4/10 OWASP |
| **Tuần 2** | Re-train DistilBERT 9-class | FN giảm cho các class mới |
| **Tuần 3** | Thêm anomaly autoencoder, expose qua endpoint thứ 2 | Bắt được attack lạ |
| **Tuần 4** | Engine v2 mở rộng pattern type `ml_anomaly_gt` | Rule có thể dùng anomaly score |
| **Tuần 5+** | Threat intel feed integration | Block known-bad IPs/payloads |

---

## 7. Kết luận

ML 4-class **không phải là silver bullet**. Nó tốt cho **3/10 OWASP** và rất tốt cho việc **giảm FP** trên các class đã biết. Ngoài phạm vi đó:

1. Model **failed silently** (predict `normal` với confidence cao).
2. Trong tình huống xấu, model **chủ động làm yếu WAF** bằng cách trừ điểm rule signature.
3. **Rule signature là tuyến phòng thủ chính** cho các class ngoài training.
4. **Mở rộng training set + anomaly model** là path nâng cấp rõ ràng.

→ **Đề xuất cho thesis**: trình bày ML như "thành phần hỗ trợ giảm FP cho 3 class chính" thay vì "phát hiện tấn công đa năng". Defense in depth chính = rule v2 mới (45 rules cover OWASP Top 10 rộng hơn 36 rule v1) + behavior detector + decision engine score model.
