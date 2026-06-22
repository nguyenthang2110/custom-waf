# Đề cương chi tiết Đồ án Tốt nghiệp
## Xây dựng Hệ thống Tường lửa Ứng dụng Web (WAF) tích hợp Machine Learning

**Template:** Application (SOICT_DATN_Application_VIE_Template)
**Sinh viên:** Nguyễn Thắng

---

## TÓM TẮT NỘI DUNG

Đồ án xây dựng một hệ thống Tường lửa Ứng dụng Web (WAF) hiệu năng cao viết bằng Go,
kết hợp hai lớp phát hiện tấn công: (1) engine dựa trên luật với 78 quy tắc bao phủ 13
nhóm lỗ hổng OWASP Top 10, và (2) mô hình phân loại DistilBERT fine-tuned nhận dạng 10
loại tấn công, được kích hoạt trong "vùng xám" khi điểm anomaly nằm trong khoảng [3.0, 5.0).
Hệ thống cung cấp Dashboard giám sát thời gian thực, hệ thống xác thực JWT với RBAC ba
vai trò (admin / editor / viewer), trang quản lý tài khoản tự phục vụ và trang quản trị
người dùng dành cho admin, rate limiting theo thuật toán Token Bucket, và triển khai
hoàn chỉnh qua Docker.

---

## CHƯƠNG 1 — GIỚI THIỆU ĐỀ TÀI

### 1.1 Đặt vấn đề
- Tổng quan tình hình tấn công web hiện nay (OWASP Top 10, xu hướng 2023–2025)
- Hạn chế của WAF truyền thống chỉ dùng rule-based: false positive cao, rule cứng không
  thích nghi với biến thể tấn công mới (evasion, obfuscation)
- Khoảng trống trong thực tế: thiếu WAF mã nguồn mở hiệu năng cao + có tầng ML kiểm
  chứng cho "vùng xám"
- Nhu cầu giám sát trực quan và quản trị tập trung cho security team

### 1.2 Mục tiêu và phạm vi đề tài
**Mục tiêu:**
- Xây dựng WAF reverse-proxy hiệu năng cao (Go) có thể triển khai thực tế
- Rule engine với bộ luật chuẩn hóa 78 rules / 13 nhóm tấn công
- Tích hợp mô hình ML (DistilBERT) làm lớp kiểm chứng thứ hai trong vùng xám
- Dashboard quản trị và giám sát real-time
- Pipeline huấn luyện và đánh giá mô hình ML có thể tái lập

**Phạm vi:**
- Các loại tấn công: SQLi, XSS, CMDi, Path Traversal, SSRF, XXE, Log4Shell, SSTI,
  NoSQLi, RCE
- Triển khai trên máy chủ Linux (Docker), test trên DVWA / Juice Shop
- Không xử lý Layer 3/4 (DDoS volumetric), không thay thế NGFW

### 1.3 Định hướng giải pháp
- Kiến trúc hai lớp: Rule Engine (tốc độ) + ML Layer (độ chính xác vùng xám)
- Reverse proxy trong suốt, không yêu cầu thay đổi ứng dụng backend
- Cơ chế anomaly scoring thay vì block ngay theo rule đơn lẻ

### 1.4 Bố cục đồ án
*(Liệt kê 6 chương và nội dung tóm tắt mỗi chương)*

---

## CHƯƠNG 2 — KHẢO SÁT VÀ PHÂN TÍCH YÊU CẦU

### 2.1 Khảo sát hiện trạng

#### 2.1.1 Khảo sát nhu cầu người dùng
- Nhóm người dùng: Security Engineer, DevOps/SRE, Developer
- Nhu cầu: phát hiện tấn công chính xác, ít false positive, dễ vận hành, log rõ ràng
- Khảo sát công cụ pentesting phổ biến hiện nay để hiểu bề mặt tấn công cần bảo vệ

#### 2.1.2 Khảo sát các hệ thống WAF hiện có
| Hệ thống | Loại | Ưu điểm | Hạn chế |
|---|---|---|---|
| ModSecurity + OWASP CRS | OSS Rule-based | Chuẩn công nghiệp, phổ biến | Khó tune, nhiều FP, không có ML |
| Cloudflare WAF | Commercial cloud | Dễ dùng, ML tích hợp | Không on-premise, chi phí cao |
| AWS WAF | Commercial cloud | Tích hợp AWS | Phụ thuộc vendor, giới hạn rule |
| Shadow Daemon | OSS | Đơn giản | Ít maintained, không có dashboard |
| **Hệ thống đề xuất** | OSS on-premise | Go hiệu năng cao + ML vùng xám | Đang phát triển |

### 2.2 Tổng quan chức năng

#### 2.2.1 Biểu đồ ca sử dụng tổng quát
*(Hình vẽ — các actor: Attacker, End User, Admin, ML Service)*

#### 2.2.2 Ca sử dụng: Kiểm tra và lọc request HTTP
- Actor: Attacker / End User (không biết có WAF)
- Luồng chính: request → parser → normalizer → rule engine → scoring → quyết định
- Luồng thay thế: score vùng xám → gọi ML service → điều chỉnh score → quyết định

#### 2.2.3 Ca sử dụng: Quản lý luật (Rule Management)
- Tải luật mới qua API / giao diện web
- Bật/tắt từng rule, filter theo category/severity
- Xem thống kê hit count theo rule

#### 2.2.4 Ca sử dụng: Giám sát và xem log
- Real-time dashboard: request/s, block rate, top attacks
- Xem chi tiết log tấn công (IP, payload, rule match, ML verdict)
- Lọc log theo thời gian, loại tấn công, IP

#### 2.2.5 Ca sử dụng: Quản lý IP (Blacklist / Whitelist)
- Thêm/xóa IP khỏi blacklist/whitelist động
- Xem danh sách IP đang bị chặn do rate limiting

#### 2.2.6 Ca sử dụng: Cấu hình hệ thống
- Cấu hình backend target URL
- Bật/tắt require_auth, ngưỡng block/monitor
- Cấu hình ML service endpoint

#### 2.2.7 Ca sử dụng: Cảnh báo sự kiện bảo mật (Alert / Notification)
- Actor: Admin, Hệ thống notifier (background worker)
- Trigger: WAF phát hiện sự kiện có severity ≥ ngưỡng cấu hình (mặc định HIGH)
- Luồng chính:
  1. Decision layer phát sự kiện BLOCK → notifier.Send() (async, không block)
  2. Worker kiểm tra throttle (dedup theo IP + ruleID trong cửa sổ 5 phút)
  3. Fan-out đến các kênh đã bật: Slack, Email (SMTP), Webhook tùy chỉnh
  4. Ghi stats (sent_count / failed_count) cho từng destination
- Luồng thay thế: timeout 5s per channel → fail, không ảnh hưởng WAF processing
- Admin cũng có thể gửi test notification để xác nhận kênh đã cấu hình đúng

#### 2.2.8 Ca sử dụng: Xác thực và phân quyền (Auth)
- Đăng nhập, JWT lưu trong HttpOnly cookie + hỗ trợ Bearer header
- RBAC 3 vai trò:
  - **admin**: toàn quyền (quản lý user, cấu hình, rule, IP, notification)
  - **editor**: được phép thay đổi cấu hình WAF (rule, IP list, settings) nhưng không
    quản trị tài khoản người khác
  - **viewer**: chỉ đọc dashboard và log
- Không có đăng ký công khai: tài khoản chỉ được admin tạo qua `POST /waf-api/auth/users`
  (đóng lỗ leo thang đặc quyền). Tài khoản admin khởi tạo mặc định là `admin/admin`.

#### 2.2.9 Ca sử dụng: Quản lý tài khoản cá nhân (Account Settings)
- Actor: mọi user đã đăng nhập
- Chức năng:
  - Xem thông tin tài khoản (username, role — chỉ đọc)
  - Cập nhật email
  - Đổi mật khẩu (bắt buộc nhập mật khẩu cũ để chống takeover khi JWT bị lộ)
- Ràng buộc: mật khẩu mới ≥ 8 ký tự, hash bcrypt cost 10

#### 2.2.10 Ca sử dụng: Quản trị người dùng (Admin User Management)
- Actor: admin
- Chức năng CRUD: tạo user mới với role tùy chọn, sửa email/role, reset password,
  xóa user
- Ràng buộc bảo vệ:
  - **Last-admin protection**: không cho phép xóa hoặc demote admin cuối cùng
  - **Self-action protection**: admin không thể tự xóa hoặc tự demote chính mình
  - Mọi hành động ghi audit log (actor, target, action, timestamp)

### 2.3 Đặc tả chức năng

#### 2.3.1 Đặc tả: Kiểm tra request và đưa ra quyết định
- Input: HTTP request (method, path, query, headers, body)
- Processing: normalize → match rules → anomaly scoring → [ML confirm nếu vùng xám]
- Output: ALLOW / MONITOR / BLOCK + audit log entry
- Ngưỡng (config.yaml): monitor_threshold mặc định = 0 (mọi điểm dương → MONITOR), block ≥ 5.0

#### 2.3.2 Đặc tả: Xử lý anomaly scoring
- Mỗi rule match cộng điểm (anomaly_score × severity_multiplier)
- Vùng xám [3.0, 5.0): gọi ML service → nếu ML xác nhận tấn công: +delta, nếu ML
  xác nhận normal: −delta
- Quyết định cuối dựa trên tổng điểm sau điều chỉnh ML

#### 2.3.3 Đặc tả: Rate Limiting
- Thuật toán Token Bucket per IP
- Cấu hình rate và burst trong config.yaml
- Tự động thêm IP vi phạm vào danh sách tạm chặn

#### 2.3.4 Đặc tả: Cảnh báo sự kiện bảo mật
- **Kênh hỗ trợ**: Slack (Incoming Webhook), Email (SMTP), Generic Webhook (HTTP POST)
- **Cấu hình per-destination**: enabled flag, URL/host, template payload tùy chỉnh
- **Throttle**: dedup window mặc định 300s — cùng (channel, IP, ruleID) không gửi lặp
- **Severity filter**: bỏ qua sự kiện dưới MinSeverity (INFO < LOW < MEDIUM < HIGH < CRITICAL)
- **Async hoàn toàn**: `notifier.Send()` return ngay, worker goroutine xử lý nền
- **Test destination**: admin gọi API test → notifier gửi 1 sự kiện thử, trả về kết quả

#### 2.3.5 Đặc tả: Audit Logging
- Ghi log mỗi request bị flag (rule match, ML verdict, IP, timestamp, score)
- Lưu vào PostgreSQL, có thể query/filter qua API

### 2.4 Yêu cầu phi chức năng
- **Hiệu năng**: latency thêm vào < 5ms (P99) cho request bình thường; ML call ≤ 800ms timeout
- **Độ chính xác**: block rate ≥ 95% với OWASP payload chuẩn; false positive < 5% với traffic thường
- **Khả dụng**: fail-open (ML unavailable → không block traffic hợp lệ)
- **Bảo mật nội bộ**: JWT auth, bcrypt password, admin endpoint gated
- **Triển khai**: Docker Compose một lệnh, HTTPS/TLS

---

## CHƯƠNG 3 — CÔNG NGHỆ SỬ DỤNG

### 3.1 Go (Golang) — Nền tảng xây dựng WAF core

#### 3.1.1 Khái quát
- Compiled language, GC-managed, built-in concurrency (goroutines/channels)
- Standard library `net/http` đủ mạnh cho reverse proxy

#### 3.1.2 Vai trò trong hệ thống
- Toàn bộ WAF core: proxy, rule engine, API server, middleware stack
- Xử lý concurrent requests với goroutine pool

#### 3.1.3 Lý do lựa chọn
- Hiệu năng cao hơn Python/Node.js trong I/O-bound workload
- Binary deploy đơn giản, Docker image nhỏ
- So sánh: Go vs. Rust vs. Java cho WAF workload

### 3.2 Rule Engine và OWASP CRS — Cơ sở phát hiện dựa trên luật

#### 3.2.1 Khái quát cơ chế rule-based detection
- Anomaly scoring model (vs. immediate block model)
- Transform chain: URL_DECODE → LOWERCASE → COMPRESS_WHITESPACE
- Pattern types: REGEX và TOKEN (proximity match)

#### 3.2.2 Cấu trúc rule JSON
- Các trường: conditions, transforms, patterns, scoring, actions, exceptions
- Phase: REQUEST (hiện tại), có thể mở rộng sang RESPONSE

#### 3.2.3 Bộ luật 78 rules / 13 nhóm
*(Bảng liệt kê các nhóm: rce, sqli, xss, lfi, ssrf, info_leak, custom, scanner,
ato, nosqli, xxe, bot, dos)*

### 3.3 DistilBERT — Mô hình phân loại tấn công

#### 3.3.1 Khái quát kiến trúc Transformer và BERT
- Self-attention, positional encoding
- DistilBERT: chắt lọc từ BERT-base, 40% nhỏ hơn, 60% nhanh hơn, giữ 97% hiệu suất

#### 3.3.2 Fine-tuning cho bài toán phân loại HTTP request
- Task: sequence classification (10 lớp)
- Input: canonical text (full HTTP request được chuẩn hóa)
- Cách build canonical text: method + path + headers + body

#### 3.3.3 Lý do lựa chọn
- So sánh với: LSTM, CNN-text, BERT-base, RoBERTa
- Trade-off: độ chính xác vs. latency (DistilBERT phù hợp real-time WAF)

### 3.4 FastAPI + Python — ML Inference Service

#### 3.4.1 Khái quát
- ASGI framework, async, tự động sinh OpenAPI docs

#### 3.4.2 Vai trò
- Nhận POST /predict từ Go WAF, trả label + confidence
- Tách biệt runtime Python/PyTorch khỏi Go binary

### 3.5 PostgreSQL — Lưu trữ logs, users, cấu hình

#### 3.5.1 Khái quát
#### 3.5.2 Vai trò: audit log, user accounts, rule metadata, IP lists
#### 3.5.3 Schema chính: bảng users, audit_logs, ip_lists

### 3.6 JWT và Bcrypt — Xác thực và bảo mật

#### 3.6.1 JWT: stateless auth, dual-mode (HttpOnly cookie + Bearer header)
#### 3.6.2 Bcrypt: password hashing với cost factor 10
#### 3.6.3 RBAC 3 vai trò: admin / editor / viewer
- Database CHECK constraint trên `users.role` đảm bảo chỉ nhận 3 giá trị hợp lệ
- Middleware `requireAdmin` gate các endpoint quản trị user
- Middleware `requireAuthN` chỉ yêu cầu đã đăng nhập (cho `/me`, `/me/password`)

### 3.7 Token Bucket — Thuật toán Rate Limiting

#### 3.7.1 Khái quát Token Bucket vs. Leaky Bucket vs. Sliding Window
#### 3.7.2 Triển khai per-IP với in-memory store
#### 3.7.3 Tích hợp vào middleware stack

### 3.8 Docker & Docker Compose — Triển khai và sandbox

#### 3.8.1 Containerization WAF, PostgreSQL, ML Service
#### 3.8.2 Docker Compose one-command deployment
#### 3.8.3 Lý do lựa chọn (reproducibility, isolation)

---

## CHƯƠNG 4 — KẾT QUẢ THỰC NGHIỆM

### 4.1 Kiến trúc tổng quan hệ thống

#### 4.1.1 Sơ đồ kiến trúc tổng thể
```
Client → [WAF Proxy :8080/:8443]
              │
              ├── Middleware Stack
              │     ├── Auth Middleware (JWT)
              │     ├── WAF Middleware (Rule Engine + ML Hook)
              │     └── Logging Middleware
              │
              ├── Rule Engine ──→ [ML Service :8000] (gray zone only)
              │
              ├── Decision Layer (ALLOW/MONITOR/BLOCK)
              │
              └── [Backend App] (Juice Shop, etc.)

Admin → [Dashboard :8443/web] → [WAF API /waf-api/*] → PostgreSQL
```

#### 4.1.2 Luồng xử lý request
1. Nhận request → parser (method, path, query, headers, body)
2. Normalizer: URL decode, lowercase, whitespace compression
3. IP check: blacklist → block ngay; whitelist → pass
4. Rate limit check → block nếu vượt
5. Rule engine: duyệt 78 rules → tính anomaly score
6. Nếu score ∈ [3.0, 5.0): gọi ML service → điều chỉnh score
7. Decision: score ≥ 5 → BLOCK; > 0 → MONITOR; else (score = 0) ALLOW
8. Forward request đến backend (nếu ALLOW/MONITOR)
9. Ghi audit log

#### 4.1.3 Các thành phần chính và tương tác
*(Bảng: package Go, chức năng, phụ thuộc)*

### 4.2 Thiết kế và triển khai Rule Engine

#### 4.2.1 Cấu trúc dữ liệu Rule
- `Rule` struct: metadata, conditions, transforms, patterns, scoring, actions
- `ParsedRequest` struct: các field đã normalize

#### 4.2.2 Transform chain
- Danh sách transform: URL_DECODE, LOWERCASE, COMPRESS_WHITESPACE, BASE64_DECODE, HTML_ENTITY_DECODE
- Ý nghĩa: chống evasion qua encoding

#### 4.2.3 Pattern matching
- REGEX pattern: dùng Go `regexp`, precompile tại load
- TOKEN pattern: proximity match, order-sensitive

#### 4.2.4 Anomaly scoring và decision
- Tính tổng score từ tất cả rule match
- `blockThreshold`, `monitorThreshold` cấu hình động

#### 4.2.5 Bộ luật 78 rules
*(Bảng chi tiết: ID, category, severity, description, pattern chính)*

### 4.3 Thiết kế và triển khai ML Layer

#### 4.3.1 Kiến trúc ML Inference Service
- FastAPI app, load DistilBERT từ Hugging Face format
- Endpoint `/predict` và `/predict_batch`
- Labels: normal, sqli, xss, cmdi, path_traversal, ssrf, xxe, log4shell, ssti, nosqli

#### 4.3.2 Cơ chế tích hợp vào Rule Engine (ml_hook.go)
- Interface `MLPredictor` → tách biệt engine và ML client
- `runMLConfirm`: gọi ML, check confidence threshold, tính delta score
- Timeout 800ms, fail-open (ML timeout → không ảnh hưởng quyết định)

#### 4.3.3 Canonical text preprocessing
- `BuildCanonicalText` (Go) và `canonical_compose` (Python) phải byte-identical
- Format: `METHOD PATH\nHost: ...\nUser-Agent: ...\n\nBODY`
- URL-decode một lớp, giới hạn header value 256 chars

#### 4.3.4 Pipeline huấn luyện và phiên bản model
- Dataset: 10 nhóm tấn công + normal
- Fine-tune từ DistilBERT-base-uncased
- Versioning: v5 (baseline) → v6 (fail report) → v7 (model production, 10 lớp)
- Augmentation strategy cho các lớp yếu (cmdi, log4shell, ssti)

### 4.4 Thiết kế cơ sở dữ liệu

#### 4.4.1 Sơ đồ ERD
*(Bảng: users, audit_logs, ip_lists, config)*

#### 4.4.2 Bảng `audit_logs`
- id, timestamp, ip, method, path, score, decision, rule_ids, ml_label, ml_confidence

#### 4.4.3 Bảng `users`
- Cột: id, username, email, password_hash, role, created_at, updated_at
- CHECK constraint: `role IN ('admin','editor','viewer')`
- UNIQUE constraint trên `username` và `email` (chống trùng tài khoản)

### 4.5 Giao diện Dashboard

#### 4.5.1 Tổng quan giao diện
- Single-page app (HTML/CSS/JS thuần, không framework)
- Responsive, dark-mode friendly

#### 4.5.2 Các màn hình chính
- **Login** (`login.html`): form đăng nhập, JWT lưu HttpOnly cookie
- **Dashboard** (`index.html`): real-time counters (requests/s, block rate, top attack types)
- **Logs**: bảng audit log có filter (IP, loại tấn công, thời gian)
- **Rules**: danh sách 78 rules, filter theo category/severity, bật/tắt từng rule
- **IP Management**: blacklist/whitelist CRUD
- **System Settings**: cấu hình backend URL, ngưỡng, ML service URL
- **Notifications**: cấu hình kênh alert (Slack webhook URL, SMTP, generic webhook),
  bật/tắt từng destination, gửi test notification, xem stats (sent/failed count)
- **Account Settings** (`settings.html`): trang cá nhân — đổi email, đổi mật khẩu
  (xác nhận mật khẩu cũ), hiển thị username + role chỉ đọc
- **User Management** (`users.html`, chỉ admin): danh sách tài khoản, tạo user mới,
  sửa email/role, reset password, xóa user (có bảo vệ self-action và last-admin)

#### 4.5.3 Hệ thống Theme đồng nhất
- CSS custom properties với `[data-theme="dark"]` / `[data-theme="light"]`
- Pre-paint bootstrap script đọc `localStorage.waf_theme` trước khi render → tránh FOUC
- Nút toggle theme có mặt ở mọi trang (login, dashboard, settings, users)
- Tailwind CSS qua CDN + font Inter, glass-card layout thống nhất

### 4.6 Kiểm thử

#### 4.6.1 Chiến lược kiểm thử
- Unit test: rule engine logic, transform chain, token matching
- Integration test: WAF middleware với backend thật (Juice Shop)
- Penetration test: 42 payload OWASP chuẩn (SQLi, XSS, RCE, Path Traversal, ...)
- Load test: Apache Bench 1000 req, 100 concurrent

#### 4.6.2 Kết quả kiểm thử rule engine (42 attack payloads OWASP)
| Metric | Trước fix | Sau fix |
|---|---|---|
| Rules load vào engine | 17/78 | **78/78** |
| Block rate (42 OWASP attacks) | 88.1% (37/42) | **97.6% (41/42)** |
| Latency precision | 0 ms (làm tròn) | **0.13 ms (sub-ms)** |
| Bypass: SQLi ORDER BY, RCE PHP, Shellshock | 5 lọt | **0 lọt** |

#### 4.6.3 Kết quả kiểm thử ML model (v7, 10 lớp, in-distribution)
*(Bảng per-class P/R/F1, confusion matrix)*

- In-distribution (trên phân bố huấn luyện tổng hợp): accuracy 0.9968, macro-F1 0.9959
- Lưu ý: đây là metrics in-distribution, chưa phản ánh tổng quát hóa trên traffic thực
- Đối chiếu với v5/v6 baseline (97 mẫu OOD): JSON-body bias, shell URL paths,
  log4shell obfuscation là các failure pattern đã được augmentation khắc phục ở v7

#### 4.6.4 Kết quả kiểm thử rate limiting
- Block rate với 1500 burst: 65.6% (984/1500) sau fix

#### 4.6.5 Kiểm thử bảo mật nội bộ (auth/authorization)
- **Endpoint matrix**:
  - Public: `/login`, `/logout`
  - Auth-only (mọi role): `/me`, `/me/password`
  - Admin-only: `/users`, `/users/{id}`, `/users/{id}/password`, các endpoint cấu hình WAF
- **Test case chính**:
  - Gọi không có token → 401
  - Gọi với viewer token vào admin endpoint → 403
  - Gọi với admin token → 200
- **Test không có đăng ký công khai**: không tồn tại endpoint `/register` hay trang
  `register.html`; tài khoản chỉ tạo được qua `POST /waf-api/auth/users` (admin-gated)
  → bịt hoàn toàn bề mặt tự tạo tài khoản / leo thang đặc quyền
- **Test invariant bảo vệ**:
  - Xóa admin cuối cùng → 400 với message "cannot delete the last admin"
  - Demote admin cuối cùng từ admin → editor/viewer → 400
  - Admin tự xóa chính mình → 400 với message "cannot delete your own account"
- **Test đổi password**: nhập sai mật khẩu cũ → 401, đúng → 200 + audit log entry

### 4.7 Triển khai

#### 4.7.1 Yêu cầu hệ thống
- Docker + Docker Compose
- 2GB RAM (thêm ~1GB cho ML service với model v7)

#### 4.7.2 Hướng dẫn triển khai (Docker Compose)
```bash
./scripts/setup_db.sh      # PostgreSQL + migrations
./scripts/generate_certs.sh  # self-signed TLS
make build && make run       # WAF tại :8443
docker compose up ml -d      # ML service tại :8000
```

#### 4.7.3 Cấu trúc file triển khai
*(Giải thích docker-compose.db.yml, Makefile targets)*

---

## CHƯƠNG 5 — CÁC GIẢI PHÁP VÀ ĐÓNG GÓP NỔI BẬT

### 5.1 Thiết kế cơ chế Anomaly Scoring hai lớp (Rule + ML)

#### 5.1.1 Đặt vấn đề
- Rule-based đơn thuần: nhiều false positive hoặc phải hạ ngưỡng → bỏ sót
- ML đơn thuần: latency cao, không giải thích được, không có rule logic
- "Vùng xám" [3.0, 5.0): những request mơ hồ mà rule không đủ tự tin

#### 5.1.2 Giải pháp đề xuất
- Layer 1 (rule engine): nhanh, giải thích được, xử lý rõ ràng (score < 3 hoặc ≥ 5)
- Layer 2 (ML): chỉ kích hoạt khi score ∈ [3.0, 5.0) → tiết kiệm latency
- Delta adjustment: ML confirm tấn công → +score; ML xác nhận normal → −score
- Fail-open: ML timeout/unavailable → giữ nguyên rule score

#### 5.1.3 Kết quả
- Giảm false positive trong vùng xám
- Bắt được biến thể tấn công mà rule regex không cover
- So sánh: với vs. không có ML layer (precision/recall trên test set)

### 5.2 Thiết kế bộ luật chuẩn hóa 78 rules với Transform Chain chống Evasion

#### 5.2.1 Đặt vấn đề
- Attacker bypass rule regex bằng URL encoding, double encoding, case variation,
  whitespace padding
- OWASP CRS có transform nhưng config phức tạp, khó maintain

#### 5.2.2 Giải pháp đề xuất
- Transform chain per-rule: áp dụng theo thứ tự (URL_DECODE → LOWERCASE → COMPRESS_WHITESPACE)
- TOKEN pattern với proximity: `union...select` trong vòng 20 ký tự, sequential
- Exceptions per-rule: bỏ qua `/health`, `/metrics` để không FP monitoring

#### 5.2.3 Kết quả
- 5 bypass payload đã vá (SQLi ORDER BY, RCE PHP, reverse-shell, Shellshock, OR 1=1)
- Block rate tăng từ 88.1% → 97.6% với 42 OWASP payload

### 5.3 Pipeline huấn luyện ML có kiểm soát chất lượng (Hard Gate)

#### 5.3.1 Đặt vấn đề
- Fine-tuning ML mà không có tiêu chí rõ ràng → model kém bị deploy lên production
- Các lớp tấn công hiếm (log4shell obfuscation, SSTI) dễ bị mô hình bỏ qua

#### 5.3.2 Giải pháp đề xuất
- Hard gate: overall accuracy ≥ 0.92, cmdi F1 ≥ 0.85, log4shell F1 ≥ 0.90
- Model không pass gate → không ship (xem báo cáo v6 fail)
- Augmentation chiến lược: phân tích misclassification → sinh thêm sample đúng dạng bị lỗi
- Canonical text đồng bộ Go↔Python (7 fixture test cases)

#### 5.3.3 Kết quả (v6 fail → v7 pass)
- v6 accuracy: 0.8866 (chưa đạt ≥ 0.92), cmdi F1: 0.818, log4shell F1: 0.857 → bị gate
  chặn, không ship
- Root-cause 3 failure pattern: JSON-body bias, shell URL paths, log4shell obfuscation
- Sau augmentation có mục tiêu, model v7 (10 lớp) vượt gate: accuracy 0.9968,
  macro-F1 0.9959 (in-distribution) → đây là model production hiện hành

### 5.4 Thiết kế interface MLPredictor tách biệt Engine và ML Client

#### 5.4.1 Đặt vấn đề
- Import cycle: `engine` import `ml` import `engine`
- Khó test engine mà không cần ML service chạy thật

#### 5.4.2 Giải pháp đề xuất
- Interface `MLPredictor` trong `engine` package (chỉ cần `Predict` + `Enabled`)
- `MLClientAdapter` trong `engine` nhận raw function → adapter pattern
- `internal/ml.Client` satisfy interface từ bên ngoài
- Unit test engine dùng mock MLPredictor

#### 5.4.3 Lợi ích
- Test isolation hoàn toàn
- Dễ swap ML backend (HTTP service → local model → gRPC)

### 5.5 Củng cố lớp Auth: bịt lỗ leo thang đặc quyền và thêm Invariant bảo vệ

#### 5.5.1 Đặt vấn đề
- Đăng ký công khai (self-service sign-up) là bề mặt tấn công tạo tài khoản / leo thang
  đặc quyền (ai cũng POST được `{"role":"admin"}` nếu endpoint chấp nhận trường `role`)
- Hệ thống cần cơ chế đổi mật khẩu sau đăng nhập → không để user dùng mãi mật khẩu mặc
  định `admin`
- Thiếu trang quản trị tài khoản → không thể thu hồi/đổi role mà không truy cập DB
- Có nguy cơ "khóa trái" (lockout) khi admin cuối cùng bị xóa hoặc tự demote

#### 5.5.2 Giải pháp đề xuất
- **Không có đăng ký công khai**: hệ thống không có endpoint `/register`, handler
  `handleRegister` hay trang `register.html`. Tài khoản chỉ được admin tạo qua
  `POST /waf-api/auth/users` (admin-gated); role chỉ thay đổi qua endpoint admin
  (`PUT /users/{id}`) → bịt hoàn toàn bề mặt tự tạo tài khoản / leo thang đặc quyền
- **Self-service password change**: endpoint `PUT /me/password` yêu cầu mật khẩu cũ
  trước khi cho đổi (chống takeover khi JWT bị đánh cắp)
- **Trang quản trị user (admin only)**: tạo / sửa / reset password / xóa user, với
  audit logging mọi hành động
- **Invariant chống lockout**:
  - `CountByRole("admin")` được gọi trước khi delete hoặc demote bất kỳ admin nào
  - Self-delete và self-demote bị từ chối tại tầng handler
  - UI cũng disable nút "Delete" cho chính account đang đăng nhập (defense-in-depth)
- **Bảo mật cookie**: JWT lưu trong HttpOnly cookie để chống XSS exfiltration; vẫn
  hỗ trợ Bearer header cho API client

#### 5.5.3 Kết quả
- Không tồn tại endpoint `/register` hay trang `register.html` → không có đường tự tạo
  tài khoản; tài khoản mới chỉ sinh ra qua `POST /waf-api/auth/users` (admin-gated)
- Test invariant: 4 case (last-admin delete/demote, self-delete/demote) đều trả 400
- 100% admin endpoint mới được gate qua `requireAdmin` middleware
- Mật khẩu mặc định `admin` giờ có thể đổi qua UI ngay sau lần đăng nhập đầu

---

## CHƯƠNG 6 — KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN

### 6.1 Kết luận

**Kết quả đạt được:**
- Hệ thống WAF reverse-proxy viết bằng Go với rule engine 78 rules, block rate 97.6% với
  42 OWASP payload chuẩn
- Tích hợp thành công ML layer (DistilBERT 10 lớp, model v7) với cơ chế gray-zone
  activation; metrics in-distribution: accuracy 0.9968, macro-F1 0.9959
- Dashboard quản trị hoàn chỉnh: real-time monitoring, log management, rule/IP management,
  account settings và admin user management — toàn bộ trang dùng chung theme (dark/light
  toggle, pre-paint script chống FOUC)
- Auth system bảo mật: JWT HttpOnly cookie, bcrypt cost 10, RBAC 3 vai trò
  (admin/editor/viewer), không có đăng ký công khai (tài khoản chỉ do admin tạo),
  invariant chống last-admin lockout, audit logging mọi thao tác user-management
- Pipeline huấn luyện ML có kiểm soát chất lượng (hard gate, augmentation)
- Triển khai hoàn chỉnh qua Docker Compose

**Đánh giá so với mục tiêu ban đầu:**
*(Bảng đối chiếu mục tiêu ↔ kết quả đạt được)*

**Hạn chế:**
- Metrics của model v7 (accuracy 0.9968, macro-F1 0.9959) là in-distribution trên phân
  bố huấn luyện tổng hợp, chưa phản ánh khả năng tổng quát hóa trên traffic thực
- Model v7 chưa bao phủ một số loại tấn công: LDAP/XPath injection, insecure
  deserialization, business-logic/IDOR, evasion/obfuscation nâng cao, tấn công
  hành vi/xác thực (behavioral/auth)
- Chưa test với traffic production thực tế (chỉ lab/Juice Shop)
- Rate limiting chỉ đạt 65.6% với burst 1500 (cần tune thêm)

### 6.2 Hướng phát triển

#### 6.2.1 Ngắn hạn
- Đánh giá model v7 trên traffic thực (out-of-distribution) thay vì chỉ phân bố tổng hợp
- Mở rộng phủ các loại tấn công còn thiếu: LDAP/XPath injection, insecure deserialization
- Cải thiện rate limiting: Sliding Window Counter, Redis-backed distributed
- Thêm RESPONSE phase inspection (phát hiện data leak, error messages)

#### 6.2.2 Trung hạn
- Plugin architecture: load rule engine custom từ Lua/WASM
- Active learning: dùng false positive/negative được admin label lại để fine-tune tiếp
- Clustering mode: shared state cho multi-instance deployment (Redis)

#### 6.2.3 Dài hạn
- Tích hợp threat intelligence feed (IP reputation, malware URLs)
- Zero-day detection bằng anomaly detection (unsupervised) song song với supervised model
- Compliance reporting: PCI-DSS, GDPR log retention

---

## PHỤ LỤC

### Phụ lục A — Cấu trúc thư mục dự án
*(Tree đầy đủ với giải thích từng package)*

### Phụ lục B — Danh sách 78 Rules đầy đủ
*(Bảng: ID, category, severity, pattern chính, anomaly score)*

### Phụ lục C — API Reference
*(Danh sách endpoint WAF API: method, path, auth required, mô tả)*

**Nhóm Auth & Account (mới bổ sung):**
| Method | Path | Auth | Mô tả |
|---|---|---|---|
| POST | `/waf-api/auth/login` | public | Đăng nhập, set HttpOnly cookie |
| POST | `/waf-api/auth/logout` | any | Xóa cookie |
| GET | `/waf-api/auth/me` | any | Thông tin user hiện tại |
| PUT | `/waf-api/auth/me` | any | Cập nhật email của chính mình |
| PUT | `/waf-api/auth/me/password` | any | Đổi mật khẩu (cần old_password) |
| GET | `/waf-api/auth/users` | admin | List user |
| POST | `/waf-api/auth/users` | admin | Tạo user với role tùy chọn |
| GET | `/waf-api/auth/users/{id}` | admin | Chi tiết user |
| PUT | `/waf-api/auth/users/{id}` | admin | Update email/role (chặn last-admin) |
| DELETE | `/waf-api/auth/users/{id}` | admin | Xóa user (chặn last-admin + self) |
| PUT | `/waf-api/auth/users/{id}/password` | admin | Reset password (không cần old) |

### Phụ lục D — Hướng dẫn cài đặt và chạy thử
*(Step-by-step cho người mới)*

---

*Tổng số chương nội dung: 6 | Ước tính số trang: 80–100 trang*
