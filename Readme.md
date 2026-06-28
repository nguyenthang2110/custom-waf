# Web Application Firewall (WAF) Project

🚀 **High-Performance WAF built with Go (Golang)**

Hệ thống WAF hiệu năng cao được xây dựng từ đầu bằng ngôn ngữ Go, có khả năng phát hiện và ngăn chặn các cuộc tấn công web phổ biến (OWASP Top 10), đồng thời cung cấp giao diện Dashboard giám sát trực quan và hệ thống quản lý người dùng bảo mật.

---

## 🌟 Tính Năng Chính (Key Features)

### 🛡️ Core Protection Engine
*   **Rule-based Detection**: Hệ thống luật (Ruleset) mạnh mẽ với 78 rules bao phủ 13 nhóm lỗ hổng (theo OWASP):
    *   SQL Injection (SQLi)
    *   Cross-Site Scripting (XSS)
    *   Remote Code Execution (RCE)
    *   Path Traversal / LFI
    *   Server-Side Request Forgery (SSRF)
    *   XML External Entity (XXE)
    *   NoSQL Injection
    *   Log4j & Shellshock
    *   Scanner Detection & Behavior Analysis
*   **Rate Limiting**: Thuật toán Token Bucket giúp chống DDoS và Brute Force.
*   **IP Management**: Quản lý Blacklist/Whitelist động.

### 🔐 Bảo Mật & Xác Thực (Authentication)
*   **Secure Auth System**: Đăng nhập dựa trên **PostgreSQL**; tài khoản do admin tạo (không có đăng ký công khai).
*   **JWT Authentication**: Cơ chế xác thực không trạng thái (Stateless), bảo mật cao.
*   **Password Hashing**: Mật khẩu được mã hóa an toàn với **Bcrypt**.
*   **Role-based Access Control**: Phân quyền 3 vai trò **admin / editor / viewer**.

### 📊 Dashboard & Monitoring
*   **Real-time Dashboard**: Giám sát lưu lượng truy cập và các request bị chặn theo thời gian thực.
*   **Traffic Analysis**: Biểu đồ thống kê trực quan.
*   **Log Management**: Xem và lọc nhật ký tấn công chi tiết.
*   **System Configuration**: Cấu hình luật và hệ thống ngay trên giao diện web.

### 🚀 Performance & Infrastructure
*   **High Performance**: Viết bằng Go (Golang) cho tốc độ xử lý cực nhanh và khả năng chịu tải lớn (Concurrency).
*   **Dockerized**: Dễ dàng triển khai với Docker và Docker Compose.
*   **TLS tách lớp**: WAF chạy HTTP thuần; TLS do lớp phía trước (Cloudflare / nginx / Caddy) terminate — gọn nhẹ, không phải quản lý chứng chỉ trong WAF.

---

## 📦 Cấu Trúc Dự Án

```
waf-project/
├── cmd/waf/                # Điểm khởi chạy ứng dụng (Main entry point)
├── configs/                # File cấu hình (config.yaml) và bộ luật (rules/)
├── internal/
│   ├── api/                # Xử lý các API endpoints (/waf-api/*)
│   ├── auth/               # Logic xác thực và JWT
│   ├── database/           # Kết nối và thao tác PostgreSQL
│   ├── engine/             # Lõi xử lý WAF (Inspection, Matching)
│   ├── middleware/         # Các lớp Middleware (Auth, Logging, WAF)
│   └── models/             # Định nghĩa cấu trúc dữ liệu (User, Log)
├── migrations/             # Scripts khởi tạo database
├── web/                    # Giao diện Frontend (HTML/CSS/JS)
├── scripts/                # Scripts tiện ích (Setup DB, Test)
└── deployments/            # Cấu hình Docker
```

---

## 🛠️ Hướng Dẫn Triển Khai (Deployment)

### Yêu cầu tiên quyết
*   **Go** 1.21 trở lên
*   **Docker** & **Docker Compose** (chạy PostgreSQL)
*   **Python** 3.10–3.12 (chạy ML service — PyTorch chưa hỗ trợ 3.13/3.14)
*   **Make** (Linux/macOS, hoặc WSL2/Git Bash trên Windows)
*   **Model DistilBERT v8** đặt tại `model_v8/final_model_v8/` (không kèm trong repo — xem Bước 1)

### Bước 1: Tải model
Model không commit trong git. Tải bản đóng gói từ GitHub Release rồi giải nén:
```bash
gh release download model-v8 -p '*.zip'        # hoặc tải tay từ trang Releases
unzip 'model_v8-*.zip' -d .                     # tạo ra model_v8/final_model_v8/
```
Trang tải: <https://github.com/nguyenthang2110/custom-waf/releases/tag/model-v8>

Đường dẫn sau khi giải nén phải khớp `MODEL_DIR` mặc định: `model_v8/final_model_v8/`.

### Bước 2: Cấu hình
Chỉnh `configs/config.yaml`:
*   `upstream.url` — backend cần bảo vệ (mặc định `http://127.0.0.1:3000`)
*   `auth.jwt_secret` — thay chuỗi mới cho môi trường ngoài localhost
*   `database.*` — khớp với credential PostgreSQL
*   `admin.allowed_cidrs` — thêm subnet nếu cần quản trị từ máy khác

### Bước 3: Database
```bash
make db-start
```

### Bước 4: ML Service
```bash
make ml-install
make ml-start MODEL_DIR=/abs/path/to/final_model_v8
```

### Bước 5: TLS (do lớp ngoài lo)
WAF **không** tự terminate TLS — nó chạy HTTP thuần trên `:8080`. Việc mã hóa
đường truyền do lớp phía trước đảm nhiệm, tùy môi trường:
*   **Dev / localhost**: dùng trực tiếp HTTP, không cần chứng chỉ.
*   **Public qua Cloudflare Tunnel**: Cloudflare terminate TLS ở edge; chạy
    `cloudflared tunnel --url http://localhost:8080`. WAF nhận IP thật qua
    `CF-Connecting-IP` (cấu hình ở `admin.trusted_proxies`).
*   **Public tự host**: đặt nginx/Caddy trước WAF, cấu hình chứng chỉ
    (Let's Encrypt) ở đó rồi `proxy_pass` về `http://127.0.0.1:8080`. Nhớ
    forward `X-Forwarded-Proto` để cookie `Secure` được set đúng.

### Bước 6: Build & Run
```bash
make build
make run MODEL_DIR=/abs/path/to/final_model_v8
```
`make run` tự khởi động Postgres + ML rồi chạy WAF ở foreground. Các lệnh liên quan:
```bash
make run-waf      # chỉ WAF (ML đã chạy sẵn, hoặc tắt qua ml.enabled=false)
make stop         # dừng ML (giữ Postgres)
make down         # dừng cả ML và Postgres
```

### Cổng dịch vụ
| Dịch vụ | Địa chỉ |
|---|---|
| Dashboard | `http://localhost:8080/dashboard` |
| Proxy traffic | `http://localhost:8080` |
| ML service | `http://127.0.0.1:8000` |
| Backend upstream | `http://127.0.0.1:3000` |

### Triển khai bằng Docker
```bash
make docker
make docker-run
```

### Production (không dùng Docker)
Linux dùng systemd (`deployments/systemd/`), Windows dùng Windows Service
(`deployments/windows/install-services.ps1`). Đặt một reverse proxy TLS
(nginx/Caddy/Cloudflare) phía trước, `proxy_pass` về `http://127.0.0.1:8080`,
forward `X-Forwarded-Proto` + IP thật (`X-Real-IP`/`CF-Connecting-IP`) và khai
IP proxy vào `admin.trusted_proxies`.

> **Windows:** `make` không chạy trên CMD/PowerShell thuần. Dùng **WSL2** (khuyến nghị)
> hoặc Git Bash, hoặc chạy thủ công `go build` + `uvicorn` + `docker compose`.

---

## 🧪 Kiểm Thử (Testing)

Bốn lớp kiểm thử — từ unit tới đánh giá phát hiện trên dataset chuẩn:

### 1. Unit test (Go)
```bash
make test          # = go test ./...  (engine, auth, middleware, config, admin-gate…)
```

### 2. Đánh giá phát hiện trên CSIC 2010 (detection benchmark)
Harness `cmd/wafbench` đẩy bộ dữ liệu chuẩn **HTTP DATASET CSIC 2010** qua đúng
pipeline production (parser → normalizer → rule engine) rồi in Recall / FPR /
Precision / F1 — chính là số liệu trong báo cáo.
```bash
# Tải dataset một lần (hướng dẫn ở docs/EVALUATION.md mục 6), rồi:
go run ./cmd/wafbench -split test -tag test    # chỉ số trên tập TEST giữ kín
go run ./cmd/wafbench -split all  -tag final   # headline toàn corpus
```
Phương pháp luận + cách tái lập đầy đủ: [`docs/EVALUATION.md`](docs/EVALUATION.md).

### 3. Test chức năng black-box (WAF phải đang chạy)
```bash
./scripts/test_all.sh        # gộp: auto-ban + ML gray-zone + thuần ML (một lệnh)

# hoặc chạy riêng (cần .venv có `requests`):
.venv/bin/python scripts/test_ml_service.py     # thuần model, gửi thẳng :8000
.venv/bin/python scripts/test_autoban.py        # auto-ban → access-control blacklist
.venv/bin/python scripts/test_ml_gray_zone.py   # rule không quyết → gọi ML service
python3 scripts/test_multi_ips.py               # giả lập tấn công từ nhiều IP
```

### 4. Test chịu tải (load)
```bash
ab -n 1000 -c 100 http://localhost:8080/        # cần Apache Bench ('ab')
```

---

## 👤 Tài khoản Mặc định

*   **Admin Dashboard**: `http://localhost:8080/dashboard`
*   **User mặc định**:
    *   Username: `admin`
    *   Password: `admin` (Vui lòng đổi mật khẩu sau khi đăng nhập)

---

## 📝 Nhật Ký Thay Đổi (Changelog)

*   **v1.0**: Initial Release - WAF Core Engine, Basic Rules.
*   **v1.1**: Added Dashboard & Rate Limiting.
*   **v1.2**: Integrated PostgreSQL Authentication & JWT.
*   **v1.3**: Expanded Ruleset (78 rules, 13 categories).
*   **v1.4**: ML gray-zone layer (DistilBERT). Bỏ TLS trong WAF — terminate ở lớp ngoài (giống Coraza). Real-IP admin gate sau proxy, auto-ban → blacklist.

---

**Developed by Nguyen Thang**
