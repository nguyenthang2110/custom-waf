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
*   **Secure Auth System**: Hệ thống đăng ký/đăng nhập hoàn chỉnh sử dụng **PostgreSQL**.
*   **JWT Authentication**: Cơ chế xác thực không trạng thái (Stateless), bảo mật cao.
*   **Password Hashing**: Mật khẩu được mã hóa an toàn với **Bcrypt**.
*   **Role-based Access Control**: Phân quyền Admin/User.

### 📊 Dashboard & Monitoring
*   **Real-time Dashboard**: Giám sát lưu lượng truy cập và các request bị chặn theo thời gian thực.
*   **Traffic Analysis**: Biểu đồ thống kê trực quan.
*   **Log Management**: Xem và lọc nhật ký tấn công chi tiết.
*   **System Configuration**: Cấu hình luật và hệ thống ngay trên giao diện web.

### 🚀 Performance & Infrastructure
*   **High Performance**: Viết bằng Go (Golang) cho tốc độ xử lý cực nhanh và khả năng chịu tải lớn (Concurrency).
*   **Dockerized**: Dễ dàng triển khai với Docker và Docker Compose.
*   **HTTPS Support**: Hỗ trợ TLS/SSL bảo mật đường truyền.

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
├── scripts/                # Scripts tiện ích (Setup DB, Gen Certs, Test)
└── deployments/            # Cấu hình Docker
```

---

## 🛠️ Hướng Dẫn Triển Khai (Deployment)

### Yêu cầu tiên quyết
*   **Go** 1.21 trở lên
*   **Docker** & **Docker Compose** (chạy PostgreSQL)
*   **Python** 3.10+ (chạy ML service)
*   **Make** (Linux/macOS, hoặc WSL2/Git Bash trên Windows)
*   **Model DistilBERT v8** đặt tại `model_v8/final_model_v8/` (~268MB, không kèm trong repo)

### Bước 1: Cấu hình
Chỉnh `configs/config.yaml`:
*   `upstream.url` — backend cần bảo vệ (mặc định `http://127.0.0.1:3000`)
*   `auth.jwt_secret` — thay chuỗi mới cho môi trường ngoài localhost
*   `database.*` — khớp với credential PostgreSQL
*   `admin.allowed_cidrs` — thêm subnet nếu cần quản trị từ máy khác

### Bước 2: Database
```bash
make db-start
```

### Bước 3: ML Service
```bash
make ml-install
make ml-start MODEL_DIR=/abs/path/to/final_model_v8
```

### Bước 4: Chứng chỉ SSL
Repo đã kèm `configs/certs/cert.pem` & `key.pem`. Tạo lại khi cần:
```bash
mkdir -p configs/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout configs/certs/key.pem -out configs/certs/cert.pem -subj "/CN=localhost"
chmod 600 configs/certs/key.pem
```

### Bước 5: Build & Run
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
| Dashboard (HTTPS) | `https://localhost:8443` |
| Proxy traffic (HTTP) | `http://localhost:8080` |
| ML service | `http://127.0.0.1:8000` |
| Backend upstream | `http://127.0.0.1:3000` |

### Triển khai bằng Docker
```bash
make docker
make docker-run
```

### Production (không dùng Docker)
Linux dùng systemd (`deployments/systemd/`), Windows dùng Windows Service
(`deployments/windows/install-services.ps1`). Chi tiết: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

> **Windows:** `make` không chạy trên CMD/PowerShell thuần. Dùng **WSL2** (khuyến nghị)
> hoặc Git Bash, hoặc chạy thủ công `go build` + `uvicorn` + `docker compose`.

---

## 🧪 Kiểm Thử (Testing)

Dự án cung cấp sẵn các script để kiểm thử khả năng bảo vệ của WAF:

### 1. Test với các lỗ hổng cơ bản
```bash
# Chạy script Python giả lập tấn công từ nhiều IP
python3 scripts/test_multi_ips.py
```

### 2. Test toàn diện (Comprehensive)
```bash
# Script bash chạy toàn bộ bộ test
./scripts/test_all.sh

# Hoặc test riêng các luật WAF
./scripts/test_waf_rules.sh
```

### 3. Test năng lực chịu tải (Benchmark)
```bash
# Yêu cầu cài đặt 'ab' (Apache Bench)
ab -n 1000 -c 100 https://localhost:8443/
```

---

## 👤 Tài khoản Mặc định

*   **Admin Dashboard**: `https://localhost:8443`
*   **User mặc định**:
    *   Username: `admin`
    *   Password: `admin` (Vui lòng đổi mật khẩu sau khi đăng nhập)

---

## 📝 Nhật Ký Thay Đổi (Changelog)

*   **v1.0**: Initial Release - WAF Core Engine, Basic Rules.
*   **v1.1**: Added Dashboard & Rate Limiting.
*   **v1.2**: Integrated PostgreSQL Authentication & JWT.
*   **v1.3**: Expanded Ruleset (78 rules, 13 categories) & HTTPS Support.

---

**Developed by Nguyen Thang**
