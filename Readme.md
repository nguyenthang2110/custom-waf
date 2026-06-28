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

---

## 📦 Cấu Trúc Dự Án

```
waf-project/
├── cmd/
│   ├── waf/                # Điểm khởi chạy WAF (main entry point)
│   └── wafbench/           # Harness benchmark phát hiện trên CSIC 2010
├── internal/
│   ├── api/                # API endpoints quản trị (/waf-api/*)
│   ├── audit/              # Logger access + audit (JSON-lines + ring buffer)
│   ├── auth/               # Xác thực & JWT
│   ├── behavior/           # Behavior detector (brute-force, auto-ban)
│   ├── configstore/        # Lưu cấu hình runtime xuống PostgreSQL
│   ├── database/           # Kết nối PostgreSQL
│   ├── decision/           # Decision engine (BLOCK / MONITOR / ALLOW)
│   ├── engine/             # Rule engine (inspect, matching, ML hook)
│   ├── metrics/            # Thu thập số liệu thống kê
│   ├── middleware/         # Middleware WAF + admin access control
│   ├── ml/                 # Client gọi ML service (HTTP)
│   ├── models/             # Cấu trúc dữ liệu (User, Log)
│   ├── normalizer/         # Chuẩn hoá request trước khi inspect
│   ├── notifier/           # Gửi cảnh báo (Slack / Email / PagerDuty)
│   ├── parser/             # Parse HTTP request
│   ├── ratelimit/          # Rate limiter (Token Bucket per-IP)
│   ├── statestore/         # Snapshot trạng thái runtime (IP lists…)
│   └── training/           # Canonical text + xuất dữ liệu huấn luyện
├── pkg/config/             # Định nghĩa & nạp config.yaml
├── ml-service/             # ML service FastAPI + DistilBERT (app.py)
├── configs/                # config.yaml và bộ luật (rules/)
├── migrations/             # Scripts khởi tạo database
├── web/                    # Frontend (HTML/CSS/JS) nhúng vào binary
├── scripts/                # Scripts tiện ích (setup DB, test)
└── deployments/            # Docker, systemd, Windows Service
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
Model không commit trong git. Tải thư mục `final_model_v8/` từ Google Drive về,
đặt vào `model_v8/` trong repo:

> 📦 **Model + Dataset (Google Drive):** <https://drive.google.com/drive/folders/1un5pL9wrnDJ9971JTaNxsubzDwioFKSz?usp=sharing>

Đường dẫn sau khi đặt phải khớp `MODEL_DIR` mặc định: `model_v8/final_model_v8/`.

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
WAF tách **hai mặt phẳng** trên hai cổng riêng (kiểu control/data plane):

| Dịch vụ | Địa chỉ | Mặt phẳng |
|---|---|---|
| Dashboard + API quản trị | `http://localhost:8080/dashboard` | **control** (`admin.listen`) |
| Traffic được bảo vệ → upstream | `http://localhost:8081` | **data** (`server.listen`) |
| ML service | `http://127.0.0.1:8000` | — |
| Backend upstream | `http://127.0.0.1:3000` | — |

> API quản trị (`/waf-api/*`, `/metrics`, `/admin/*`) **chỉ** nằm trên cổng control (8080); cổng data (8081) chỉ phục vụ traffic và không lộ API quản trị. Khi expose ra public (Cloudflare Tunnel / nginx), trỏ vào **cổng data 8081**; giữ 8080 cục bộ.

### Triển khai bằng Docker
```bash
make docker
make docker-run
```

### Production (không dùng Docker)
Linux dùng systemd (`deployments/systemd/`), Windows dùng Windows Service
(`deployments/windows/install-services.ps1`).

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

## 🧠 Huấn Luyện Model (Training)

Model DistilBERT 11 lớp được train bằng notebook
[`Web_Attack_Detection_v8.ipynb`](Web_Attack_Detection_v8.ipynb) trên **Google Colab**
(GPU). Train **fresh** từ `distilbert-base-uncased` (không warm-start).

**11 lớp:** `normal, sqli, xss, cmdi, path_traversal, ssrf, xxe, log4shell, ssti, nosqli, crlf`.

### Dataset
3 file CSV (cột `text`, `label`) — đặt public trên Google Drive:

> 📦 **Dataset:** <https://drive.google.com/drive/folders/1un5pL9wrnDJ9971JTaNxsubzDwioFKSz?usp=sharing>  (cùng thư mục Drive với model)

| File | Số dòng |
|---|---|
| `train.csv` | 408.801 |
| `val.csv` | 51.099 |
| `test.csv` | 51.099 |

`text` là **canonical WAF** (khớp byte-for-byte với `internal/training` phía Go và
`ml-service/app.py` phía Python); `label` là một trong 11 lớp ở trên.

### Các bước (Colab)
1. Tải 3 file CSV từ Drive ở trên, đặt vào `MyDrive/web_attack_detection_v8/`.
2. Mở `Web_Attack_Detection_v8.ipynb` bằng Colab → **Runtime → Change runtime type → GPU**
   (A100/L4 khuyến nghị; T4 mất ~5–6h cho 3 epoch).
3. Chạy lần lượt từng cell từ trên xuống.
4. Notebook lưu model ra `MyDrive/web_attack_detection_v8/model_v8/final_model_v8/`
   (kèm `label_config.json` + `confusion_v8.png`).

**Cấu hình train** (CELL 3): `max_length=256`, `epochs=3`, `batch=32`, `lr=2e-5`,
warmup 0.06, weight decay 0.01, label smoothing 0.05, class weights *balanced* (tự động).

### Dùng model vừa train
Tải thư mục `final_model_v8/` từ Drive về máy, đặt khớp `MODEL_DIR` mặc định:
```
model_v8/final_model_v8/
```
rồi chạy lại WAF (Bước 4–5). Hoặc trỏ tay: `make run MODEL_DIR=/abs/path/to/final_model_v8`.

---

## 👤 Tài khoản Mặc định

*   **Admin Dashboard**: `http://localhost:8080/dashboard`
*   **User mặc định**:
    *   Username: `admin`
    *   Password: `admin` (Vui lòng đổi mật khẩu sau khi đăng nhập)

---

**Developed by Nguyen Thang**
