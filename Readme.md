# Web Application Firewall (WAF) Project

🚀 **High-Performance WAF built with Go (Golang)**

Hệ thống WAF hiệu năng cao được xây dựng từ đầu bằng ngôn ngữ Go, có khả năng phát hiện và ngăn chặn các cuộc tấn công web phổ biến (OWASP Top 10), đồng thời cung cấp giao diện Dashboard giám sát trực quan và hệ thống quản lý người dùng bảo mật.

---

## 🌟 Tính Năng Chính (Key Features)

### 🛡️ Core Protection Engine
*   **Rule-based Detection**: Hệ thống luật (Ruleset) mạnh mẽ với 36 rules bao phủ 12 nhóm lỗ hổng:
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

## 🛠️ Hướng Dẫn Cài Đặt (Installation)

### Yêu cầu tiên quyết
*   **Docker** & **Docker Compose**
*   **Go** (phiên bản 1.21 trở lên)
*   **Make** (tùy chọn)

### Bước 1: Khởi tạo Database
Chạy script để setup PostgreSQL trên Docker và tạo bảng dữ liệu:
```bash
chmod +x scripts/setup_db.sh
./scripts/setup_db.sh
```

### Bước 2: Tạo chứng chỉ SSL (cho HTTPS)
Tạo chứng chỉ tự ký (Self-signed certificate) để chạy HTTPS trên localhost:
```bash
./scripts/generate_certs.sh
```

### Bước 3: Build và Chạy WAF
Sử dụng Makefile để build và chạy ứng dụng:
```bash
# Build ứng dụng
make build

# Chạy ứng dụng
make run
```
*WAF sẽ khởi động tại `https://localhost:8443` (Dashboard) và proxy traffic từ `http://localhost:8080`.*

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
# Script bash test đầy đủ các trường hợp
./scripts/test_comprehensive.sh
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
    *   Password: `admin123` (Vui lòng đổi mật khẩu sau khi đăng nhập)

---

## 📝 Nhật Ký Thay Đổi (Changelog)

*   **v1.0**: Initial Release - WAF Core Engine, Basic Rules.
*   **v1.1**: Added Dashboard & Rate Limiting.
*   **v1.2**: Integrated PostgreSQL Authentication & JWT.
*   **v1.3**: Expanded Ruleset (36 rules, 12 categories) & HTTPS Support.

---

**Developed by Nguyen Thang**
