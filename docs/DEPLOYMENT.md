# Hướng dẫn triển khai (Deployment) — Linux & Windows Server

Tài liệu này mô tả cách triển khai WAF **không dùng Docker** (cài trực tiếp trên
server) cho cả **Linux** và **Windows Server**. Phần cuối có ghi chú về triển khai
bằng Docker.

> Nếu chỉ muốn chạy thử trên máy dev, dùng `make run` (xem `CLAUDE.md`). Tài liệu
> này dành cho môi trường production.

---

## 1. Kiến trúc & các thành phần cần chạy

WAF gồm **3 tiến trình** độc lập:

| Thành phần | Công nghệ | Cổng mặc định | Bắt buộc? |
|---|---|---|---|
| **WAF reverse proxy** | Go binary (`bin/waf`) | `8080` (HTTP), `8443` (HTTPS) | ✅ Có |
| **PostgreSQL** | Postgres 15 | `5432` | ✅ Có (lưu user/auth, config & state) |
| **ML inference service** | Python FastAPI + DistilBERT | `8000` (chỉ loopback) | ⚙️ Tùy chọn — tắt bằng `ml.enabled: false` |

Sơ đồ luồng:

```
Internet ──▶ [WAF :8443] ──▶ upstream backend (app thật của bạn)
                │  │
                │  └─▶ PostgreSQL :5432   (user, runtime config, state)
                └────▶ ML service :8000   (chỉ gọi khi điểm rule nằm vùng xám)
```

- Dashboard quản trị nằm **nhúng trong binary** (`/dashboard`) — không có file tĩnh
  cần copy riêng.
- WAF đứng **trước** ứng dụng của bạn. Đặt địa chỉ ứng dụng thật vào
  `upstream.url` trong `configs/config.yaml`.

---

## 2. Yêu cầu phiên bản

| Phần mềm | Phiên bản | Ghi chú |
|---|---|---|
| Go | **1.24+** | Bắt buộc để build (`go.mod` khai báo `go 1.24.0`). |
| Python | **3.11** | Chỉ cần nếu chạy ML service. |
| PostgreSQL | **15** | 13–16 đều chạy được; CI/dev dùng 15. |
| RAM | ≥ 2 GB (ML cần ~1.5 GB cho model) | Không bật ML thì ~256 MB là đủ. |

> **Mô hình ML (mặc định) nằm trong repo ở `model_v7/final_model_v7/`** (thư mục
> `model_v*/` được `.gitignore` bỏ qua nên không bị commit). `MODEL_DIR` mặc định
> trỏ vào đây. Khi deploy lên server, copy thư mục `final_model_v7` lên và trỏ
> `MODEL_DIR` vào đó (hoặc một model tương đương).

---

## 3. Triển khai trên LINUX SERVER (Ubuntu/Debian)

Ví dụ cài vào `/opt/waf`, chạy dưới user hệ thống `waf`.

### 3.1. Cài phụ thuộc

```bash
sudo apt update
sudo apt install -y git build-essential python3.11 python3.11-venv postgresql postgresql-contrib

# Cài Go 1.24 (nếu apt chưa có bản đủ mới)
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee /etc/profile.d/go.sh
source /etc/profile.d/go.sh
go version   # phải in go1.24.x
```

### 3.2. Lấy source & build binary

```bash
sudo useradd --system --create-home --home-dir /opt/waf --shell /usr/sbin/nologin waf
sudo git clone <repo-url> /opt/waf        # hoặc rsync source lên /opt/waf
cd /opt/waf

sudo -u waf bash -c 'GOCACHE=/opt/waf/.gocache /usr/local/go/bin/go build -o bin/waf ./cmd/waf'
sudo -u waf ./bin/waf -version || true
```

Binary tự chứa toàn bộ dashboard và rule engine. Web assets đã `//go:embed`.

### 3.3. PostgreSQL

**Phương án A — Postgres native (khuyến nghị cho production):**

```bash
sudo -u postgres psql <<'SQL'
CREATE DATABASE waf_db;
CREATE USER waf_user WITH PASSWORD 'doi-mat-khau-manh-o-day';
GRANT ALL PRIVILEGES ON DATABASE waf_db TO waf_user;
\c waf_db
GRANT ALL ON SCHEMA public TO waf_user;
SQL
```

> ⚠️ **Quan trọng — phải chạy migrations thủ công.** Binary Go chỉ tự tạo các
> bảng *runtime config/state*; nó **KHÔNG** tự tạo bảng `users`/auth. Áp dụng
> các migration theo đúng thứ tự số:

```bash
cd /opt/waf
for f in migrations/0*.sql; do
  echo "Applying $f"
  PGPASSWORD='doi-mat-khau-manh-o-day' psql -h localhost -U waf_user -d waf_db -f "$f"
done
```

Việc này tạo bảng `users` và seed tài khoản admin mặc định **`admin / admin`**
(migration `005`). Đổi mật khẩu ngay sau khi đăng nhập lần đầu.

**Phương án B — Postgres trong Docker:** dùng `docker-compose.db.yml` ở repo root.
File này mount `./migrations` vào `/docker-entrypoint-initdb.d`, nên migrations
**tự chạy** ở lần khởi tạo DB đầu tiên:

```bash
docker compose -f docker-compose.db.yml up -d
```

### 3.4. ML service (bỏ qua nếu `ml.enabled: false`)

```bash
cd /opt/waf
sudo -u waf python3.11 -m venv .venv
sudo -u waf .venv/bin/pip install -r ml-service/requirements.txt

# Copy model lên server, ví dụ /opt/waf/models/final_model_v7
sudo mkdir -p /opt/waf/models
# rsync -a final_model_v7/ /opt/waf/models/final_model_v7/
```

### 3.5. Cấu hình production (`configs/config.yaml`)

Sửa các mục bắt buộc cho production:

```yaml
server:
  listen: "0.0.0.0:80"          # hoặc giữ 8080 nếu có LB/Nginx phía trước
  https_listen: "0.0.0.0:443"

upstream:
  url: "http://127.0.0.1:3000"  # ⟵ TRỎ VÀO APP THẬT CỦA BẠN

database:
  host: "localhost"
  password: "doi-mat-khau-manh-o-day"   # khớp bước 3.3

auth:
  jwt_secret: "<chuoi-ngau-nhien-64-ky-tu>"   # openssl rand -hex 32
  require_auth: true            # ⟵ BẬT xác thực ở production

admin:
  local_only: true
  allowed_cidrs:
    - "127.0.0.1/32"
    - "10.0.0.0/8"              # ⟵ thêm dải IP máy quản trị của bạn

ml:
  enabled: true
  endpoint: "http://127.0.0.1:8000"
```

**TLS:** mặc định `tls.enabled: true` và trỏ tới `./configs/certs/cert.pem` +
`key.pem`. Nếu file chứng chỉ không tồn tại, server HTTPS sẽ lỗi. Hai lựa chọn:

```bash
# (a) Tạo cert tự ký để test:
mkdir -p configs/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -keyout configs/certs/key.pem -out configs/certs/cert.pem \
  -subj "/CN=waf.local"
chmod 600 configs/certs/key.pem

# (b) Hoặc tắt TLS trong binary và để Nginx/LB lo TLS:
#     đặt tls.enabled: false trong config.yaml
```

### 3.6. Chạy như systemd service

Repo có sẵn unit files trong `deployments/systemd/`:

```bash
sudo cp deployments/systemd/waf-ml.service /etc/systemd/system/
sudo cp deployments/systemd/waf.service    /etc/systemd/system/
# Sửa MODEL_DIR trong waf-ml.service cho khớp đường dẫn model thật
sudo chown -R waf:waf /opt/waf
sudo systemctl daemon-reload
sudo systemctl enable --now waf-ml.service   # bỏ qua nếu không dùng ML
sudo systemctl enable --now waf.service
sudo systemctl status waf.service
journalctl -u waf -f
```

### 3.7. Firewall

```bash
sudo ufw allow 443/tcp      # HTTPS public
sudo ufw allow 80/tcp       # HTTP (redirect → HTTPS)
# KHÔNG mở 8000 (ML) và 5432 (Postgres) ra ngoài — chỉ loopback.
sudo ufw enable
```

---

## 4. Triển khai trên WINDOWS SERVER

Ví dụ cài vào `C:\waf`. Dùng PowerShell **Administrator**.

### 4.1. Cài phụ thuộc

- **Go 1.24+**: tải `go1.24.x.windows-amd64.msi` từ https://go.dev/dl/
- **Python 3.11**: từ python.org (tích "Add to PATH").
- **PostgreSQL 15**: installer từ enterprisedb.com (đặt password cho user `postgres`).
- **NSSM** (chạy console app như Windows Service): `choco install nssm`
  hoặc tải `nssm.exe` từ https://nssm.cc và đặt vào PATH.

### 4.2. Lấy source & build

```powershell
git clone <repo-url> C:\waf
cd C:\waf
go build -o bin\waf.exe ./cmd/waf
.\bin\waf.exe -version
```

> Có thể **cross-compile từ máy Linux/Mac** rồi copy lên Windows:
> ```bash
> GOOS=windows GOARCH=amd64 go build -o waf.exe ./cmd/waf
> ```

### 4.3. PostgreSQL

Tạo DB và user (PowerShell, dùng `psql` đi kèm Postgres):

```powershell
$env:PGPASSWORD = '<mat-khau-postgres>'
psql -U postgres -h localhost -c "CREATE DATABASE waf_db;"
psql -U postgres -h localhost -c "CREATE USER waf_user WITH PASSWORD 'doi-mat-khau-manh';"
psql -U postgres -h localhost -c "GRANT ALL PRIVILEGES ON DATABASE waf_db TO waf_user;"
psql -U postgres -h localhost -d waf_db -c "GRANT ALL ON SCHEMA public TO waf_user;"

# Áp dụng migrations theo thứ tự (tạo bảng users + seed admin/admin)
$env:PGPASSWORD = 'doi-mat-khau-manh'
Get-ChildItem C:\waf\migrations\0*.sql | Sort-Object Name | ForEach-Object {
    Write-Host "Applying $($_.Name)"
    psql -U waf_user -h localhost -d waf_db -f $_.FullName
}
```

### 4.4. ML service (tùy chọn)

```powershell
cd C:\waf
python -m venv .venv
.\.venv\Scripts\pip install -r ml-service\requirements.txt
# Copy model vào C:\waf\models\final_model_v7
```

### 4.5. Cấu hình

Sửa `C:\waf\configs\config.yaml` y như mục **3.5** (jwt_secret, require_auth,
upstream.url, database.password, admin.allowed_cidrs).

Tạo cert tự ký (cần OpenSSL, hoặc dùng PowerShell `New-SelfSignedCertificate`):

```powershell
# Cách đơn giản: tắt TLS trong config.yaml (tls.enabled: false) và để IIS/LB lo,
# hoặc tạo cert bằng OpenSSL nếu đã cài:
mkdir C:\waf\configs\certs
openssl req -x509 -newkey rsa:2048 -nodes -days 365 `
  -keyout C:\waf\configs\certs\key.pem -out C:\waf\configs\certs\cert.pem -subj "/CN=waf.local"
```

### 4.6. Chạy như Windows Service (NSSM)

Repo có sẵn script `deployments\windows\install-services.ps1`:

```powershell
# Chạy trong PowerShell Administrator
cd C:\waf
.\deployments\windows\install-services.ps1 -InstallRoot 'C:\waf' -ModelDir 'C:\waf\models\final_model_v7'

Get-Service WAF, WAF-ML
```

Script tạo 2 service: **WAF-ML** (ML inference) và **WAF** (reverse proxy, phụ
thuộc WAF-ML), bật auto-start và auto-restart, ghi log vào `C:\waf\logs\`.

Gỡ service:
```powershell
nssm remove WAF confirm
nssm remove WAF-ML confirm
```

### 4.7. Firewall

```powershell
New-NetFirewallRule -DisplayName "WAF HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "WAF HTTP"  -Direction Inbound -Protocol TCP -LocalPort 80  -Action Allow
# KHÔNG mở 8000 và 5432 ra ngoài.
```

---

## 5. Kiểm tra sau khi deploy (cả hai HĐH)

```bash
# 1. Health check (không cần auth)
curl -k https://<server>/health          # kỳ vọng: 200 OK

# 2. ML service sống (chạy trên chính server)
curl http://127.0.0.1:8000/health        # kỳ vọng: {"status":"ok",...}

# 3. Dashboard — mở từ máy nằm trong admin.allowed_cidrs
#    https://<server>/dashboard  → đăng nhập admin/admin → ĐỔI MẬT KHẨU NGAY

# 4. Thử một request tấn công để xác nhận WAF chặn
curl -k "https://<server>/?id=1' OR '1'='1"   # kỳ vọng: bị BLOCK (403)
```

Xem log:
- Linux: `journalctl -u waf -f`, `journalctl -u waf-ml -f`, file `logs/waf/access.log` & `audit.log`.
- Windows: `C:\waf\logs\waf-service.log`, `ml-service.log`, `logs\waf\*.log`.

---

## 6. Checklist bảo mật trước khi mở ra Internet

- [ ] Đổi mật khẩu `admin/admin` ngay sau lần đăng nhập đầu.
- [ ] `auth.require_auth: true`.
- [ ] `auth.jwt_secret` thay bằng chuỗi ngẫu nhiên (`openssl rand -hex 32`).
- [ ] `database.password` mạnh, khác mặc định `waf_password`.
- [ ] `admin.allowed_cidrs` chỉ chứa dải IP quản trị (mặc định loopback).
- [ ] TLS bật với cert hợp lệ (hoặc TLS do LB/Nginx phía trước đảm nhiệm).
- [ ] Cổng `8000` (ML) và `5432` (Postgres) **không** mở ra ngoài.
- [ ] `upstream.url` trỏ đúng app backend thật.
- [ ] File `configs/certs/key.pem` quyền `600`, không commit vào git.

---

## 7. Triển khai bằng Docker (tham khảo)

- `docker-compose.db.yml` (repo root) — chỉ Postgres, tự chạy migrations.
- `deployments/docker/Dockerfile` + `docker-compose.yml` — build image WAF.

> ⚠️ `deployments/docker/Dockerfile` build được image cho riêng WAF binary,
> nhưng `deployments/docker/docker-compose.yml` ở đó **chưa kèm Postgres và ML
> service** (chỉ có WAF + nginx demo + Prometheus/Grafana), nên chưa phải bộ
> stack hoàn chỉnh. Để chạy đầy đủ bằng Docker, bạn cần tự thêm service Postgres
> (xem `docker-compose.db.yml`) và ML (xem `ml-service/Dockerfile`, nhớ mount
> model vào `/app/model`). Khuyến nghị dùng cách cài native ở mục 3/4 cho
> production cho tới khi bộ Docker được hoàn thiện.

---

## 8. Nâng cấp (update phiên bản mới)

```bash
# Linux
cd /opt/waf && sudo -u waf git pull
sudo -u waf bash -c 'GOCACHE=/opt/waf/.gocache /usr/local/go/bin/go build -o bin/waf ./cmd/waf'
# Nếu có file migrations mới (006_*.sql ...), áp dụng chúng trước khi restart
sudo systemctl restart waf
```

```powershell
# Windows
cd C:\waf; git pull
go build -o bin\waf.exe ./cmd/waf
# Áp dụng migrations mới nếu có, rồi:
Restart-Service WAF
```

Runtime config đã chỉnh qua dashboard được lưu trong Postgres nên **vẫn giữ
nguyên** sau khi nâng cấp/restart.

---

## 9. Ví dụ thực tế: mở ra Internet, bảo vệ backend OWASP Juice Shop (`:3000`)

Phần này là một kịch bản **end-to-end hoàn chỉnh**: dựng một app dễ-bị-tấn-công
([OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)) làm backend chạy
ở cổng `3000`, đặt WAF đứng trước nó, rồi expose WAF ra Internet qua `:443`.
Dùng đúng giá trị mặc định `upstream.url: http://127.0.0.1:3000` đã có sẵn trong
`configs/config.yaml`.

### 9.1. Mô hình triển khai (1 server)

```
                          server công khai (VPS / EC2 / VM)
                 ┌──────────────────────────────────────────────────┐
  Internet ─────▶│  WAF  :80 → 301 → :443  (Go binary, chạy systemd) │
   (client thật) │     │                                             │
                 │     └─▶ upstream  127.0.0.1:3000  (Juice Shop)    │  ← chỉ loopback
                 │     └─▶ PostgreSQL 127.0.0.1:5432                 │  ← chỉ loopback
                 │     └─▶ ML service 127.0.0.1:8000 (tùy chọn)      │  ← chỉ loopback
                 └──────────────────────────────────────────────────┘
   Admin ─────── SSH tunnel ──▶ 127.0.0.1 trên server ──▶ /dashboard
```

**Nguyên tắc vàng:** chỉ **WAF** được nghe ra ngoài (`80`/`443`). Backend
(`3000`), Postgres (`5432`) và ML (`8000`) **chỉ bind loopback** — người ngoài
bắt buộc phải đi xuyên qua WAF, không có đường vòng.

> ⚠️ **KHÔNG đặt Nginx/HAProxy/LB đứng *trước* WAF trong mô hình này.** Cổng gác
> admin (`/dashboard`, `/waf-api/*` …) nhận diện client bằng **địa chỉ TCP thật**
> (`RemoteAddr`), *không* đọc `X-Forwarded-For`. Nếu có proxy phía trước, mọi
> request sẽ mang IP của proxy (thường `127.0.0.1`) → lọt vào dải loopback mặc
> định trong `admin.allowed_cidrs` → **toàn bộ Internet xem được trang admin**.
> Để WAF tự nghe `:443` (mục 9.4) là cách an toàn nhất. Nếu bắt buộc phải có CDN
> phía trước, xem cảnh báo ở mục 9.7.

### 9.2. Dựng backend OWASP Juice Shop ở cổng 3000

Cách nhanh nhất là Docker, **bind vào loopback** để không lộ ra ngoài:

```bash
# Chạy Juice Shop, chỉ nghe 127.0.0.1:3000 (không phải 0.0.0.0)
docker run -d --name juiceshop --restart unless-stopped \
  -p 127.0.0.1:3000:3000 bkimminich/juice-shop

# Kiểm tra backend sống (từ chính server)
curl -sI http://127.0.0.1:3000 | head -1     # → HTTP/1.1 200 OK
```

> Không có Docker? Chạy native: `git clone https://github.com/juice-shop/juice-shop`,
> `npm install`, rồi `nohup npm start &` (mặc định nghe `0.0.0.0:3000` — nhớ chặn
> cổng 3000 ở firewall, mục 9.6). Bất kỳ app nào của bạn chạy ở `:3000` đều thay
> được Juice Shop ở đây; chỉ cần đổi `upstream.url` nếu cổng khác.

### 9.3. Trỏ WAF vào backend & mở cổng công khai

Sửa `configs/config.yaml` (giả sử cài tại `/opt/waf` theo mục 3):

```yaml
server:
  listen: "0.0.0.0:80"          # nhận HTTP public (sẽ 301 sang HTTPS)
  https_listen: "0.0.0.0:443"   # nhận HTTPS public

upstream:
  url: "http://127.0.0.1:3000"  # ← Juice Shop / app của bạn (đã là mặc định)

tls:
  enabled: true
  cert_file: "/opt/waf/configs/certs/fullchain.pem"
  key_file: "/opt/waf/configs/certs/privkey.pem"
  auto_redirect: true           # 80 → 443

auth:
  require_auth: true
  jwt_secret: "<openssl rand -hex 32>"

admin:
  local_only: true
  allowed_cidrs:
    - "127.0.0.0/8"             # giữ loopback → admin qua SSH tunnel (mục 9.5)
    - "::1/128"
```

systemd unit `deployments/systemd/waf.service` đã có
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, nên user `waf` **bind được `:80`/`:443`
mà không cần chạy root**.

### 9.4. TLS thật bằng Let's Encrypt (có domain)

WAF tự phục vụ TLS từ `cert_file`/`key_file`, nên ta chỉ cần lấy cert rồi trỏ vào.
Dùng certbot ở chế độ `standalone` (xin/ gia hạn cert) — phải tạm dừng WAF khi xin
vì certbot cần cổng 80:

```bash
sudo apt install -y certbot
sudo systemctl stop waf
sudo certbot certonly --standalone -d waf.example.com   # thay domain của bạn
sudo systemctl start waf
```

Cert nằm ở `/etc/letsencrypt/live/waf.example.com/`. Vì binary chạy bằng user
`waf` (không đọc được `/etc/letsencrypt`), copy cert sang thư mục WAF qua một
**deploy-hook** để mỗi lần gia hạn tự cập nhật:

```bash
sudo tee /etc/letsencrypt/renewal-hooks/deploy/waf-copy.sh >/dev/null <<'EOF'
#!/bin/bash
D=/etc/letsencrypt/live/waf.example.com
install -m 644 -o waf -g waf "$D/fullchain.pem" /opt/waf/configs/certs/fullchain.pem
install -m 600 -o waf -g waf "$D/privkey.pem"   /opt/waf/configs/certs/privkey.pem
systemctl restart waf
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/waf-copy.sh
sudo /etc/letsencrypt/renewal-hooks/deploy/waf-copy.sh   # chạy lần đầu
```

Certbot tự cài timer gia hạn; kiểm tra bằng `sudo certbot renew --dry-run`.

> Chỉ demo trong LAN, chưa có domain? Bỏ qua Let's Encrypt — tạo cert tự ký
> (`./scripts/generate_certs.sh`, trỏ `cert_file`/`key_file` vào đó) và chấp nhận
> cảnh báo trình duyệt.

### 9.5. Truy cập trang admin an toàn (SSH tunnel)

Giữ `allowed_cidrs` chỉ loopback rồi mở tunnel từ máy bạn — request admin sẽ tới
WAF với `RemoteAddr = 127.0.0.1`, qua được cổng gác mà **không phải mở admin ra
Internet**:

```bash
# Trên máy của bạn: forward localhost:8443 → cổng 443 trên server
ssh -N -L 8443:127.0.0.1:443 deploy@waf.example.com
# Rồi mở trình duyệt:  https://127.0.0.1:8443/dashboard
# Đăng nhập admin/admin → ĐỔI MẬT KHẨU NGAY
```

> Muốn admin trực tiếp không qua tunnel? Thêm IP tĩnh của bạn vào `allowed_cidrs`
> (ví dụ `203.0.113.5/32`) thay vì mở rộng dải. Tránh dùng dải lớn hay `0.0.0.0/0`.

### 9.6. Firewall đám mây / security group

Chỉ mở **3 cổng vào**; mọi cổng nội bộ phải đóng với Internet:

| Cổng | Hướng | Mở ra Internet? |
|---|---|---|
| `22` (SSH) | vào | ✅ (tốt nhất giới hạn theo IP quản trị) |
| `80`, `443` (WAF) | vào | ✅ |
| `3000` (backend), `8000` (ML), `5432` (Postgres) | — | ❌ **Đóng** |

```bash
# Tường lửa máy (ufw) — lớp phòng thủ thứ hai sau security group đám mây
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw deny 3000/tcp        # phòng khi backend lỡ bind 0.0.0.0
sudo ufw enable
```

Ở AWS/GCP/Azure, đặt quy tắc tương đương trong **Security Group / firewall đám mây**
— đừng chỉ dựa vào ufw.

### 9.7. DNS & (tùy chọn) CDN phía trước

- Trỏ bản ghi **A** `waf.example.com` → IP công khai của server.
- **Nếu muốn đặt Cloudflare/CDN trước WAF:** đọc kỹ — vì WAF *tin tuyệt đối*
  `X-Forwarded-For`/`CF-Connecting-IP` (xem [parser.go](internal/parser/parser.go:71)),
  việc đứng trực tiếp ra Internet khiến kẻ tấn công có thể **giả mạo IP** để né
  blacklist/rate-limit. Đặt sau Cloudflare *và* khóa firewall server **chỉ nhận
  kết nối từ dải IP Cloudflare** sẽ vừa lấy được IP client thật (Cloudflare ghi đè
  header), vừa chặn giả mạo. Khi đó vẫn quản trị qua **SSH tunnel** (mục 9.5) để
  cổng gác admin theo `RemoteAddr` hoạt động đúng — đừng nới `allowed_cidrs` cho
  dải Cloudflare, vì thế là mở admin cho mọi khách đi qua CDN.

### 9.8. Kiểm thử end-to-end

```bash
# 1) Lưu lượng hợp lệ phải đi xuyên qua WAF tới Juice Shop
curl -sI https://waf.example.com/ | head -1            # → 200, trang Juice Shop

# 2) Tấn công SQLi mẫu phải bị WAF CHẶN (403) — không chạm tới backend
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://waf.example.com/rest/products/search?q=test%27%20OR%201=1--"   # → 403

# 3) XSS mẫu cũng bị chặn
curl -s -o /dev/null -w "%{http_code}\n" \
  "https://waf.example.com/?search=<script>alert(1)</script>"            # → 403

# 4) Backend KHÔNG được lộ trực tiếp từ ngoài
curl -m 5 -sI http://waf.example.com:3000/ ; echo "exit=$?"   # → timeout/refused
```

Mở `/dashboard` (qua tunnel) → tab **Access Log** sẽ thấy các request bị `BLOCK`
kèm rule đã khớp và điểm anomaly; tab **Audit Log** (chỉ admin) ghi sự kiện đăng
nhập/đổi cấu hình.

### 9.9. Tóm tắt khác biệt so với deploy nội bộ

| Hạng mục | Nội bộ (mục 3/4) | Public + Juice Shop (mục 9) |
|---|---|---|
| `server.listen` | `:8080` / `:8443` | `:80` / `:443` |
| `upstream.url` | app nội bộ | `http://127.0.0.1:3000` (Juice Shop) |
| TLS | self-signed | Let's Encrypt + auto-renew |
| `require_auth` | có thể `false` khi test | **bắt buộc `true`** |
| Admin | mở trực tiếp trong LAN | **SSH tunnel**, giữ loopback CIDR |
| Firewall | tùy | chỉ `22/80/443`; chặn `3000/8000/5432` |
