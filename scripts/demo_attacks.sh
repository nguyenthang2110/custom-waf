#!/usr/bin/env bash
#
# demo_attacks.sh — Demo trực quan: cùng một payload tấn công, bắn song song
# vào (1) site CÓ WAF và (2) backend KHÔNG WAF, rồi in kết quả cạnh nhau.
#
# Dùng cho buổi demo: người xem thấy ngay WAF chặn (403) trong khi backend
# trần xử lý request tấn công bình thường (200/500...).
#
#   ./scripts/demo_attacks.sh [WAF_URL] [BACKEND_URL]
#
# Mặc định:
#   WAF_URL      = http://localhost:8080   (reverse-proxy WAF)
#   BACKEND_URL  = http://localhost:3000   (OWASP Juice Shop trần)
#
# Ví dụ demo qua tunnel:
#   ./scripts/demo_attacks.sh https://xxxx.trycloudflare.com http://localhost:3000
#
set -u

WAF="${1:-http://localhost:8080}"
BACK="${2:-http://localhost:3000}"
TIMEOUT=8

# Màu
G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; B=$'\e[1m'; D=$'\e[2m'; N=$'\e[0m'

# Trả về HTTP status code của một request (mọi tham số curl truyền sau)
http_code() { curl -s -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "$@" 2>/dev/null || echo "ERR"; }

# Verdict cho phía WAF: 403 = chặn (tốt), khác = lọt
waf_verdict() {
  case "$1" in
    403) echo "${G}${B}🛡  BLOCKED (403)${N}" ;;
    000|ERR) echo "${Y}… không kết nối được${N}" ;;
    *) echo "${R}${B}⚠  LỌT ($1)${N}" ;;
  esac
}
# Verdict cho backend trần: bất kỳ 2xx/4xx/5xx nghĩa là request CHẠM được app
back_verdict() {
  case "$1" in
    000|ERR) echo "${Y}… không kết nối được${N}" ;;
    *) echo "${D}xử lý request ($1)${N}" ;;
  esac
}

# Mỗi test định nghĩa bằng: TÊN | PHƯƠNG THỨC | ĐƯỜNG DẪN+QUERY | (tuỳ chọn) body | (tuỳ chọn) content-type
# Bắn vào $WAF$path và $BACK$path với cùng tham số.
test_get() {
  local name="$1" path="$2"; shift 2
  local w b
  w=$(http_code -G "$WAF$path" "$@" -H 'Accept: application/json, text/plain, */*')
  b=$(http_code -G "$BACK$path" "$@" -H 'Accept: application/json, text/plain, */*')
  printf "%b\n   %-22s %b\n   %-22s %b\n\n" \
    "${B}▸ $name${N}" "CÓ WAF :" "$(waf_verdict "$w")" "KHÔNG WAF:" "$(back_verdict "$b")"
}
test_post_json() {
  local name="$1" path="$2" body="$3"
  local w b
  w=$(http_code -X POST "$WAF$path"  -H 'Content-Type: application/json' --data "$body")
  b=$(http_code -X POST "$BACK$path" -H 'Content-Type: application/json' --data "$body")
  printf "%b\n   %-22s %b\n   %-22s %b\n\n" \
    "${B}▸ $name${N}" "CÓ WAF :" "$(waf_verdict "$w")" "KHÔNG WAF:" "$(back_verdict "$b")"
}
test_post_raw() {
  local name="$1" path="$2" ctype="$3" body="$4"
  local w b
  w=$(http_code -X POST "$WAF$path"  -H "Content-Type: $ctype" --data "$body")
  b=$(http_code -X POST "$BACK$path" -H "Content-Type: $ctype" --data "$body")
  printf "%b\n   %-22s %b\n   %-22s %b\n\n" \
    "${B}▸ $name${N}" "CÓ WAF :" "$(waf_verdict "$w")" "KHÔNG WAF:" "$(back_verdict "$b")"
}

# Reset: gỡ auto-ban loopback để buổi demo bắt đầu sạch (best-effort, bỏ qua lỗi).
# Sau loạt tấn công, WAF tự blacklist IP → traffic sạch cũng bị 403; reset để lặp lại được.
reset_state() {
  for ip in "::1" "127.0.0.1" "[::1]"; do
    curl -s -o /dev/null --max-time 5 -X POST "$WAF/waf-api/ips/unblock" \
      -H 'Content-Type: application/json' --data "{\"ip\":\"$ip\"}" 2>/dev/null
  done
}

echo "${B}==================================================================${N}"
echo "${B} DEMO WAF — cùng payload, bắn vào site CÓ WAF vs KHÔNG WAF${N}"
echo "${B}==================================================================${N}"
echo "  CÓ WAF    : $WAF"
echo "  KHÔNG WAF : $BACK   (OWASP Juice Shop trần)"
echo "------------------------------------------------------------------"
reset_state
echo ""

echo "${B}### A. TRAFFIC HỢP LỆ — phải đi qua WAF bình thường (không chặn nhầm)${N}"
echo ""
w=$(http_code "$WAF/" -H 'Accept: text/html'); b=$(http_code "$BACK/" -H 'Accept: text/html')
printf "%b\n   %-22s %b\n   %-22s %b\n\n" "${B}▸ Mở trang chủ (GET /)${N}" \
  "CÓ WAF :" "${G}cho qua ($w)${N}" "KHÔNG WAF:" "${D}cho qua ($b)${N}"
w=$(http_code -G "$WAF/rest/products/search" --data-urlencode "q=apple")
b=$(http_code -G "$BACK/rest/products/search" --data-urlencode "q=apple")
printf "%b\n   %-22s %b\n   %-22s %b\n\n" "${B}▸ Tìm kiếm hợp lệ (q=apple)${N}" \
  "CÓ WAF :" "${G}cho qua ($w)${N}" "KHÔNG WAF:" "${D}cho qua ($b)${N}"

echo "${B}### B. TẤN CÔNG — WAF chặn (403), backend trần xử lý request${N}"
echo ""

# --- 1. SQL Injection: bypass đăng nhập (admin) ---
test_post_json "[1] SQLi — bypass đăng nhập admin" \
  "/rest/user/login" \
  '{"email":"'"'"' OR 1=1--","password":"x"}'

# --- 2. SQL Injection: UNION rút bảng users qua ô search ---
test_get "[2] SQLi — UNION SELECT qua ô search" \
  "/rest/products/search" \
  --data-urlencode "q=')) UNION SELECT 1,2,3,4,5,6,7,8,9 FROM users--"

# --- 3. XSS phản chiếu trong search (server-side) ---
test_get "[3] XSS — iframe/onload qua search" \
  "/rest/products/search" \
  --data-urlencode 'q=<iframe src="javascript:alert(`xss`)">'

# --- 4. Path traversal: leo thư mục qua /ftp (URL-encoded) ---
test_get "[4] Path Traversal — /ftp encoded ../../etc/passwd" \
  "/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd"

# --- 5. LFI: leo thư mục đọc /etc/passwd ---
test_get "[5] LFI — ../../../../etc/passwd" \
  "/" --data-urlencode "file=../../../../etc/passwd"

# --- 6. NoSQL injection ---
test_get "[6] NoSQL Injection — toán tử \$ne" \
  "/rest/products/search" \
  --data-urlencode 'q[$ne]=1'

# --- 7. OS Command injection ---
test_get "[7] Command Injection — ; cat /etc/passwd" \
  "/" --data-urlencode "x=; cat /etc/passwd"

# --- 8. XXE: external entity đọc file ---
test_post_raw "[8] XXE — external entity đọc /etc/passwd" \
  "/file-upload" "application/xml" \
  '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

# --- 9. SSRF: gọi vào metadata nội bộ ---
test_get "[9] SSRF — gọi 169.254.169.254 (cloud metadata)" \
  "/profile/image/url" \
  --data-urlencode "imageUrl=http://169.254.169.254/latest/meta-data/"

echo "------------------------------------------------------------------"
echo "${G}🛡  = WAF chặn (403)${N}    ${R}⚠ = lọt${N}    ${D}backend trần luôn xử lý request${N}"
echo ""
echo "Ghi chú: vài payload sát ngưỡng có thể chỉ bị chặn sau khi IP đã bị"
echo "đánh dấu là 'repeat offender'. Chạy lại script lần 2 nếu thấy 1 dòng lọt."
