#!/usr/bin/env bash
# Smoke-test the WAF + ML hybrid pipeline.
#
# Each payload is engineered to land in a specific zone:
#
#   GRAY ZONE  (rule score = 4.0  → invokes BERT model)
#   BLOCK ZONE (rule score ≥ 5.0  → blocked by rule directly)
#   ALLOW ZONE (rule score < 4.0  → allowed without ML)
#
# Watch the dashboard at http://localhost:8080/dashboard during the run.
# Logs from gray-zone payloads will show "🤖 MODEL" in the Source column.

set -u
# Default to HTTPS port because the WAF redirects 8080→8443 when TLS is on.
# Override with: WAF_URL=http://localhost:8080 ./scripts/test_ml_payloads.sh
WAF_URL="${WAF_URL:-https://localhost:8443}"
ML_URL="${ML_URL:-http://localhost:8000}"

cyan() { printf "\033[36m%s\033[0m\n" "$*"; }
green() { printf "\033[32m%s\033[0m\n" "$*"; }
red() { printf "\033[31m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }

# -k    : accept self-signed cert (the WAF ships with one)
# -L    : follow redirects (HTTP→HTTPS, dashboard, etc.)
# --max-time 5 : never block forever
CURL_ARGS=(-skL --max-time 5 -A "WAF-test/1.0")

hit() {
  local label="$1"; local url="$2"; local zone="$3"
  printf "[%s] %-22s -> " "$zone" "$label"
  status=$(curl "${CURL_ARGS[@]}" -o /dev/null -w "%{http_code}" "$url")
  case "$status" in
    200) green   "HTTP $status (allowed)" ;;
    403) red     "HTTP $status (blocked)" ;;
    429) yellow  "HTTP $status (challenge)" ;;
    *)   echo "HTTP $status" ;;
  esac
}

cyan "=== Health checks ==="
hit "WAF /health"     "$WAF_URL/health"          "BYPASS"
hit "ML  /health"     "$ML_URL/health"           "ML-svc"
echo

cyan "=== GRAY ZONE (rule=4.0 → BERT decides) ==="
hit "SQLi tautology"  "$WAF_URL/?id=1%20OR%201%3D1"                     "GRAY"
hit "SQLi error-based" "$WAF_URL/?u=test%40%40version"                  "GRAY"
hit "XSS event handler" "$WAF_URL/?name=hello%20onclick%3Dalert(1)"     "GRAY"
hit "XSS DOM sink"    "$WAF_URL/?msg=document.cookie"                   "GRAY"
hit "CMDi recon"      "$WAF_URL/?q=whoami"                              "GRAY"
hit "CMDi windows"    "$WAF_URL/?cmd=cmd.exe"                           "GRAY"
hit "Path single"     "$WAF_URL/?file=..%2Fconfig"                      "GRAY"
hit "Path nullbyte"   "$WAF_URL/?file=test.txt%00.png"                  "GRAY"
echo

cyan "=== BLOCK ZONE (rule ≥ 5.0 → rule blocks directly) ==="
hit "SQLi UNION"      "$WAF_URL/?id=1%20UNION%20SELECT%20user%2Cpw%20FROM%20users" "BLOCK"
hit "SQLi time-based" "$WAF_URL/?id=1%3B%20SLEEP(5)"                    "BLOCK"
hit "SQLi stacked"    "$WAF_URL/?id=1%3B%20DROP%20TABLE%20users"        "BLOCK"
hit "XSS <script>"    "$WAF_URL/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E" "BLOCK"
hit "XSS javascript:" "$WAF_URL/?to=javascript%3Aalert(1)"              "BLOCK"
hit "CMDi pipe+cmd"   "$WAF_URL/?q=test%7Ccat%20%2Fetc%2Fpasswd"        "BLOCK"
hit "CMDi backtick"   "$WAF_URL/?q=%60whoami%60"                        "BLOCK"
hit "Path multi ../"  "$WAF_URL/?file=..%2F..%2F..%2Fetc%2Fpasswd"      "BLOCK"
hit "Path /etc/passwd" "$WAF_URL/?file=%2Fetc%2Fpasswd"                 "BLOCK"
echo

cyan "=== ALLOW ZONE (clean traffic) ==="
hit "Clean GET"       "$WAF_URL/?page=1&size=10"                        "ALLOW"
hit "Clean search"    "$WAF_URL/?q=hello%20world"                       "ALLOW"
echo

green "Done. Open ${WAF_URL}/dashboard → Logs tab."
echo "Filter Source = 🤖 MODEL to see only ML-decided requests."
