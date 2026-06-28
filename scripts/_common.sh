#!/usr/bin/env bash
# scripts/_common.sh
#
# Shared helpers for the WAF E2E test scripts. Each script sources this
# file at the top and then calls require_curl_jq + waf_login. All scripts
# share the same env-overridable defaults:
#
#   WAF_URL=http://localhost:8080 ADMIN_USER=admin ADMIN_PASS=admin123
#
# Tests assume `make run` (or the WAF binary built from current sources)
# is already serving at WAF_URL.
#
# NOTE: this file is sourced, not executed — don't `set -e` here; let the
# caller decide its own bash flags.

# Defaults — override by exporting before running the test.
WAF_URL="${WAF_URL:-http://localhost:8080}"
ADMIN_USER="${ADMIN_USER:-admin}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"

# Colors. Detached from TTY (e.g. piped to a file) → strip ANSI.
if [[ -t 1 ]]; then
  c_blue='\033[36m'; c_red='\033[31m'; c_green='\033[32m'; c_yellow='\033[33m'; c_dim='\033[2m'; c_reset='\033[0m'
else
  c_blue=''; c_red=''; c_green=''; c_yellow=''; c_dim=''; c_reset=''
fi

say()  { printf "${c_blue}[test]${c_reset} %s\n" "$*"; }
note() { printf "${c_dim}       %s${c_reset}\n" "$*"; }
warn() { printf "${c_yellow}[warn]${c_reset} %s\n" "$*"; }
pass() { printf "${c_green}[PASS]${c_reset} %s\n" "$*"; }
fail() { printf "${c_red}[FAIL]${c_reset} %s\n" "$*" >&2; exit 1; }

require_curl_jq() {
  command -v curl >/dev/null || fail "curl not found"
  command -v jq   >/dev/null || fail "jq not found (brew install jq / apt install jq)"
}

# Make sure the WAF is reachable before kicking off any assertions.
require_waf_up() {
  if ! curl -sk -m 3 -o /dev/null "${WAF_URL}/health"; then
    fail "WAF not reachable at ${WAF_URL} — start it with 'make run' first"
  fi
}

# Logs in and exports TOKEN + AUTH ("Authorization: Bearer ..."). On
# failure prints the server's JSON so the operator can see what blocked
# them (wrong creds, account locked, etc.).
waf_login() {
  local resp
  resp="$(curl -sk -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}" \
    "${WAF_URL}/waf-api/auth/login")" || fail "login request failed"
  TOKEN="$(printf %s "$resp" | jq -r '.token // empty')"
  if [[ -z "$TOKEN" ]]; then
    fail "login failed for ${ADMIN_USER}: ${resp}"
  fi
  AUTH="Authorization: Bearer ${TOKEN}"
  export TOKEN AUTH
}

# Authenticated curl wrappers — uniform across all test scripts.
waf_get()    { curl -sk -H "$AUTH" "${WAF_URL}$1"; }
waf_post()   { curl -sk -X POST   -H "$AUTH" -H "Content-Type: application/json" -d "$2" "${WAF_URL}$1"; }
waf_put()    { curl -sk -X PUT    -H "$AUTH" -H "Content-Type: application/json" -d "$2" "${WAF_URL}$1"; }
waf_delete() { curl -sk -X DELETE -H "$AUTH" -H "Content-Type: application/json" -d "${2:-{}}" "${WAF_URL}$1"; }

# Status-code only — useful when the body isn't interesting.
waf_status() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl -sk -o /dev/null -w "%{http_code}" -X "$method" \
      -H "$AUTH" -H "Content-Type: application/json" \
      -d "$body" "${WAF_URL}${path}"
  else
    curl -sk -o /dev/null -w "%{http_code}" -X "$method" \
      -H "$AUTH" "${WAF_URL}${path}"
  fi
}
