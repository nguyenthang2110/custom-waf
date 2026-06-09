#!/usr/bin/env bash
# scripts/test_waf_rules.sh
#
# E2E sanity check that the rule engine fires for the four headline
# OWASP categories: SQLi, XSS, LFI, RCE. For each, we send a probe URL
# that should trip a known rule, expect HTTP 403, then confirm the
# /waf-api/logs buffer contains a BLOCK row with a matched_rules entry
# from that category.
#
# This is not a coverage test of every rule — it's a smoke test that
# (parse → normalize → engine → decision → audit) is plumbed correctly
# end-to-end. If one category fails, the breakage is upstream of that
# specific rule.
#
# Override defaults via env:
#   WAF_URL=https://127.0.0.1:8443 ./scripts/test_waf_rules.sh
#
# Exit 0 = pass.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

require_curl_jq
require_waf_up

say "Logging in as ${ADMIN_USER}"
waf_login

# Probe URLs are URL-encoded to survive shell + curl quoting consistently.
# Format: CAT|encoded path. Pipe-separated so any whitespace in the path
# survives intact (and we don't have to fight bash word splitting).
declare -a CASES=(
  "SQLI|/shop?id=1%27%20UNION%20SELECT%20null,version()%20--"
  "XSS|/search?q=%3Cscript%3Ealert(1)%3C/script%3E%3Cimg%20src=x%20onerror=alert(1)%3E"
  "LFI|/file?name=..%2F..%2F..%2Fetc%2Fpasswd"
  "RCE|/run?cmd=%3B%20cat%20%2Fetc%2Fpasswd"
)

# ---------- 1. Fire probes ----------
say "Firing probes (each expects HTTP 403)"
for entry in "${CASES[@]}"; do
  cat="${entry%%|*}"
  path="${entry#*|}"
  code="$(curl -sk -o /dev/null -w "%{http_code}" "${WAF_URL}${path}" || true)"
  if [[ "$code" == "403" ]]; then
    pass "${cat}: HTTP ${code} BLOCK"
  else
    fail "${cat}: expected 403, got ${code} (probe: ${path})"
  fi
done

# ---------- 2. Async audit + buffer push ----------
sleep 2

# ---------- 3. Inspect /waf-api/logs ----------
say "Querying /waf-api/logs for BLOCK rows by category"
LOGS_JSON="$(waf_get '/waf-api/logs?per_page=200')"
TOTAL_BLOCKS="$(printf %s "$LOGS_JSON" | jq -r '[.logs[] | select(.decision=="BLOCK")] | length')"
note "total BLOCK rows in buffer: ${TOTAL_BLOCKS}"

# For each category, the engine should have stamped at least one
# matched_rules entry whose ID starts with the WAF-0XX prefix for that
# category (001-007 SQLi, 010-019 XSS, 020-029 LFI/PATH, 030-036 RCE).
# macOS bash is still 3.2 — no associative arrays — so we hard-code the
# 4 pairs inline rather than declare -A.
category_prefix() {
  case "$1" in
    SQLI) printf 'WAF-00[1-7]-SQLI' ;;
    XSS)  printf 'WAF-01[0-9]-XSS'  ;;
    LFI)  printf 'WAF-02[0-9]-LFI'  ;;
    RCE)  printf 'WAF-03[0-6]-RCE'  ;;
    *)    return 1 ;;
  esac
}

for cat in SQLI XSS LFI RCE; do
  pat="$(category_prefix "$cat")"
  count="$(printf %s "$LOGS_JSON" | jq -r --arg pat "$pat" '
    [.logs[]
     | select(.decision == "BLOCK")
     | (.matched_rules // [])
     | .[]
     | (.rule_id // "")
     | select(test($pat))
    ] | length')"
  if [[ "$count" -ge 1 ]]; then
    pass "${cat}: ${count} matched rule hit(s) in log buffer (regex /${pat}/)"
  else
    fail "${cat}: no log row with matched_rules ~ /${pat}/ — engine wiring broken or rule not loaded"
  fi
done

# ---------- 4. Sanity: block_reason filled ----------
# The dashboard renders block_reason on every BLOCK row; we wired the
# field through LogEntry. If it's empty across the board, the wiring
# regressed.
WITH_REASON="$(printf %s "$LOGS_JSON" | jq -r '
  [.logs[] | select(.decision == "BLOCK") | select((.block_reason // "") != "")] | length')"
if [[ "$WITH_REASON" -ge 1 ]]; then
  pass "block_reason populated on at least one BLOCK row (${WITH_REASON} total)"
else
  warn "no BLOCK row carries a block_reason — dashboard may show empty reasons. WAF binary likely stale."
fi

printf "\n${c_green}All WAF rule assertions passed.${c_reset}\n"
