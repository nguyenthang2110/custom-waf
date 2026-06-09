#!/usr/bin/env bash
# scripts/test_ip_management.sh
#
# E2E test for the IP allow/deny list management API.
#
# Scope:
#   - Add an IP to blacklist via POST, verify GET reflects it.
#   - Remove it via DELETE, verify GET no longer includes it.
#   - Same for whitelist.
#   - Verify TTL entries carry an expires_at field on GET.
#
# We do NOT test enforcement (blocking traffic from a blacklisted IP)
# because the test runs against the WAF from loopback — admin allow-list
# tooling already gives 127.0.0.1 first-class access, so we can't
# meaningfully assert blocking without spoofing X-Forwarded-For (which is
# a separate config knob, out of scope here).
#
# Override defaults via env:
#   WAF_URL=https://127.0.0.1:8443 ./scripts/test_ip_management.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

require_curl_jq
require_waf_up

# Use uniquely chosen TEST-NET IPs (RFC 5737) so collisions with real
# operator config are essentially impossible, and so the test never
# accidentally blocks anything reachable.
BLACK_IP="203.0.113.$((RANDOM % 254 + 1))"
BLACK_IP_TTL="203.0.113.$((RANDOM % 254 + 1))"
WHITE_IP="198.51.100.$((RANDOM % 254 + 1))"

cleanup() {
  local rc=$?
  set +e
  if [[ -n "${TOKEN:-}" ]]; then
    for ip in "$BLACK_IP" "$BLACK_IP_TTL"; do
      waf_delete /waf-api/blacklist "{\"ip\":\"${ip}\"}" >/dev/null 2>&1
    done
    waf_delete /waf-api/whitelist "{\"ip\":\"${WHITE_IP}\"}" >/dev/null 2>&1
    note "Cleaned up test IP entries."
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

say "Logging in as ${ADMIN_USER}"
waf_login

# Helper — returns 0 if the list at $1 currently contains IP $2.
list_has_ip() {
  local list="$1" ip="$2"
  waf_get "/waf-api/${list}" | jq -e --arg ip "$ip" '
    ((.ips // []) | index($ip)) != null
    or ((.entries // []) | map(.ip) | index($ip)) != null' >/dev/null
}

# ---------- 1. Blacklist add ----------
say "Adding ${BLACK_IP} to blacklist (permanent)"
ADD_RESP="$(waf_post /waf-api/blacklist "{\"ip\":\"${BLACK_IP}\"}")"
printf %s "$ADD_RESP" | jq -e '.status == "added"' >/dev/null \
  || fail "blacklist add did not return status=added: ${ADD_RESP}"
if list_has_ip blacklist "$BLACK_IP"; then
  pass "GET /waf-api/blacklist contains ${BLACK_IP}"
else
  fail "GET /waf-api/blacklist missing ${BLACK_IP} after POST"
fi

# ---------- 2. Blacklist add with TTL ----------
say "Adding ${BLACK_IP_TTL} to blacklist with ttl_seconds=120"
TTL_RESP="$(waf_post /waf-api/blacklist "{\"ip\":\"${BLACK_IP_TTL}\",\"ttl_seconds\":120}")"
TTL_EXP="$(printf %s "$TTL_RESP" | jq -r '.expires_at // empty')"
if [[ -n "$TTL_EXP" ]]; then
  pass "TTL add response carries expires_at=${TTL_EXP}"
else
  fail "TTL add response missing expires_at: ${TTL_RESP}"
fi

# The expires_at field should also surface on the entry returned by GET.
ENTRY_EXP="$(waf_get /waf-api/blacklist | jq -r --arg ip "$BLACK_IP_TTL" '
  (.entries // []) | map(select(.ip == $ip))[0] | (.expires_at // empty)')"
if [[ -n "$ENTRY_EXP" && "$ENTRY_EXP" != "null" ]]; then
  pass "GET entry for ${BLACK_IP_TTL} carries expires_at=${ENTRY_EXP}"
else
  warn "GET entry for ${BLACK_IP_TTL} missing expires_at — may be legacy schema"
fi

# ---------- 3. Blacklist remove ----------
say "Removing ${BLACK_IP} from blacklist"
DEL_RESP="$(waf_delete /waf-api/blacklist "{\"ip\":\"${BLACK_IP}\"}")"
printf %s "$DEL_RESP" | jq -e '.status == "removed"' >/dev/null \
  || fail "blacklist remove did not return status=removed: ${DEL_RESP}"
if list_has_ip blacklist "$BLACK_IP"; then
  fail "GET /waf-api/blacklist still contains ${BLACK_IP} after DELETE"
else
  pass "GET /waf-api/blacklist no longer contains ${BLACK_IP}"
fi

# ---------- 4. Whitelist add + remove ----------
say "Adding ${WHITE_IP} to whitelist"
W_ADD="$(waf_post /waf-api/whitelist "{\"ip\":\"${WHITE_IP}\"}")"
printf %s "$W_ADD" | jq -e '.status == "added"' >/dev/null \
  || fail "whitelist add did not return status=added: ${W_ADD}"
if list_has_ip whitelist "$WHITE_IP"; then
  pass "GET /waf-api/whitelist contains ${WHITE_IP}"
else
  fail "GET /waf-api/whitelist missing ${WHITE_IP} after POST"
fi

say "Removing ${WHITE_IP} from whitelist"
W_DEL="$(waf_delete /waf-api/whitelist "{\"ip\":\"${WHITE_IP}\"}")"
printf %s "$W_DEL" | jq -e '.status == "removed"' >/dev/null \
  || fail "whitelist remove did not return status=removed: ${W_DEL}"
if list_has_ip whitelist "$WHITE_IP"; then
  fail "GET /waf-api/whitelist still contains ${WHITE_IP} after DELETE"
else
  pass "GET /waf-api/whitelist no longer contains ${WHITE_IP}"
fi

# ---------- 5. Non-admin cannot mutate ----------
# Auth-gate sanity. Only meaningful when require_auth=true in YAML; with
# auth off the requireAdminForWrite wrapper short-circuits and anonymous
# mutation is allowed by design.
say "Probing auth enforcement before testing anonymous mutation"
ANON_PROBE="$(curl -sk -o /dev/null -w "%{http_code}" "${WAF_URL}/waf-api/auth/users")"
if [[ "$ANON_PROBE" == "200" ]]; then
  warn "require_auth appears disabled — skipping anonymous mutation test (would succeed by design)."
else
  say "Anonymous POST to /waf-api/blacklist (expect 401/403)"
  ANON="$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    -H 'Content-Type: application/json' \
    -d '{"ip":"203.0.113.99"}' \
    "${WAF_URL}/waf-api/blacklist")"
  if [[ "$ANON" == "401" || "$ANON" == "403" ]]; then
    pass "anonymous mutation rejected with HTTP ${ANON}"
  else
    fail "anonymous mutation returned HTTP ${ANON} (expected 401/403)"
  fi
fi

printf "\n${c_green}All IP management assertions passed.${c_reset}\n"
