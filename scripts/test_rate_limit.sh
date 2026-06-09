#!/usr/bin/env bash
# scripts/test_rate_limit.sh
#
# E2E test for the opt-in rate-limit feature.
#
# Invariant under test: paths NOT listed in endpoint_limits are never
# rate-limited; paths that ARE listed enforce per-IP token-bucket limits.
#
# Flow:
#   1. Login as admin.
#   2. Snapshot current WAF config (decision + rate_limit); restore on exit.
#   3. Verify an unconfigured probe path returns NOT 429 even on a burst.
#   4. POST endpoint_limit for a subtree (rpm=10, burst=2).
#   5. Fire 6 quick requests; expect ≥4 to be 429 (burst=2 used, rest blocked).
#   6. Remove the endpoint_limit.
#   7. Verify the path is unlimited again.
#
# We don't assert "first 2 = 200" because the upstream service may be
# down — the WAF would proxy and the upstream returns 502/504. What we
# CAN assert is the 429 vs non-429 split.
#
# Override defaults via env:
#   WAF_URL=https://127.0.0.1:8443 ./scripts/test_rate_limit.sh
#
# Exit 0 = pass.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

# Unique enough that the subtree key doesn't collide with anything an
# operator might already have configured. The trailing slash makes it a
# subtree match in the rate limiter.
PROBE_BASE="/__rl_test_$$"
PROBE_KEY="${PROBE_BASE}/"

TMP_DIR="$(mktemp -d -t waf-rl-XXXXXX)"
ORIG_CFG="${TMP_DIR}/cfg.json"

cleanup() {
  local rc=$?
  set +e
  if [[ -n "${TOKEN:-}" && -s "$ORIG_CFG" ]]; then
    # Echo the snapshotted decision + rate_limit back to clear our key
    # and restore whatever was there before.
    local restore; restore="$(jq '{decision: .decision, rate_limit: .rate_limit}' "$ORIG_CFG")"
    if waf_post /waf-api/config "$restore" >/dev/null 2>&1; then
      note "Restored original WAF config."
    else
      warn "Failed to restore WAF config — inspect ${ORIG_CFG}"
    fi
  fi
  rm -rf "$TMP_DIR"
  exit $rc
}
trap cleanup EXIT INT TERM

require_curl_jq
require_waf_up

say "Logging in as ${ADMIN_USER}"
waf_login

# ---------- 1. Snapshot ----------
say "Snapshotting current WAF config"
waf_get /waf-api/config > "$ORIG_CFG"
[[ -s "$ORIG_CFG" ]] || fail "couldn't read /waf-api/config"

# Quick burst probe — counts how many of N requests came back 429.
burst_count_429() {
  local path="$1" n="${2:-6}" code count=0
  for i in $(seq 1 "$n"); do
    code="$(curl -sk -o /dev/null -w "%{http_code}" "${WAF_URL}${path}${i}" || true)"
    [[ "$code" == "429" ]] && count=$((count+1))
  done
  printf '%d' "$count"
}

# ---------- 2. Baseline: unconfigured path → no 429 ----------
say "Baseline: probing unconfigured ${PROBE_BASE}/a (expect zero 429s)"
BASELINE_429=$(burst_count_429 "${PROBE_BASE}/a" 6)
if [[ "$BASELINE_429" -eq 0 ]]; then
  pass "unconfigured path is not rate-limited (0/6 returned 429)"
else
  fail "unconfigured path emitted ${BASELINE_429}/6 429s — opt-in invariant broken"
fi

# ---------- 3. Configure tight limit on the subtree ----------
say "Adding endpoint_limit ${PROBE_KEY} rpm=10 burst=2"
NEW_CFG="$(jq \
  --arg key "$PROBE_KEY" \
  '.decision as $d
   | .rate_limit as $rl
   | {
       decision: $d,
       rate_limit: ($rl + {
         endpoint_limits: (($rl.endpoint_limits // {}) + {($key): {requests_per_min: 10, burst_size: 2}})
       })
     }' "$ORIG_CFG")"
SAVE_RESP="$(waf_post /waf-api/config "$NEW_CFG")"
printf %s "$SAVE_RESP" | jq -e '.success == true' >/dev/null \
  || fail "failed to POST endpoint_limit: ${SAVE_RESP}"

# Confirm the server actually accepted the key.
waf_get /waf-api/config | jq -e --arg k "$PROBE_KEY" '.rate_limit.endpoint_limits[$k]' >/dev/null \
  || fail "endpoint_limit ${PROBE_KEY} not present in fresh GET"

# Give the rate-limiter a beat to settle the new config.
sleep 0.5

# ---------- 4. Burst test ----------
say "Probing ${PROBE_BASE}/b...g (burst=2, expect ≥4 of 6 to be 429)"
LIMITED_429=$(burst_count_429 "${PROBE_BASE}/probe" 6)
if [[ "$LIMITED_429" -ge 4 ]]; then
  pass "limited path returned ${LIMITED_429}/6 429s (burst used up, rest dropped)"
else
  fail "limited path returned only ${LIMITED_429}/6 429s — rate limiter not enforcing"
fi

# ---------- 5. Remove the limit ----------
say "Removing endpoint_limit ${PROBE_KEY}"
CLEAR_CFG="$(jq '{decision: .decision, rate_limit: .rate_limit}' "$ORIG_CFG")"
waf_post /waf-api/config "$CLEAR_CFG" | jq -e '.success == true' >/dev/null \
  || fail "couldn't restore original config to clear the limit"

# Give the token bucket time to expire / config flip to settle.
sleep 2

# ---------- 6. Verify path is unlimited again ----------
# Use a fresh subpath so any leftover bucket from step 4 doesn't cloud
# the read.
say "Re-probing ${PROBE_BASE}/cleared/a (expect zero 429s after removal)"
POST_429=$(burst_count_429 "${PROBE_BASE}/cleared/a" 6)
if [[ "$POST_429" -eq 0 ]]; then
  pass "path is no longer rate-limited after removal (0/6 returned 429)"
else
  fail "path still returning ${POST_429}/6 429s after removal — config change didn't take"
fi

printf "\n${c_green}All rate-limit assertions passed.${c_reset}\n"
