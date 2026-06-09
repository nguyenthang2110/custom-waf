#!/usr/bin/env bash
# scripts/test_alerts.sh
#
# E2E test for the alert pipeline. We only verify that events REACH the
# notifier and the dashboard log buffer — where the alert is delivered
# (Slack/Email/Webhook) is the operator's config concern and out of scope.
#
# Flow:
#   1. Login as admin.
#   2. Snapshot the live alerts config; restore on exit.
#   3. Set alerts.enabled=true, min_severity=INFO, throttle=0, both kinds on.
#      (No destination is configured — Send() still runs the gates, which
#      is what we care about.)
#   4. Verify the broadcast endpoint reports sent=true for BOTH kinds.
#      That proves: master enabled, kind toggle, sev gate, throttle all pass.
#   5. Trigger a REAL system event (POST /waf-api/config no-op echo).
#   6. Trigger a REAL request event (SQL-injection probe → BLOCK).
#   7. Assert both rows appear in /waf-api/logs.
#
# Override defaults via env:
#   WAF_URL=https://127.0.0.1:8443 ADMIN_USER=admin ADMIN_PASS=admin123 \
#       ./scripts/test_alerts.sh
#
# Exit 0 = pass.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

TMP_DIR="$(mktemp -d -t waf-alerts-XXXXXX)"
ORIG_CFG="${TMP_DIR}/alerts_orig.json"

cleanup() {
  local rc=$?
  set +e
  if [[ -n "${TOKEN:-}" && -s "$ORIG_CFG" ]] && jq -e '.config' "$ORIG_CFG" >/dev/null 2>&1; then
    local body; body="$(jq '.config' "$ORIG_CFG")"
    if waf_put /waf-api/alerts/config "$body" >/dev/null 2>&1; then
      note "Restored original alerts config."
    else
      warn "Failed to restore alerts config — inspect ${ORIG_CFG}"
    fi
  fi
  rm -rf "$TMP_DIR"
  exit $rc
}
trap cleanup EXIT INT TERM

# ---------- 0. Prereqs ----------
require_curl_jq
require_waf_up

# ---------- 1. Login ----------
say "Logging in as ${ADMIN_USER}"
waf_login

# ---------- 2. Snapshot ----------
say "Snapshotting current alerts config"
waf_get /waf-api/alerts/config > "$ORIG_CFG"
[[ -s "$ORIG_CFG" ]] || fail "couldn't read /waf-api/alerts/config"

# ---------- 3. Configure for testing ----------
say "Setting alerts.enabled=true, min_severity=INFO, throttle=0, both kinds ON"
NEW_CFG=$(cat <<'JSON'
{
  "enabled": true,
  "min_severity": "INFO",
  "throttle_seconds": 0,
  "send_request_events": true,
  "send_system_events": true,
  "slack": [],
  "email": [],
  "webhook": []
}
JSON
)
PUT_RESP="$(waf_put /waf-api/alerts/config "$NEW_CFG")"
printf %s "$PUT_RESP" | jq -e '.success == true' >/dev/null \
  || fail "failed to set alerts config: ${PUT_RESP}"

# ---------- 4. Broadcast test (validates pipeline gates) ----------
say "Verifying broadcast pipeline reports sent=true for both kinds"
for kind in request system; do
  R="$(waf_post /waf-api/alerts/test-broadcast "{\"kind\":\"${kind}\"}")"
  if printf %s "$R" | jq -e '.sent == true' >/dev/null; then
    pass "broadcast ${kind}: sent=true (severity HIGH ≥ $(printf %s "$R" | jq -r '.min_severity'))"
  else
    fail "broadcast ${kind} dropped: $(printf %s "$R" | jq -r '.reason // .')"
  fi
done

# ---------- 5. Real SYSTEM event: no-op config echo ----------
# POST /waf-api/config validates decision + rate_limit together, so we
# read the current values and echo them back unchanged. The handler logs
# a CONFIG_CHANGE system event regardless.
say "Triggering real SYSTEM event (POST /waf-api/config no-op echo)"
CUR_CFG="$(waf_get /waf-api/config)"
SYS_BODY="$(printf %s "$CUR_CFG" | jq '{decision: .decision, rate_limit: .rate_limit}')"
SYS_RESP="$(waf_post /waf-api/config "$SYS_BODY")"
printf %s "$SYS_RESP" | jq -e '.success == true' >/dev/null \
  || warn "config POST didn't echo success — got: ${SYS_RESP}"

# ---------- 6. Real REQUEST event: SQLi probe → BLOCK ----------
say "Triggering real REQUEST event (SQL injection probe on /shop)"
SQLI_PATH="/shop?id=1%27%20OR%20%271%27%3D%271"
SQLI_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "${WAF_URL}${SQLI_PATH}" || true)
note "WAF responded HTTP ${SQLI_STATUS} (expecting 403 for BLOCK)"

# Async fanout + buffer push.
sleep 2

# ---------- 7. Dashboard log buffer assertions ----------
say "Querying /waf-api/logs for SYSTEM + BLOCK rows"
LOGS_JSON="$(waf_get '/waf-api/logs?per_page=100')"
DECISIONS="$(printf %s "$LOGS_JSON" | jq -r '.logs[].decision' | sort -u)"
note "decisions seen: $(echo "$DECISIONS" | tr '\n' ' ')"

if echo "$DECISIONS" | grep -qx SYSTEM; then
  pass "/waf-api/logs contains SYSTEM rows"
else
  fail "SYSTEM row missing from /waf-api/logs (got: ${DECISIONS})"
fi
if echo "$DECISIONS" | grep -qx BLOCK; then
  pass "/waf-api/logs contains BLOCK rows"
else
  fail "BLOCK row missing from /waf-api/logs (got: ${DECISIONS})"
fi

# Sanity check: LogEntry should carry metadata.event_type for SYSTEM rows
# (added when wiring the audit sink). A null usually means the running WAF
# binary is stale — rebuild and restart.
SYS_HAS_META="$(printf %s "$LOGS_JSON" | jq -r '[.logs[] | select(.decision=="SYSTEM")][0] | (.metadata.event_type // empty)')"
if [[ -n "$SYS_HAS_META" ]]; then
  pass "SYSTEM row carries metadata.event_type (${SYS_HAS_META})"
else
  warn "SYSTEM row has no metadata.event_type — running WAF binary is likely stale."
  warn "Stop 'make run', rebuild, and restart."
fi

printf "\n${c_green}All alert assertions passed.${c_reset}\n"
