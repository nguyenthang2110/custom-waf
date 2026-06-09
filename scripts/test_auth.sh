#!/usr/bin/env bash
# scripts/test_auth.sh
#
# E2E test for the auth invariants documented in CLAUDE.md:
#
#   1. No client-controlled role on /auth/register — body is forced to viewer.
#   2. Old-password requirement on POST /auth/me/password.
#   3. Self-action protection — admin cannot delete or demote own account.
#   4. Viewer cannot list/create users (admin-gated endpoints).
#
# We don't re-test the DB-level last-admin guard here — Go unit tests
# cover the atomic transaction. We only check the externally-observable
# HTTP behaviour.
#
# Override defaults via env:
#   WAF_URL=https://127.0.0.1:8443 ./scripts/test_auth.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

require_curl_jq
require_waf_up

# Random suffix per run so a failure mid-test doesn't poison reruns.
SUFFIX="$(date +%s)$$"
TEST_USER="qa_${SUFFIX}"
TEST_EMAIL="${TEST_USER}@waf.test"
TEST_PASS="QaPass!12345"
NEW_PASS="QaPass!54321"

CREATED_IDS=()

# Best-effort cleanup — admin-deletes anything we created so reruns are
# idempotent regardless of which assertion failed.
cleanup() {
  local rc=$?
  set +e
  if [[ -n "${TOKEN:-}" ]]; then
    for uid in "${CREATED_IDS[@]:-}"; do
      [[ -z "$uid" ]] && continue
      waf_delete "/waf-api/auth/users/${uid}" >/dev/null 2>&1 \
        && note "Cleaned up user id=${uid}" \
        || warn "Failed to clean up user id=${uid}"
    done
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

# ---------- 0. Admin login ----------
say "Logging in as ${ADMIN_USER}"
waf_login
ADMIN_AUTH="$AUTH"
# Resolve admin's own user id for self-action tests later.
ADMIN_ID="$(waf_get /waf-api/auth/me | jq -r '.user.id // .id // empty')"
[[ -n "$ADMIN_ID" ]] || fail "couldn't resolve admin user id from /auth/me"
note "admin id=${ADMIN_ID}"

# Probe whether auth enforcement is on. When require_auth=false in YAML,
# both requireAuthN and requireAdmin are no-ops — denial assertions don't
# apply. We still validate the register-strips-role invariant because
# that one is enforced at the handler level regardless.
AUTH_PROBE="$(curl -sk -o /dev/null -w "%{http_code}" "${WAF_URL}/waf-api/auth/users")"
if [[ "$AUTH_PROBE" == "200" ]]; then
  AUTH_ENFORCED=0
  warn "require_auth appears disabled in config (anonymous GET /auth/users → 200) — denial assertions will be skipped."
else
  AUTH_ENFORCED=1
  note "auth enforcement active (anonymous GET /auth/users → ${AUTH_PROBE})"
fi

# ---------- 1. /auth/register strips client-set role ----------
say "Registering ${TEST_USER} with explicit \"role\":\"admin\" in body"
REG_RESP="$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"email\":\"${TEST_EMAIL}\",\"password\":\"${TEST_PASS}\",\"role\":\"admin\"}" \
  "${WAF_URL}/waf-api/auth/register")"
RET_ROLE="$(printf %s "$REG_RESP" | jq -r '.user.role // empty')"
RET_ID="$(printf %s "$REG_RESP" | jq -r '.user.id // empty')"
[[ -n "$RET_ID" ]] || fail "register failed: ${REG_RESP}"
CREATED_IDS+=("$RET_ID")

if [[ "$RET_ROLE" == "viewer" ]]; then
  pass "register dropped client-set role (got: viewer, requested: admin) — invariant #1 holds"
else
  fail "register kept role=${RET_ROLE} from request body — privilege escalation hole reopened"
fi

# ---------- 2. New user is actually a viewer per /auth/me ----------
say "Logging in as ${TEST_USER} and reading /auth/me"
USER_LOGIN="$(curl -sk -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"${TEST_USER}\",\"password\":\"${TEST_PASS}\"}" \
  "${WAF_URL}/waf-api/auth/login")"
USER_TOKEN="$(printf %s "$USER_LOGIN" | jq -r '.token // empty')"
[[ -n "$USER_TOKEN" ]] || fail "user login failed: ${USER_LOGIN}"
USER_AUTH="Authorization: Bearer ${USER_TOKEN}"

ME_ROLE="$(curl -sk -H "$USER_AUTH" "${WAF_URL}/waf-api/auth/me" | jq -r '.user.role // .role // empty')"
if [[ "$ME_ROLE" == "viewer" ]]; then
  pass "/auth/me reports role=viewer"
else
  fail "/auth/me reports role=${ME_ROLE} (expected viewer)"
fi

# ---------- 3. Viewer is locked out of admin endpoints ----------
if [[ "$AUTH_ENFORCED" == "1" ]]; then
  say "Viewer attempting GET /waf-api/auth/users (admin-only)"
  CODE="$(curl -sk -o /dev/null -w "%{http_code}" -H "$USER_AUTH" "${WAF_URL}/waf-api/auth/users")"
  if [[ "$CODE" == "403" || "$CODE" == "401" ]]; then
    pass "viewer denied with HTTP ${CODE} on GET /auth/users"
  else
    fail "viewer got HTTP ${CODE} on GET /auth/users — admin gate broken"
  fi
else
  note "skipping viewer-denial test (require_auth=false)"
fi

# ---------- 4. Old-password requirement on password change ----------
# This one runs even with require_auth=false: handleChangeOwnPassword
# resolves the caller via currentUser(r), which is empty when auth is
# disabled, so the handler returns 401 regardless of old_password. We
# only run this when auth is on; with auth off it can't distinguish a
# wrong-password rejection from an unauthenticated rejection.
if [[ "$AUTH_ENFORCED" == "1" ]]; then
  say "Change-password with WRONG old_password (expect 401)"
  WRONG="$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    -H "$USER_AUTH" -H "Content-Type: application/json" \
    -d "{\"old_password\":\"definitely-not-it\",\"new_password\":\"${NEW_PASS}\"}" \
    "${WAF_URL}/waf-api/auth/me/password")"
  if [[ "$WRONG" == "401" ]]; then
    pass "wrong old_password rejected with HTTP 401 — invariant #4 holds"
  else
    fail "wrong old_password returned HTTP ${WRONG} (expected 401) — JWT-only takeover vector reopened"
  fi

  say "Change-password with CORRECT old_password (expect 200)"
  RIGHT="$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    -H "$USER_AUTH" -H "Content-Type: application/json" \
    -d "{\"old_password\":\"${TEST_PASS}\",\"new_password\":\"${NEW_PASS}\"}" \
    "${WAF_URL}/waf-api/auth/me/password")"
  if [[ "$RIGHT" == "200" ]]; then
    pass "correct old_password accepted, password rotated"
  else
    fail "correct old_password returned HTTP ${RIGHT} (expected 200)"
  fi
else
  note "skipping old-password requirement test (require_auth=false makes it indistinguishable)"
fi

# ---------- 5. Admin cannot delete/demote OWN account ----------
# Self-action protection lives in the handler and runs only when there
# IS a known caller. With require_auth=false, currentUser() returns
# empty, the self-check is skipped, and the request would actually
# delete the admin — DO NOT exercise this path or we wipe the only
# admin in dev. Skip the assertion in that mode.
if [[ "$AUTH_ENFORCED" == "1" ]]; then
  say "Admin attempting to delete own account (expect 400)"
  SELF_DEL="$(curl -sk -o /dev/null -w "%{http_code}" -X DELETE \
    -H "$ADMIN_AUTH" "${WAF_URL}/waf-api/auth/users/${ADMIN_ID}")"
  if [[ "$SELF_DEL" == "400" ]]; then
    pass "self-delete blocked with HTTP 400 — invariant #3a holds"
  else
    fail "self-delete returned HTTP ${SELF_DEL} (expected 400)"
  fi

  say "Admin attempting to demote own account to viewer (expect 400 or 409)"
  SELF_DEMOTE="$(curl -sk -o /dev/null -w "%{http_code}" -X PUT \
    -H "$ADMIN_AUTH" -H "Content-Type: application/json" \
    -d '{"role":"viewer"}' \
    "${WAF_URL}/waf-api/auth/users/${ADMIN_ID}")"
  if [[ "$SELF_DEMOTE" == "400" || "$SELF_DEMOTE" == "409" ]]; then
    pass "self-demote blocked with HTTP ${SELF_DEMOTE} — invariant #3b holds"
  else
    fail "self-demote returned HTTP ${SELF_DEMOTE} (expected 400 or 409)"
  fi
else
  note "skipping self-action protection tests (require_auth=false; would actually delete the admin)"
fi

printf "\n${c_green}All auth assertions passed.${c_reset}\n"
