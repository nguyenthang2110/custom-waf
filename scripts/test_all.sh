#!/usr/bin/env bash
# scripts/test_all.sh
#
# Runs every test_* script in this directory, in a sensible order, and
# prints a final pass/fail summary. Exits non-zero if any sub-script
# fails. Useful as a single command for CI.
#
# Each child script handles its own snapshot/restore so a failure
# mid-run leaves the WAF config in its original state.
#
# Override defaults via env:
#   WAF_URL=https://127.0.0.1:8443 ADMIN_USER=admin ADMIN_PASS=admin123 \
#       ./scripts/test_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

require_curl_jq
require_waf_up

TESTS=(
  test_waf_rules.sh
)

declare -a PASSED=()
declare -a FAILED=()

for t in "${TESTS[@]}"; do
  path="${SCRIPT_DIR}/${t}"
  if [[ ! -x "$path" ]]; then
    warn "${t} not executable — skipping"
    continue
  fi

  echo
  printf "${c_blue}══════ %s ══════${c_reset}\n" "$t"
  if "$path"; then
    PASSED+=("$t")
  else
    FAILED+=("$t")
  fi
done

echo
printf "${c_blue}══════ summary ══════${c_reset}\n"
for t in "${PASSED[@]:-}"; do [[ -n "$t" ]] && pass "$t"; done
for t in "${FAILED[@]:-}"; do [[ -n "$t" ]] && printf "${c_red}[FAIL]${c_reset} %s\n" "$t"; done

if [[ ${#FAILED[@]} -gt 0 ]]; then
  printf "\n${c_red}%d test script(s) failed.${c_reset}\n" "${#FAILED[@]}"
  exit 1
fi
printf "\n${c_green}All %d test scripts passed.${c_reset}\n" "${#PASSED[@]}"
