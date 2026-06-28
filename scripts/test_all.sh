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
#   WAF_URL=http://127.0.0.1:8080 ADMIN_USER=admin ADMIN_PASS=admin \
#       ./scripts/test_all.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./_common.sh
source "${SCRIPT_DIR}/_common.sh"

require_curl_jq
require_waf_up

# Python black-box tests need `requests`; prefer the repo venv.
PYTHON="${SCRIPT_DIR}/../.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="python3"

# WAF base URL passed to most Python tests via --url (default: local HTTP WAF).
WAF_BASE="${WAF_URL:-http://localhost:8080}"
# ML service URL — the pure-model test talks straight to :8000 (no WAF).
ML_BASE="${ML_URL:-http://127.0.0.1:8000}"

TESTS=(
  test_ml_service.py
  test_autoban.py
  test_ml_gray_zone.py
)

declare -a PASSED=()
declare -a FAILED=()

for t in "${TESTS[@]}"; do
  path="${SCRIPT_DIR}/${t}"
  if [[ ! -f "$path" ]]; then
    warn "${t} not found — skipping"
    continue
  fi

  # .py tests run through the venv interpreter; bash tests run directly.
  # The pure-model test targets the ML service (:8000); the rest hit the WAF.
  if [[ "$t" == *.py ]]; then
    if [[ "$t" == "test_ml_service.py" ]]; then
      runner=("$PYTHON" "$path" --url "$ML_BASE")
    else
      runner=("$PYTHON" "$path" --url "$WAF_BASE")
    fi
  elif [[ -x "$path" ]]; then
    runner=("$path")
  else
    warn "${t} not executable — skipping"
    continue
  fi

  echo
  printf "${c_blue}══════ %s ══════${c_reset}\n" "$t"
  if "${runner[@]}"; then
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
