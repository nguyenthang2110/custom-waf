#!/usr/bin/env bash
# Trigger IP status values on a running WAF and verify via /waf-api/ips.
#
# Status priority (web/index.html: statusPill):
#   1. is_blocked         -> "blocked"    (red)
#   2. blocked_requests>0 -> "warning"    (orange)
#   3. is_suspicious      -> "suspicious" (yellow)
#   4. else                -> "normal"    (green)
#
# IMPORTANT: "blocked" is UNREACHABLE in current codebase.
# rateLimiter.IsClientBlocked checks `tokens < 0`, but no code path drives
# tokens negative — BlockClient() exists but is never invoked. Documented
# in the verify output.

set -u
BASE="https://127.0.0.1:8443"
CURL="curl -sk --max-time 5 -o /dev/null -w %{http_code}"

# Fresh synthetic client IPs per run (avoid contamination from prior runs).
IP_NORMAL="203.0.113.50"
IP_WARN="203.0.113.51"
IP_SUSP="203.0.113.52"
IP_BLOCKED="203.0.113.53"   # informational only

cyan()  { printf "\033[1;36m%s\033[0m\n" "$*"; }
dim()   { printf "\033[2m%s\033[0m\n" "$*"; }

cyan "=== Scenario 1: NORMAL (${IP_NORMAL}) ==="
dim  "       Chrome UA + Accept-Language, clean paths, no payloads."
for path in / /products /about; do
  code=$($CURL -H "X-Forwarded-For: ${IP_NORMAL}" \
    -H "Accept-Language: en-US,en;q=0.9" \
    -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36" \
    "${BASE}${path}")
  echo "  GET ${path} -> ${code}"
done

echo
cyan "=== Scenario 2: WARNING (${IP_WARN}) ==="
dim  "       1-2 SQLi payloads → WAF rule BLOCK → blocked_requests>0,"
dim  "       but < bruteforce_threshold(5) so behavior detector won't escalate."
for q in "id=1' OR '1'='1" "user=admin' UNION SELECT NULL--"; do
  code=$($CURL -H "X-Forwarded-For: ${IP_WARN}" \
    -H "Accept-Language: en-US" \
    -A "Mozilla/5.0 Chrome/120" \
    -G --data-urlencode "${q}" "${BASE}/products")
  echo "  GET /products?${q} -> ${code}"
done

echo
cyan "=== Scenario 3: SUSPICIOUS (${IP_SUSP}) ==="
dim  "       UA 'curl' = in behavior scanner-list BUT NOT in rule scanner-list"
dim  "       (so WAF won't block) + 25 unique paths >threshold(20) → susp 0.7"
for i in $(seq 1 25); do
  code=$($CURL -H "X-Forwarded-For: ${IP_SUSP}" \
    -H "Accept-Language: en-US" \
    -A "curl/8.4.0" \
    "${BASE}/recon-path-${i}")
  printf "."
done
echo " (25 paths sent, last code=${code})"

echo
cyan "=== Scenario 4: BLOCKED (${IP_BLOCKED}) ==="
dim  "       Send 6 SQLi payloads (>=bruteforce_threshold=5). Each WAF-blocks,"
dim  "       behavior detector's checkBruteForce escalates: stats.isBlocked=true"
dim  "       + 10-minute temp block. Dashboard then surfaces is_blocked=true."
for i in 1 2 3 4 5 6; do
  code=$($CURL -H "X-Forwarded-For: ${IP_BLOCKED}" \
    -H "Accept-Language: en-US" \
    -A "Mozilla/5.0 Chrome/120" \
    -G --data-urlencode "id=${i}' OR '1'='1" "${BASE}/products")
  echo "  attempt #${i} -> ${code}"
done

echo
sleep 1

cyan "=== Verify: GET /waf-api/ips ==="
# Save the curl output to a tmp file so the python heredoc can read it
# without the heredoc replacing stdin and dropping the pipe.
TMP=$(mktemp)
curl -sk "${BASE}/waf-api/ips" > "$TMP"

python3 - "$TMP" <<'PY'
import json, sys, os
ips = json.load(open(sys.argv[1]))

TARGETS = [
    ("203.0.113.50", "normal",     "reachable"),
    ("203.0.113.51", "warning",    "reachable"),
    ("203.0.113.52", "suspicious", "reachable"),
    ("203.0.113.53", "blocked",    "reachable"),
]

def status(ip):
    if ip["is_blocked"]:              return "blocked"
    if ip["blocked_requests"] > 0:    return "warning"
    if ip["is_suspicious"]:           return "suspicious"
    return "normal"

GREEN = "\033[32m"; RED = "\033[31m"; YELLOW = "\033[33m"; RESET = "\033[0m"; DIM = "\033[2m"

print(f"\n{'IP':<18s} {'expected':<12s} {'actual':<12s} {'req':>5s} {'blk':>5s} "
      f"{'susp':>6s} {'is_blk':>7s} {'is_susp':>8s}  {'attacks':<22s}  result")
print("-" * 132)

found = {ip["ip"]: ip for ip in ips}
results = {"PASS": 0, "FAIL": 0, "WAF-BUG": 0}
for tip, exp, reachable in TARGETS:
    if tip not in found:
        print(f"{tip:<18s} {exp:<12s} {DIM}(no traffic){RESET}")
        continue
    ip = found[tip]
    actual = status(ip)
    attacks = ",".join(ip.get("detected_attacks") or []) or "—"

    if reachable != "reachable":
        color, mark = YELLOW, "WAF-BUG"
    elif actual == exp:
        color, mark = GREEN, "PASS"
    else:
        color, mark = RED, "FAIL"
    results[mark] += 1

    print(f"{ip['ip']:<18s} {exp:<12s} {color}{actual:<12s}{RESET} "
          f"{ip['total_requests']:>5d} {ip['blocked_requests']:>5d} "
          f"{ip['suspicion_score']:>6.2f} {str(ip['is_blocked']):>7s} {str(ip['is_suspicious']):>8s}  "
          f"{attacks:<22s}  {color}[{mark}]{RESET}")

print()
total = results["PASS"] + results["FAIL"] + results["WAF-BUG"]
print(f"  PASS:    {results['PASS']}/{total}")
if results["FAIL"]:
    print(f"  FAIL:    {results['FAIL']}/{total}")
if results["WAF-BUG"]:
    print(f"  WAF-BUG: {results['WAF-BUG']}/{total}")
print()
print(f"{DIM}Total IPs in tracker: {len(ips)}{RESET}")
PY

rm -f "$TMP"
