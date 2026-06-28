#!/usr/bin/env python3
"""
Black-box test: the ML gray-zone path.

The rule engine alone is NOT decisive for every request. When a request's rule
score lands in the gray zone [ml.gray_lower, ml.gray_upper) (default [3.0, 5.0))
the WAF consults the DistilBERT ML service for a second opinion. This test
sends a payload engineered to land in that band and proves the request actually
reached the model — i.e. the verdict came from "rule+model", not rules alone.

It contrasts three cases:
  * GRAY  — several weak-signal payloads, rule score in [3,5) -> ML IS consulted
  * HIGH  — a blatant attack, rule score >= 5                 -> rules decide, ML skipped
  * CLEAN — benign, rule score 0                              -> ML skipped

Requires the ML service to be up (make ml-start / make run).

    .venv/bin/python scripts/test_ml_gray_zone.py
    .venv/bin/python scripts/test_ml_gray_zone.py --url http://localhost:8080

Exit code 0 = all assertions passed, 1 = a failure (CI-friendly).
"""

from __future__ import annotations

import argparse
import random
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Gray-zone payloads: a null byte (weak LFI indicator) + one more weak token
# (a stray HTML tag or SQL fragment). Each lands the rule score in [3,5) —
# suspicious but not decisive — so the WAF hands it to the model. The model
# then recognises the real shape (xss / sqli), as noted per line.
GRAY_PAYLOADS = [
    "/?a=%00&b=%3Cb%3Ehi%3C/b%3E",        # <b>hi</b>      -> model: xss
    "/?a=%00&b=%3Ci%3Ex%3C/i%3E",         # <i>x</i>       -> model: xss
    "/?a=%00&b=%3Csvg%3E",                # <svg>          -> model: xss
    "/?a=%00&b=%3Cmarquee%3E",            # <marquee>      -> model: xss
    "/?a=%00&b=%27%20or%20%27",           # ' or '         -> model: sqli
]
# Blatant SQLi: rule score >= 5, the engine blocks outright, ML never called.
HIGH = "/?q=%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
# Clean traffic.
CLEAN = "/?q=apple"

# A real browser-ish request so behaviour/bot scoring doesn't muddy the picture.
BROWSER_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/124.0",
}

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


def send_and_fetch(base: str, admin: str, path: str, ip: str) -> dict:
    """Fire one request at the DATA plane, then pull its access-log row back
    from the CONTROL plane (the /waf-api/* API lives on the admin port)."""
    headers = dict(BROWSER_HEADERS, **{"X-Forwarded-For": ip})
    requests.get(base.rstrip("/") + path, headers=headers,
                 timeout=10, verify=False, allow_redirects=False)
    time.sleep(0.4)  # let the ring buffer settle
    r = requests.get(admin.rstrip("/") + f"/waf-api/logs?ip={ip}&per_page=1",
                     timeout=10, verify=False)
    body = r.json()
    rows = body if isinstance(body, list) else body.get(
        "logs", body.get("entries", body.get("data", [])))
    return rows[0] if rows else {}


def score_of(row: dict):
    return row.get("total_score", row.get("anomaly_score"))


def ml_ok(ml: dict) -> bool:
    """True only when the model actually answered (not a fail-open error)."""
    return bool(ml) and ml.get("called") and not ml.get("error") and bool(ml.get("label"))


def run(base: str, admin: str) -> None:
    print(f"Traffic: {base}   Admin: {admin}\n")

    # Fresh spoofed IPs each run so blocked requests don't accumulate across
    # runs and auto-ban the test IPs (which would skew the rule-vs-ML attribution).
    octet = random.randint(1, 254)
    ip_high, ip_clean = (f"44.{octet}.0.2", f"44.{octet}.0.3")

    print("0) Preconditions — WAF reachable and ML service healthy")
    try:
        ml_health = requests.get("http://127.0.0.1:8000/health", timeout=5).json()
        print(f"   ML /health: {ml_health}")
        check(ml_health.get("status") == "ok", "ML service is up")
    except requests.exceptions.RequestException as e:
        check(False, f"ML service reachable (got {e.__class__.__name__})")
        print("   Hint: start it with  make ml-start  (or  make run)")
        return

    print(f"\n1) GRAY-ZONE — {len(GRAY_PAYLOADS)} payloads rules can't decide, "
          "each must reach the ML service")
    for i, path in enumerate(GRAY_PAYLOADS):
        g = send_and_fetch(base, admin, path, f"44.{octet}.1.{i + 1}")
        ml = g.get("ml") or {}
        print(f"   score={score_of(g)} source={g.get('source')} "
              f"decision={g.get('decision')} ml={ml}")
        ok = (ml_ok(ml)
              and g.get("source") == "rule+model"
              and isinstance(ml.get("confidence"), (int, float))
              and ml["confidence"] > 0)
        conf = round(ml.get("confidence"), 2) if ml.get("confidence") else None
        check(ok, f"reached ML → label={ml.get('label')} conf={conf}  ({path})")

    print("\n2) HIGH-SCORE attack — rules decide alone, ML is skipped")
    h = send_and_fetch(base, admin, HIGH, ip_high)
    hml = h.get("ml")
    print(f"   score={score_of(h)} source={h.get('source')} decision={h.get('decision')} ml={hml}")
    check((score_of(h) or 0) >= 5, "blatant attack scored >= 5 on rules alone")
    check(not (hml and hml.get("called")), "ML was NOT called (rules were decisive)")
    check(h.get("source") == "rule", "verdict attributed to rule only")

    print("\n3) CLEAN traffic — no rule match, ML skipped")
    c = send_and_fetch(base, admin, CLEAN, ip_clean)
    cml = c.get("ml")
    print(f"   score={score_of(c)} source={c.get('source')} decision={c.get('decision')} ml={cml}")
    check((score_of(c) or 0) == 0, "clean request scored 0")
    check(not (cml and cml.get("called")), "ML was NOT called for clean traffic")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ML gray-zone black-box test")
    p.add_argument("--url", default="http://localhost:8081",
                   help="WAF DATA-plane URL — traffic (default: %(default)s)")
    p.add_argument("--admin-url", default="http://localhost:8080",
                   help="WAF CONTROL-plane URL — /waf-api/* (default: %(default)s)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    base = args.url
    admin = args.admin_url
    try:
        requests.get(admin.rstrip("/") + "/waf-api/logs?per_page=1", timeout=5, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error: cannot reach WAF admin API at {admin} ({e.__class__.__name__})")
        return 1

    run(base, admin)

    bar = "-" * 56
    print(f"\n{bar}\nResult: {_passed} passed, {_failed} failed\n{bar}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
