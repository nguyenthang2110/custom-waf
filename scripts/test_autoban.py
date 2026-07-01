#!/usr/bin/env python3
"""
Black-box test: auto-ban → access-control blacklist.

Verifies the end-to-end behaviour wired in the WAF: an IP that sends enough
blocked requests to trip the repeat-offender threshold is automatically added
to the *access-control blacklist* (not just the behaviour detector), which
means every subsequent request — including a clean one and a normally-bypassed
path like /socket.io — is rejected until the ban is lifted.

Run against a live WAF (defaults to the local one):
    .venv/bin/python scripts/test_autoban.py
    .venv/bin/python scripts/test_autoban.py --url http://localhost:8080
    .venv/bin/python scripts/test_autoban.py --tunnel        # via cloudflared
    .venv/bin/python scripts/test_autoban.py --threshold 5   # match config
    .venv/bin/python scripts/test_autoban.py --ban-only      # attack only, leave it BANNED

Exit code 0 = all assertions passed, 1 = a failure (CI-friendly).
"""

from __future__ import annotations

import argparse
import os
import random
import re
import sys
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# A spoofed source IP we drive the whole scenario from. X-Forwarded-For's
# leftmost value is what the WAF treats as the client (and Cloudflare keeps it
# leftmost), so this works through the tunnel too. A fresh random IP each run
# keeps the test isolated from state left over (or DB-restored) from earlier runs.
TEST_IP = f"203.0.113.{random.randint(10, 240)}"
CONTROL_IP = "198.51.100.42"  # innocent IP, never attacked

ATTACK = "/?q=' OR 1=1-- autoban"          # high-score SQLi → always BLOCK
CLEAN = "/?q=apple"                          # benign
BYPASS = "/socket.io/?EIO=4&transport=polling"  # normally bypasses the WAF

DEFAULT_TUNNEL_LOG = "/tmp/cf_tunnel.log"
_TRYCF_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")

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


# --- WAF helpers ----------------------------------------------------------

def get(base: str, path: str, ip: str) -> int:
    r = requests.get(base.rstrip("/") + path,
                     headers={"X-Forwarded-For": ip, "User-Agent": "autoban-test/1.0"},
                     timeout=10, verify=False, allow_redirects=False)
    return r.status_code


# The admin API (/waf-api/*) lives on the CONTROL-plane port (admin.listen,
# default :8080), separate from the DATA-plane port that carries attack traffic
# (server.listen, default :8081). So these helpers take the admin base URL.

def login(admin: str, user: str, pwd: str) -> str:
    """Return a JWT for the admin API, or "" if auth is disabled / login fails.
    Mutating endpoints like /ips/unblock require an admin token when
    require_auth=true; read-only GETs don't."""
    try:
        r = requests.post(admin.rstrip("/") + "/waf-api/auth/login",
                          json={"username": user, "password": pwd},
                          timeout=10, verify=False)
        return r.json().get("token", "") if r.ok else ""
    except (requests.exceptions.RequestException, ValueError):
        return ""


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"} if token else {}


def blacklist_ips(admin: str, token: str = "") -> list:
    r = requests.get(admin.rstrip("/") + "/waf-api/blacklist",
                     headers=_auth(token), timeout=10, verify=False)
    return r.json().get("ips", [])


def unblock(admin: str, ip: str, token: str = "") -> None:
    requests.post(admin.rstrip("/") + "/waf-api/ips/unblock",
                  json={"ip": ip}, headers=_auth(token), timeout=10, verify=False)


def discover_tunnel_url(log_path: str):
    env = os.environ.get("WAF_TUNNEL_URL")
    if env:
        return env.rstrip("/")
    try:
        with open(log_path, encoding="utf-8", errors="ignore") as fh:
            m = _TRYCF_RE.findall(fh.read())
        return m[-1].rstrip("/") if m else None
    except OSError:
        return None


# --- Scenario -------------------------------------------------------------

def run(base: str, admin: str, token: str, threshold: int, ban_only: bool) -> None:
    ip = TEST_IP
    print(f"Traffic: {base}   Admin: {admin}{'  (authed)' if token else ''}")
    print(f"Test IP: {ip}   (threshold {threshold})\n")

    # Clean slate so the run is repeatable (settle so the unblock lands before
    # we assert the baseline).
    unblock(admin, ip, token)
    time.sleep(0.3)

    print("1) Baseline — IP must start OFF the blacklist")
    check(ip not in blacklist_ips(admin, token), f"{ip} not blacklisted initially")

    print(f"\n2) Fire {threshold} blocked attacks to trip the auto-ban")
    codes = [get(base, ATTACK, ip) for _ in range(threshold)]
    print(f"   attack codes: {codes}")
    check(all(c == 403 for c in codes), "every attack was blocked (403)")

    print("\n3) The ban must be promoted into the access-control blacklist")
    bl = blacklist_ips(admin, token)
    check(ip in bl, f"{ip} now appears in /waf-api/blacklist")

    if ban_only:
        # Stop here and LEAVE the IP banned so you can inspect it on the
        # dashboard and unblock it yourself.
        print("\n--ban-only: stopping after the attack; IP is left BANNED.")
        print(f"  Blacklist now: {blacklist_ips(admin, token)}")
        print("  Unblock it yourself when ready:")
        print("    - Dashboard → IP Management → Unblock, or")
        print(f"    - curl -s -X POST {admin.rstrip('/')}/waf-api/ips/unblock "
              f"-H 'Content-Type: application/json' -d '{{\"ip\":\"{ip}\"}}'")
        return

    print("\n4) Ban must cover EVERY path, not just attacks")
    clean_code = get(base, CLEAN, ip)
    bypass_code = get(base, BYPASS, ip)
    print(f"   clean {CLEAN} -> {clean_code} | bypass {BYPASS} -> {bypass_code}")
    check(clean_code == 403, "a CLEAN request from the banned IP is blocked (403)")
    check(bypass_code == 403, "a normally-bypassed path (/socket.io) is blocked (403)")

    print("\n5) Unblock must clear BOTH layers")
    unblock(admin, ip, token)
    check(ip not in blacklist_ips(admin, token), f"{ip} removed from blacklist after unblock")
    check(get(base, BYPASS, ip) == 200, "/socket.io reachable again after unblock")

    # A control IP that never attacked must be unaffected throughout.
    print("\n6) Control — an innocent IP is never banned")
    check(get(base, CLEAN, CONTROL_IP) in (200, 404, 500),
          "innocent IP passes the WAF (reaches backend)")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Auto-ban → blacklist black-box test")
    p.add_argument("--url", default="http://localhost:8081",
                   help="WAF DATA-plane URL — protected traffic (default: %(default)s)")
    p.add_argument("--admin-url", default="http://localhost:8080",
                   help="WAF CONTROL-plane URL — /waf-api/* (default: %(default)s)")
    p.add_argument("--tunnel", action="store_true",
                   help="Target the public Cloudflare tunnel (auto-discovered)")
    p.add_argument("--tunnel-log", default=DEFAULT_TUNNEL_LOG)
    p.add_argument("--user", default="admin", help="admin username for the API (default: admin)")
    p.add_argument("--password", default="admin", help="admin password (default: admin)")
    p.add_argument("--threshold", type=int, default=5,
                   help="bruteforce_threshold from config (default: %(default)s)")
    p.add_argument("--ban-only", action="store_true",
                   help="Stop after the attack and LEAVE the IP banned "
                        "(unblock it yourself); skips the auto-unblock step")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    base = args.url
    admin = args.admin_url
    if args.tunnel:
        # The tunnel exposes only the DATA plane; admin stays local.
        base = discover_tunnel_url(args.tunnel_log)
        if not base:
            print("Error: --tunnel set but no tunnel URL found "
                  "(start cloudflared or set $WAF_TUNNEL_URL)")
            return 1

    try:
        requests.get(admin.rstrip("/") + "/waf-api/blacklist", timeout=5, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"Error: cannot reach WAF admin API at {admin} ({e.__class__.__name__})")
        print("Hint: is the WAF running and is this host inside admin.allowed_cidrs?")
        return 1

    # Mutating admin endpoints (/ips/unblock) need a JWT when require_auth=true.
    # Try the given password, then the well-known bootstrap defaults so this
    # works on both a fresh DB (admin/admin) and the legacy dev seed (admin123).
    token = ""
    for pw in [args.password, "admin", "admin123"]:
        token = login(admin, args.user, pw)
        if token:
            break
    if not token:
        print(f"Note: no admin token ({args.user}) — fine if require_auth=false, "
              "else the unblock step will fail. Pass --password if it differs.")

    run(base, admin, token, args.threshold, args.ban_only)

    bar = "-" * 52
    print(f"\n{bar}\nResult: {_passed} passed, {_failed} failed\n{bar}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
