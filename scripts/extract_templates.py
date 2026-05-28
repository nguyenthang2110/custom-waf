#!/usr/bin/env python3
"""
extract_templates.py — convert WAF training log → canonical templates.jsonl

USE CASE
========
The ML training pipeline (in a separate folder) needs realistic "template"
requests to inject attack payloads into. Synthetic templates with a random
pool of 8 hosts / 12 paths cause the model to learn artifacts. Real
templates from production traffic give a natural distribution of Host /
Path / User-Agent / Method / Content-Type.

This script reads `logs/waf/training-YYYY-MM-DD.jsonl` (one record per
captured request) and emits `templates.jsonl` — one JSON line per unique
benign request, in the SAME canonical format the WAF sends to /predict.

The trainer side picks a template, injects a payload into query / path /
body / header, and outputs the result as a labeled attack sample. The
distribution of Host, UA, Path stays anchored in reality.

LOG RECORD INPUT
================
Each line in `training-*.jsonl` is a JSON object with these fields:

    {
      "ts": "2026-05-14T22:41:48+07:00",
      "label": "allow" | "block",
      "decision": "ALLOW" | "BLOCK" | "CHALLENGE" | "LOG",
      "method": "GET" | "POST" | ...,
      "path":   "<NormalizedPath, no query string>",
      "query_len": <int>,        // body content NOT captured
      "body_len":  <int>,
      "content_type": "<value>",
      "user_agent":  "<value>",
      "headers": {               // whitelist captured, value-truncated
        "host": "...", "referer": "...", "x-forwarded-for": "...",
        "cookie":        "len=N,n=M",      // summary only — value redacted
        "authorization": "Bearer ***",     // scheme only
        ...
      },
      "rule_score": <float>,
      ... (RequestID, ClientIP, latency, etc. — ignored here)
    }

CANONICAL TEMPLATE OUTPUT
=========================
Each line in `templates.jsonl`:

    {
      "id": "tpl_0001",
      "method": "GET",
      "path": "/api/v1/products",
      "host": "shop.example.com",
      "user_agent": "Mozilla/5.0 ...",
      "content_type": "",
      "referer": "https://shop.example.com/",
      "extra_headers": {
        "x-forwarded-for": "203.0.113.5",
        "origin": "https://shop.example.com"
      },
      "had_query":   false,    // helps injector decide query vs body injection
      "had_body":    false,
      "original_body_len": 0,
      "canonical_template": "GET /api/v1/products\nHost: shop.example.com\nUser-Agent: Mozilla/5.0 ...\nReferer: https://shop.example.com/\n"
    }

`canonical_template` is the SKELETON — no query string, no body. Inject
your payload at the position appropriate for the attack class, then
recompute the canonical string before writing the labeled sample.

CLI
===
    python extract_templates.py \
        --input-dir ../logs/waf/ \
        --output    ./processed/templates.jsonl \
        --max-templates 5000 \
        --min-per-host  3

    # All flags optional. Defaults:
    #   --input-dir = logs/waf/      (looks for training-*.jsonl)
    #   --output    = templates.jsonl
    #   --max-templates = 0  (no cap)
    #   --min-per-host  = 0  (no minimum)

DEPENDENCIES
============
Stdlib only. Optional: tqdm (pip install tqdm) for a progress bar — falls
back to a plain counter if tqdm is missing.
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

# Optional tqdm.
try:
    from tqdm import tqdm  # type: ignore
except ImportError:                  # pragma: no cover
    def tqdm(it, **_):               # noqa: D401
        return it

# ----------------------------------------------------------------------
# Filtering
# ----------------------------------------------------------------------

# Suffixes for static asset paths — same list the WAF training logger uses.
# We re-apply here since the user might have logged everything (e.g. via a
# different config), and static assets carry zero attacker signal.
STATIC_SUFFIXES = (
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".wav", ".webm", ".ogg",
    ".pdf", ".zip", ".gz", ".tar",
    ".txt", ".xml",  # robots, sitemap — usually noise
)

# Path prefixes never worth using as a template (WAF infra / health checks).
SKIP_PREFIXES = (
    "/__waf/",
    "/health",
    "/healthz",
    "/metrics",
    "/favicon",
    "/waf-api/",
    "/socket.io/",
    "/.well-known/",
)


def is_static_asset(path: str) -> bool:
    """True if the path looks like a static asset by suffix."""
    p = path.lower().split("?", 1)[0]      # strip query if leaked in
    return p.endswith(STATIC_SUFFIXES)


def should_skip_path(path: str) -> bool:
    """True if path is in the bypass list (WAF infra, health, etc.)."""
    if not path:
        return True
    if is_static_asset(path):
        return True
    for pref in SKIP_PREFIXES:
        if path.startswith(pref):
            return True
    return False


# ----------------------------------------------------------------------
# Canonical template construction
# ----------------------------------------------------------------------

# Header keys we keep in `extra_headers` (in addition to the 4 always-on
# fields: Host, User-Agent, Content-Type, Referer). Order matters — model
# learns positional cues so we always emit headers in the same order.
EXTRA_HEADER_ORDER = (
    "x-forwarded-for",
    "x-real-ip",
    "x-requested-with",
    "origin",
    "cookie",          # already summarised in source log
    "authorization",   # already scheme-only in source log
)


def title_header(name: str) -> str:
    """Map 'x-forwarded-for' → 'X-Forwarded-For' for canonical output."""
    return "-".join(part.capitalize() if part else "" for part in name.split("-"))


@dataclass
class Template:
    id: str
    method: str
    path: str
    host: str
    user_agent: str
    content_type: str
    referer: str
    extra_headers: Dict[str, str] = field(default_factory=dict)
    had_query: bool = False
    had_body: bool = False
    original_body_len: int = 0
    canonical_template: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


def build_canonical(
    method: str,
    path: str,
    host: str,
    user_agent: str,
    content_type: str,
    referer: str,
    extra: Dict[str, str],
) -> str:
    """Compose the canonical text for the model.

    The template has NO query string and NO body — the injector adds those
    when wrapping an attack payload. The skeleton is exactly what the WAF
    would send if the request had only path + headers, no body.
    """
    lines: List[str] = []
    lines.append(f"{method} {path}".rstrip())

    def add(name: str, value: str) -> None:
        v = (value or "").strip()
        if v:
            lines.append(f"{title_header(name)}: {v[:200]}")

    add("host", host)
    add("user-agent", user_agent)
    add("content-type", content_type)
    add("referer", referer)
    for k in EXTRA_HEADER_ORDER:
        if k in {"host", "user-agent", "content-type", "referer"}:
            continue
        v = extra.get(k, "")
        if v:
            add(k, v)
    # Trailing newline mimics the blank line before body in real canonical text.
    return "\n".join(lines) + "\n"


def record_to_template(
    rec: dict,
    next_id: int,
) -> Optional[Template]:
    """Turn one log Record into a Template. Returns None if record is skipped."""
    decision = (rec.get("decision") or "").upper()
    label    = (rec.get("label") or "").lower()
    if decision != "ALLOW" or label != "allow":
        return None

    method = (rec.get("method") or "GET").upper()
    path   = rec.get("path") or "/"
    if should_skip_path(path):
        return None

    headers_in: Dict[str, str] = {k.lower(): v for k, v in (rec.get("headers") or {}).items()}
    host         = headers_in.get("host", "")
    user_agent   = headers_in.get("user-agent") or rec.get("user_agent") or ""
    content_type = headers_in.get("content-type") or rec.get("content_type") or ""
    referer      = headers_in.get("referer", "")

    extra: Dict[str, str] = {}
    for k in EXTRA_HEADER_ORDER:
        v = headers_in.get(k)
        if v:
            extra[k] = v

    canonical = build_canonical(method, path, host, user_agent, content_type, referer, extra)

    return Template(
        id=f"tpl_{next_id:06d}",
        method=method,
        path=path,
        host=host,
        user_agent=user_agent,
        content_type=content_type,
        referer=referer,
        extra_headers=extra,
        had_query=int(rec.get("query_len") or 0) > 0,
        had_body=int(rec.get("body_len") or 0) > 0,
        original_body_len=int(rec.get("body_len") or 0),
        canonical_template=canonical,
    )


# ----------------------------------------------------------------------
# Iteration / dedup
# ----------------------------------------------------------------------

def iter_records(input_dir: Path) -> Iterator[dict]:
    """Yield JSON records from all training-*.jsonl files in input_dir."""
    files = sorted(glob.glob(str(input_dir / "training-*.jsonl")))
    if not files:
        # Accept any *.jsonl as a fallback so user can rename / split files.
        files = sorted(glob.glob(str(input_dir / "*.jsonl")))
    if not files:
        print(f"[warn] no *.jsonl files in {input_dir}", file=sys.stderr)
        return

    for fp in files:
        n_lines = 0
        n_bad   = 0
        with open(fp, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                n_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    n_bad += 1
                    continue
        print(f"  ✓ {os.path.basename(fp)}: {n_lines:,} lines  ({n_bad} malformed)",
              file=sys.stderr)


def dedup_key(t: Template) -> str:
    """Stable hash so re-runs produce the same set when input is unchanged.

    We dedup by (method, path, host, content_type, head-of-UA) — Most bots
    refresh the same path with the same UA hundreds of times per day. UA
    is hashed by its first 60 chars so minor build numbers (Chrome 119.1
    vs 119.2) collapse to one template.
    """
    h = hashlib.md5()
    ua_head = (t.user_agent or "")[:60]
    h.update(f"{t.method}|{t.path}|{t.host}|{t.content_type}|{ua_head}".encode())
    return h.hexdigest()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Extract canonical templates from WAF training logs.")
    ap.add_argument("--input-dir",      type=Path, default=Path("logs/waf"),
                    help="directory containing training-*.jsonl (default: logs/waf)")
    ap.add_argument("--output",         type=Path, default=Path("templates.jsonl"),
                    help="output JSONL path (default: templates.jsonl)")
    ap.add_argument("--max-templates",  type=int,  default=0,
                    help="cap total templates emitted; 0 = no cap (default: 0)")
    ap.add_argument("--min-per-host",   type=int,  default=0,
                    help="drop hosts with fewer than N templates after dedup (default: 0)")
    ap.add_argument("--max-per-host",   type=int,  default=0,
                    help="cap templates per host (keeps distribution; 0 = no cap)")
    args = ap.parse_args()

    if not args.input_dir.exists():
        print(f"[error] input directory not found: {args.input_dir}", file=sys.stderr)
        return 1

    print(f"[info] reading from {args.input_dir}", file=sys.stderr)

    # Stage 1: parse all records, build candidate templates, dedup.
    seen:   Dict[str, Template]      = {}
    n_total = n_skipped = n_kept = 0
    next_id = 1

    for rec in tqdm(iter_records(args.input_dir), desc="reading", unit="rec"):
        n_total += 1
        tpl = record_to_template(rec, next_id)
        if tpl is None:
            n_skipped += 1
            continue
        key = dedup_key(tpl)
        if key in seen:
            n_skipped += 1
            continue
        seen[key] = tpl
        next_id += 1
        n_kept += 1

    print(f"[info] read     : {n_total:,}", file=sys.stderr)
    print(f"[info] skipped  : {n_skipped:,}  (non-allow / static / bypass / dup)", file=sys.stderr)
    print(f"[info] candidates after dedup: {n_kept:,}", file=sys.stderr)

    # Stage 2: per-host filtering / capping.
    by_host: Dict[str, List[Template]] = defaultdict(list)
    for t in seen.values():
        by_host[t.host or "(no-host)"].append(t)

    if args.min_per_host > 0:
        before = sum(len(v) for v in by_host.values())
        by_host = {h: ts for h, ts in by_host.items() if len(ts) >= args.min_per_host}
        after = sum(len(v) for v in by_host.values())
        print(f"[info] min-per-host filter: {before:,} → {after:,}", file=sys.stderr)

    if args.max_per_host > 0:
        for h, ts in by_host.items():
            if len(ts) > args.max_per_host:
                # Stable cap: keep first N (preserves earliest IDs).
                by_host[h] = ts[:args.max_per_host]

    templates: List[Template] = [t for ts in by_host.values() for t in ts]

    if args.max_templates > 0 and len(templates) > args.max_templates:
        print(f"[info] capping total at --max-templates={args.max_templates}", file=sys.stderr)
        templates = templates[:args.max_templates]

    # Stage 3: stats.
    method_dist = Counter(t.method for t in templates)
    host_dist   = Counter(t.host or "(no-host)" for t in templates)
    ct_dist     = Counter((t.content_type or "(none)").split(";", 1)[0].strip() for t in templates)
    had_query   = sum(1 for t in templates if t.had_query)
    had_body    = sum(1 for t in templates if t.had_body)
    path_prefix = Counter("/" + (t.path.lstrip("/").split("/", 1)[0]) for t in templates)

    # Stage 4: write.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        for t in templates:
            fh.write(t.to_json() + "\n")

    # Report.
    print(f"\n[ok] wrote {len(templates):,} templates → {args.output}", file=sys.stderr)
    print(f"\n--- METHOD distribution ---", file=sys.stderr)
    for m, n in method_dist.most_common():
        print(f"  {m:<8} {n:>6,}", file=sys.stderr)
    print(f"\n--- CONTENT-TYPE distribution (top 8) ---", file=sys.stderr)
    for ct, n in ct_dist.most_common(8):
        print(f"  {ct:<40} {n:>6,}", file=sys.stderr)
    print(f"\n--- HOST distribution (top 10) ---", file=sys.stderr)
    for h, n in host_dist.most_common(10):
        print(f"  {h:<40} {n:>6,}", file=sys.stderr)
    print(f"\n--- PATH prefix distribution (top 15) ---", file=sys.stderr)
    for p, n in path_prefix.most_common(15):
        print(f"  {p:<40} {n:>6,}", file=sys.stderr)
    print(f"\n--- INJECTABILITY ---", file=sys.stderr)
    print(f"  templates with query string: {had_query:,} / {len(templates):,}  "
          f"({100*had_query/max(len(templates),1):.1f}%)", file=sys.stderr)
    print(f"  templates with body:         {had_body:,} / {len(templates):,}  "
          f"({100*had_body/max(len(templates),1):.1f}%)", file=sys.stderr)

    if len(templates) == 0:
        print(f"\n[warn] zero templates emitted — check filters / input log content",
              file=sys.stderr)
        return 2

    # Quality hints.
    if len(host_dist) < 3:
        print(f"\n[warn] only {len(host_dist)} distinct host(s). Model may overfit.",
              file=sys.stderr)
        print(f"       Capture traffic against more upstreams before training.",
              file=sys.stderr)
    if method_dist.get("POST", 0) < len(templates) * 0.1:
        print(f"\n[warn] POST coverage low (<10%). Body-injection attacks may "
              f"need synthetic templates as backup.", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
