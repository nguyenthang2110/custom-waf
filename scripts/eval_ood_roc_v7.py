#!/usr/bin/env python3
"""OOD operating-point (ROC) analysis of the v7 model on CSIC 2010.

The headline OOD number (injection recall 46.3%) uses the *argmax* decision —
predict "attack" iff the top-1 class is not "normal". That is an arbitrarily
CONSERVATIVE binary threshold: it ignores cases where the model splits, say,
0.45 normal / 0.40 sqli / 0.15 xss (argmax = normal, but P(attack) = 0.55).

Because the argmax decision runs at 0% FPR on CSIC benign traffic, there is
headroom to pick a more sensitive operating point. This script computes the
binary attack score s = 1 - P(normal) for every record and sweeps the decision
threshold τ (predict attack iff s > τ), reporting recall on the injection
subset and FPR on benign at each τ — a standard ROC analysis. It also reports
the same with CRLF excluded, since v7 has no CRLF class (a documented label-set
limitation) and those 383 records are unrecoverable by any threshold.

This does NOT change any reported in-distribution number and does NOT relabel
data; it only measures the model at thresholds other than the implicit argmax
one, with the FPR cost disclosed at every point.

Usage:
    .venv/bin/python scripts/eval_ood_roc_v7.py \
        --in eval/results/test_records.jsonl \
        --out eval/results/run-ml-ood-roc-v7.json
"""
import argparse
import json
import os
import sys
import time

INJECTION = {"sqli", "xss", "traversal", "rce", "crlf", "ssi_xxe"}


def metrics_at(scores, labels, cats, tau, exclude_cats=()):
    """Binary attack iff score > tau. Positive class = injection-category
    attacks; negatives = benign. Returns (recall, fpr, tp, fn, fp, tn)."""
    tp = fn = fp = tn = 0
    for s, lab, cat in zip(scores, labels, cats):
        if cat in exclude_cats:
            continue
        is_attack_truth = (lab == "attack")
        # injection subset: positives are injection attacks; negatives benign.
        if is_attack_truth and cat not in INJECTION:
            continue  # non-injection anomaly: out of this subset entirely
        pred_attack = s > tau
        if is_attack_truth and pred_attack:
            tp += 1
        elif is_attack_truth and not pred_attack:
            fn += 1
        elif (not is_attack_truth) and pred_attack:
            fp += 1
        else:
            tn += 1
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return recall, fpr, tp, fn, fp, tn


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.environ.get("MODEL_DIR", "model_v7/final_model_v7"))
    ap.add_argument("--in", dest="infile", default="eval/results/test_records.jsonl")
    ap.add_argument("--out", default="eval/results/run-ml-ood-roc-v7.json")
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--device", default="auto")
    args = ap.parse_args()

    import torch
    from transformers import AutoTokenizer, AutoModelForSequenceClassification

    if args.device == "auto":
        if torch.cuda.is_available():
            dev = "cuda"
        elif getattr(torch.backends, "mps", None) and torch.backends.mps.is_available():
            dev = "mps"
        else:
            dev = "cpu"
    else:
        dev = args.device
    print(f"[roc] device={dev} model={args.model}", file=sys.stderr)

    with open(os.path.join(args.model, "label_config.json")) as f:
        lc = json.load(f)
    id2label = {int(k): v for k, v in lc["id2label"].items()}
    normal_id = next(i for i, n in id2label.items() if n == "normal")
    max_len = lc.get("max_length", 256)

    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    model.to(dev).eval()

    texts, labels, cats = [], [], []
    with open(args.infile) as f:
        for line in f:
            r = json.loads(line)
            if not r.get("ml_text"):
                continue
            texts.append(r["ml_text"])
            labels.append(r["label"])
            cats.append(r["category"])
    print(f"[roc] {len(texts)} records", file=sys.stderr)

    p_normal = []
    t0 = time.time()
    with torch.no_grad():
        for i in range(0, len(texts), args.batch):
            enc = tok(texts[i:i + args.batch], truncation=True, max_length=max_len,
                      padding=True, return_tensors="pt").to(dev)
            probs = torch.softmax(model(**enc).logits, dim=-1)
            p_normal.extend(probs[:, normal_id].cpu().tolist())
            if (i // args.batch) % 50 == 0:
                print(f"  ...{i}/{len(texts)} ({time.time()-t0:.0f}s)", file=sys.stderr)

    # Binary attack score = 1 - P(normal).
    scores = [1.0 - pn for pn in p_normal]

    # argmax-equivalent decision is "attack iff P(normal) < 0.5" i.e. s > 0.5.
    sweep = [0.5, 0.4, 0.3, 0.25, 0.2, 0.15, 0.1, 0.05, 0.02, 0.01]
    print("=" * 78)
    print("v7 OOD ROC sweep — binary attack iff (1 - P(normal)) > τ  [INJECTION subset]")
    print("=" * 78)
    rows = []
    print(f"{'τ':>6} | {'recall':>8} {'FPR':>7} | {'recall(excl CRLF)':>17} {'FPR':>7}")
    for tau in sweep:
        rec, fpr, tp, fn, fp, tn = metrics_at(scores, labels, cats, tau)
        recx, fprx, *_ = metrics_at(scores, labels, cats, tau, exclude_cats={"crlf"})
        rows.append(dict(tau=tau, recall=rec, fpr=fpr, tp=tp, fn=fn, fp=fp, tn=tn,
                         recall_excl_crlf=recx, fpr_excl_crlf=fprx))
        print(f"{tau:>6.2f} | {rec*100:7.2f}% {fpr*100:6.3f}% | {recx*100:16.2f}% {fprx*100:6.3f}%")

    report = dict(model=args.model, records=len(texts),
                  note="binary score = 1 - P(normal); positives = injection-category attacks; "
                       "negatives = benign; CRLF has no v7 class.",
                  sweep=rows)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
