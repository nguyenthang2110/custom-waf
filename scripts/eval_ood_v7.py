#!/usr/bin/env python3
"""Out-of-distribution evaluation of the v7 DistilBERT model on CSIC 2010.

The headline 0.9959 macro-F1 is measured *in-distribution* on the synthetic,
templated training corpus. This script measures how the SAME model behaves on
an INDEPENDENT, real-ish corpus (CSIC 2010) that it never saw during training —
the defensible generalization estimate to report alongside the in-distribution
number.

Input is eval/results/test_records.jsonl, produced by:

    go run ./cmd/wafbench -split test -export eval/results/test_records.jsonl

Each line already carries `ml_text`: the SERVE-ACCURATE canonical text the WAF
middleware would send to the model (built by internal/training.BuildCanonicalText),
so there is no train/serve text skew in this measurement.

We reduce the 10-class softmax to a binary decision (predict "attack" iff the
argmax class is not "normal") and report Recall/FPR/Precision/F1/BalancedAcc on
(a) the full anomalous set and (b) the injection-class subset — mirroring
cmd/wafbench so the ML model, the rule engine, and the CRS baseline line up in
one table.

Usage:
    .venv/bin/python scripts/eval_ood_v7.py \
        --model model_v7/final_model_v7 \
        --in eval/results/test_records.jsonl \
        --out eval/results/run-ml-ood-v7.json
"""
import argparse
import json
import os
import sys
import time

INJECTION = {"sqli", "xss", "traversal", "rce", "crlf", "ssi_xxe"}

# CSIC wafbench category -> the v7 model attack class we'd hope to see.
# Approximate (CSIC has no fine-grained labels); used only for a per-class
# detection breakdown, NOT for the headline binary metric.
CSIC_TO_V7 = {
    "sqli": "sqli",
    "xss": "xss",
    "traversal": "path_traversal",
    "rce": "cmdi",
    "ssi_xxe": "xxe",   # CSIC lumps SSI/XXE/template; v7 splits xxe/ssti/log4shell
    "crlf": None,        # no direct v7 class
}


def confusion(tp, fp, tn, fn):
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
    tnr = tn / (fp + tn) if (fp + tn) else 0.0
    bal = (recall + tnr) / 2
    return dict(TP=tp, FP=fp, TN=tn, FN=fn, recall_tpr=recall, fpr=fpr,
               precision=prec, f1=f1, balanced_accuracy=bal)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=os.environ.get("MODEL_DIR", "model_v7/final_model_v7"))
    ap.add_argument("--in", dest="infile", default="eval/results/test_records.jsonl")
    ap.add_argument("--out", default="eval/results/run-ml-ood-v7.json")
    ap.add_argument("--limit", type=int, default=0, help="max records per class (0 = all)")
    ap.add_argument("--batch", type=int, default=64)
    ap.add_argument("--device", default="auto", help="auto|cpu|mps|cuda")
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
    print(f"[ood] device={dev} model={args.model}", file=sys.stderr)

    with open(os.path.join(args.model, "label_config.json")) as f:
        lc = json.load(f)
    id2label = {int(k): v for k, v in lc["id2label"].items()}
    max_len = lc.get("max_length", 256)

    tok = AutoTokenizer.from_pretrained(args.model)
    model = AutoModelForSequenceClassification.from_pretrained(args.model)
    model.to(dev).eval()

    texts, labels, cats = [], [], []
    nb = na = 0
    with open(args.infile) as f:
        for line in f:
            r = json.loads(line)
            if not r.get("ml_text"):
                continue
            if args.limit:
                if r["label"] == "benign":
                    if nb >= args.limit:
                        continue
                    nb += 1
                else:
                    if na >= args.limit:
                        continue
                    na += 1
            texts.append(r["ml_text"])
            labels.append(r["label"])
            cats.append(r["category"])
    print(f"[ood] {len(texts)} records loaded", file=sys.stderr)

    preds = []
    t0 = time.time()
    with torch.no_grad():
        for i in range(0, len(texts), args.batch):
            batch = texts[i:i + args.batch]
            enc = tok(batch, truncation=True, max_length=max_len,
                      padding=True, return_tensors="pt").to(dev)
            logits = model(**enc).logits
            preds.extend(logits.argmax(-1).tolist())
            if (i // args.batch) % 50 == 0:
                print(f"  ...{i + len(batch)}/{len(texts)} ({time.time()-t0:.0f}s)", file=sys.stderr)
    pred_names = [id2label[p] for p in preds]

    # Binary normal-vs-attack confusion.
    full = dict(tp=0, fp=0, tn=0, fn=0)
    inj = dict(tp=0, fp=0, tn=0, fn=0)
    per_cat = {}        # csic category -> {total, detected, correct_class}
    pred_dist = {}      # predicted v7 class distribution over attack records
    for name, lab, cat in zip(pred_names, labels, cats):
        attack_truth = (lab == "attack")
        attack_pred = (name != "normal")
        bucket = "tp" if (attack_truth and attack_pred) else \
                 "fn" if (attack_truth and not attack_pred) else \
                 "fp" if (not attack_truth and attack_pred) else "tn"
        full[bucket] += 1
        if (not attack_truth) or cat in INJECTION:
            inj[bucket] += 1
        if attack_truth:
            pc = per_cat.setdefault(cat, dict(total=0, detected=0, correct_class=0))
            pc["total"] += 1
            if attack_pred:
                pc["detected"] += 1
            if CSIC_TO_V7.get(cat) and name == CSIC_TO_V7[cat]:
                pc["correct_class"] += 1
            pred_dist[name] = pred_dist.get(name, 0) + 1

    full_m = confusion(full["tp"], full["fp"], full["tn"], full["fn"])
    inj_m = confusion(inj["tp"], inj["fp"], inj["tn"], inj["fn"])

    def show(title, m):
        print(f"\n[{title}]")
        print(f"  TP={m['TP']} FN={m['FN']} FP={m['FP']} TN={m['TN']}")
        print(f"  Recall={m['recall_tpr']*100:.2f}%  FPR={m['fpr']*100:.2f}%  "
              f"Precision={m['precision']*100:.2f}%  F1={m['f1']:.3f}  "
              f"BalAcc={m['balanced_accuracy']*100:.2f}%")

    print("=" * 74)
    print("v7 DistilBERT — OUT-OF-DISTRIBUTION eval on CSIC 2010 (binary normal-vs-attack)")
    print(f"records={len(texts)}  device={dev}  canonical text = serve-accurate (BuildCanonicalText)")
    print("=" * 74)
    show("FULL anomalous set (incl. non-injection anomalies)", full_m)
    show("INJECTION-CLASS subset (sqli/xss/traversal/rce/crlf/ssi_xxe)", inj_m)

    print("\n[PER CSIC CATEGORY] detection rate (attack predicted as any non-normal class)")
    for k in sorted(per_cat):
        pc = per_cat[k]
        det = pc["detected"] / pc["total"] * 100 if pc["total"] else 0
        cc = pc["correct_class"] / pc["total"] * 100 if pc["total"] else 0
        print(f"  {k:16s} total={pc['total']:5d}  detected={det:5.1f}%  exact-class={cc:5.1f}%")

    report = dict(
        model=args.model, model_version=lc.get("model_version"),
        records=len(texts), device=dev,
        full=full_m, injection=inj_m,
        per_category=per_cat, predicted_class_distribution=pred_dist,
        in_distribution_reference=lc.get("test_metrics_v7"),
    )
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
