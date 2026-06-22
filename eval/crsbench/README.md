# CRS baseline harness (Coraza + OWASP CRS)

Replays the **same CSIC-2010 test split** that `cmd/wafbench` evaluates through a
stock **OWASP Core Rule Set** on the **Coraza** engine, so the proposed WAF and
the de-facto OSS baseline are compared on byte-identical records. Kept in its
own Go module so Coraza's dependency tree never enters the main `go.mod`.

## Reproduce the full comparison

```bash
# 1. Export the shared test set + proposed-system numbers (from repo root)
go run ./cmd/wafbench -split test -tag baseline-final \
    -export eval/results/test_records.jsonl

# 2. OWASP CRS baseline on the same records (PL1, inbound anomaly threshold 5)
cd eval/crsbench && go run . -in ../results/test_records.jsonl
#    -> eval/results/run-crs-baseline.json

# 3. Out-of-distribution check of the ML model on the same records (--model selects v7 or v8)
cd ../.. && .venv/bin/python scripts/eval_ood_v7.py --model model_v8/final_model_v8 \
    --in eval/results/test_records.jsonl --out eval/results/run-ml-ood-v8.json
```

## Headline numbers (CSIC 2010 TEST, injection subset: SQLi/XSS/Path-Traversal/CRLF)

| System | Recall | FPR | Precision | F1 |
|---|---|---|---|---|
| Proposed rule engine | **100.0%** | 0.00% | 100.0% | **1.000** |
| OWASP CRS @PL1 (Coraza) | 71.8% | 0.01% | 99.9% | 0.836 |
| DistilBERT v8 (standalone, OOD\*) | 96.8% | 0.01% | 99.9% | 0.984 |
| ↳ DistilBERT v7 (zero-shot, pre-augment) | 46.3% | 0.00% | 100.0% | 0.633 |

\*v8 was trained with **CSIC-*style* synthetic** hard negatives + an 11th `crlf`
class (NOT real CSIC records — verified 0/26,931 test records leak into the v8
training set), so 96.8% is *generalization to the deployment distribution after
targeted augmentation*, a weaker claim than v7's pure zero-shot 46.3%.

On the *full* anomalous set CRS scores higher recall (~27.8% vs ~18.0%) because it
flags more generic non-injection anomalies; it misses all CRLF and some SQLi on
the injection subset. Both run at ~0% FPR. See `docs/EVALUATION.md` §7 for the
full discussion — including the v7→v8 diagnosis (CRLF 0% + narrow SQLi/XSS) and
the honest near-OOD caveat. The OOD eval feeds the model the serve-accurate
canonical text (`ml.max_body_len` = 4096 B), NOT a 256 B truncation — the
latter would chop body-borne payloads off the end and understate recall.
