"""
WAF ML Inference Service
Loads DistilBERT classifier for 10-class attack detection (normal/sqli/xss/cmdi/
path_traversal/ssrf/xxe/log4shell/ssti/nosqli).
Exposed as FastAPI HTTP endpoint, called by Go WAF when rule score is in gray zone.

Labels are read dynamically from the model's `config.json` (or
`label_config.json` if present) so a re-trained model with a different label set
can be dropped in without code changes.
"""
import json
import os
import time
import logging
from typing import List, Dict

import torch
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoTokenizer, AutoModelForSequenceClassification

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("ml-service")

MODEL_DIR = os.environ.get("MODEL_DIR", "/app/model")
MAX_LENGTH = int(os.environ.get("MAX_LENGTH", "256"))
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# Populated at startup from the model files.
LABELS: List[str] = []

app = FastAPI(title="WAF ML Service", version="2.0")

tokenizer = None
model = None


def _load_labels(model_dir: str) -> List[str]:
    """Read id2label from label_config.json (preferred) or config.json."""
    for fname in ("label_config.json", "config.json"):
        path = os.path.join(model_dir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                blob = json.load(f)
        except Exception as e:
            log.warning(f"failed to parse {path}: {e}")
            continue
        id2label = blob.get("id2label")
        if not id2label:
            continue
        # id2label keys are strings; sort numerically.
        items = sorted(((int(k), v) for k, v in id2label.items()), key=lambda x: x[0])
        return [v for _, v in items]
    # Fallback (old 5-class model).
    log.warning("no label config found, using legacy 5-class fallback")
    return ["normal", "sqli", "xss", "cmdi", "path_traversal"]


@app.on_event("startup")
def load_model():
    global tokenizer, model, LABELS
    log.info(f"Loading model from {MODEL_DIR} on device={DEVICE}")
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.to(DEVICE)
    model.eval()
    LABELS = _load_labels(MODEL_DIR)
    log.info(
        f"Model loaded in {time.time() - t0:.2f}s, "
        f"num_labels={model.config.num_labels}, labels={LABELS}"
    )


class PredictRequest(BaseModel):
    text: str


class PredictResponse(BaseModel):
    label: str
    label_id: int
    confidence: float
    scores: Dict[str, float]
    is_attack: bool
    latency_ms: float


class BatchPredictRequest(BaseModel):
    texts: List[str]


@app.get("/health")
def health():
    return {
        "status": "ok" if model is not None else "loading",
        "device": DEVICE,
        "labels": LABELS,
        "max_length": MAX_LENGTH,
    }


@app.post("/predict", response_model=PredictResponse)
def predict(req: PredictRequest):
    t0 = time.time()
    text = (req.text or "").strip()
    if not text:
        return PredictResponse(
            label="normal", label_id=0, confidence=1.0,
            scores={l: 0.0 for l in LABELS},
            is_attack=False, latency_ms=0.0,
        )

    enc = tokenizer(
        text,
        truncation=True,
        max_length=MAX_LENGTH,
        padding=False,
        return_tensors="pt",
        return_token_type_ids=False,  # DistilBERT does not accept token_type_ids
    ).to(DEVICE)

    with torch.no_grad():
        logits = model(**enc).logits[0]
        probs = torch.softmax(logits, dim=-1).cpu().tolist()

    scores = {LABELS[i]: float(probs[i]) for i in range(len(LABELS))}
    label_id = int(max(range(len(probs)), key=lambda i: probs[i]))
    label = LABELS[label_id]
    confidence = float(probs[label_id])

    return PredictResponse(
        label=label,
        label_id=label_id,
        confidence=confidence,
        scores=scores,
        is_attack=(label != "normal"),
        latency_ms=(time.time() - t0) * 1000.0,
    )


@app.post("/predict_batch")
def predict_batch(req: BatchPredictRequest):
    t0 = time.time()
    texts = [t.strip() for t in (req.texts or []) if t and t.strip()]
    if not texts:
        return {"predictions": [], "latency_ms": 0.0}

    enc = tokenizer(
        texts,
        truncation=True,
        max_length=MAX_LENGTH,
        padding=True,
        return_tensors="pt",
        return_token_type_ids=False,
    ).to(DEVICE)

    with torch.no_grad():
        logits = model(**enc).logits
        probs = torch.softmax(logits, dim=-1).cpu().tolist()

    predictions = []
    for p in probs:
        scores = {LABELS[i]: float(p[i]) for i in range(len(LABELS))}
        label_id = int(max(range(len(p)), key=lambda i: p[i]))
        predictions.append({
            "label": LABELS[label_id],
            "label_id": label_id,
            "confidence": float(p[label_id]),
            "scores": scores,
            "is_attack": LABELS[label_id] != "normal",
        })

    return {"predictions": predictions, "latency_ms": (time.time() - t0) * 1000.0}
