"""
WAF ML Inference Service
Loads DistilBERT classifier for SQLi/XSS/CMDi/PathTraversal detection.
Exposed as FastAPI HTTP endpoint, called by Go WAF when rule score is in gray zone.
"""
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

LABELS = ["normal", "sqli", "xss", "cmdi", "path_traversal"]

app = FastAPI(title="WAF ML Service", version="1.0")

tokenizer = None
model = None


@app.on_event("startup")
def load_model():
    global tokenizer, model
    log.info(f"Loading model from {MODEL_DIR} on device={DEVICE}")
    t0 = time.time()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    model.to(DEVICE)
    model.eval()
    log.info(f"Model loaded in {time.time() - t0:.2f}s, num_labels={model.config.num_labels}")


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
