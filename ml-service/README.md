# WAF ML Inference Service

FastAPI service serving the DistilBERT classifier for the WAF.
Called by the Go WAF when a request's rule score lands in the gray zone (4.0–4.99).

## Labels
`normal`, `sqli`, `xss`, `cmdi`, `path_traversal`

## Run locally (without Docker)

```bash
cd ml-service
pip install -r requirements.txt
MODEL_DIR=../../../model_zip_v3/model/final_model_v3 \
  uvicorn app:app --host 0.0.0.0 --port 8000
```

## Run with Docker

```bash
# from project root
docker compose up ml -d
```

The compose file mounts `model_zip_v3/model/final_model_v3` into `/app/model`.

## Endpoints

- `GET /health` → service status
- `POST /predict` body `{"text": "..."}` → label/confidence/scores
- `POST /predict_batch` body `{"texts": [...]}`

## Test

```bash
curl -s -X POST localhost:8000/predict \
  -H 'content-type: application/json' \
  -d '{"text":"id=1 OR 1=1"}' | jq
```
