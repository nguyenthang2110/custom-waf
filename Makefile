.PHONY: build test run run-waf clean docker docker-run \
        ml-install ml-run ml-start ml-stop ml-status ml-logs \
        db-start db-stop db-status db-logs stop down

GOCACHE_DIR := $(CURDIR)/.gocache

# ML service config — override on the command line, e.g.
#   make run MODEL_DIR=/path/to/final_model_v7
ML_VENV    ?= $(CURDIR)/.venv
ML_HOST    ?= 127.0.0.1
ML_PORT    ?= 8000
MODEL_DIR  ?= $(CURDIR)/model_v8/final_model_v8
MAX_LENGTH ?= 256
ML_LOG     ?= $(CURDIR)/logs/ml-service.log
ML_PID     ?= $(CURDIR)/.ml-service.pid

# Postgres (Docker) config
DB_COMPOSE   ?= $(CURDIR)/docker-compose.db.yml
DB_CONTAINER ?= waf_postgres
DB_USER      ?= waf_user
DB_NAME      ?= waf_db
# Prefer the v2 plugin (`docker compose`); fall back to legacy v1 binary.
DC           ?= $(shell command -v docker-compose >/dev/null 2>&1 && echo docker-compose || echo docker compose)

build:
	GOFLAGS= GOCACHE=$(GOCACHE_DIR) go build -o bin/waf ./cmd/waf

test:
	GOFLAGS= GOCACHE=$(GOCACHE_DIR) go test ./...

# Boot Postgres + ML in background, then run WAF in foreground.
# On WAF exit (Ctrl+C, crash, or normal stop), the ML service is killed.
# Postgres is intentionally LEFT RUNNING so persisted config & dev data
# stay warm across edit-rebuild-rerun cycles. Use `make down` to stop it.
run: build db-start ml-start
	@trap '$(MAKE) --no-print-directory ml-stop' EXIT INT TERM; \
	  ./bin/waf -config configs/config.yaml

# WAF only — assume ML is already running (or not needed).
run-waf: build
	./bin/waf -config configs/config.yaml

# Run ML service in foreground (blocks).
ml-run:
	@mkdir -p $(dir $(ML_LOG))
	cd ml-service && \
	  MODEL_DIR=$(MODEL_DIR) MAX_LENGTH=$(MAX_LENGTH) \
	  $(ML_VENV)/bin/uvicorn app:app --host $(ML_HOST) --port $(ML_PORT)

# Start ML service in background, write PID, wait for /health.
ml-start:
	@if [ -f $(ML_PID) ] && kill -0 $$(cat $(ML_PID)) 2>/dev/null; then \
	  echo "→ ML service already running (PID $$(cat $(ML_PID)))"; \
	  exit 0; \
	fi
	@if [ ! -x $(ML_VENV)/bin/uvicorn ]; then \
	  echo "ML venv missing at $(ML_VENV) — run 'make ml-install'"; exit 1; \
	fi
	@if [ ! -d $(MODEL_DIR) ]; then \
	  echo "MODEL_DIR not found: $(MODEL_DIR)"; \
	  echo "Override with: make run MODEL_DIR=/path/to/final_model_v7"; exit 1; \
	fi
	@mkdir -p $(dir $(ML_LOG))
	@echo "→ Starting ML service on $(ML_HOST):$(ML_PORT)  (logs: $(ML_LOG))"
	@cd ml-service && \
	  MODEL_DIR=$(MODEL_DIR) MAX_LENGTH=$(MAX_LENGTH) \
	  nohup $(ML_VENV)/bin/uvicorn app:app --host $(ML_HOST) --port $(ML_PORT) \
	    > $(ML_LOG) 2>&1 & echo $$! > $(ML_PID)
	@for i in $$(seq 1 30); do \
	  sleep 1; \
	  if ! kill -0 $$(cat $(ML_PID)) 2>/dev/null; then \
	    echo "ML service died on startup — see $(ML_LOG)"; \
	    rm -f $(ML_PID); exit 1; \
	  fi; \
	  if curl -sf http://$(ML_HOST):$(ML_PORT)/health >/dev/null 2>&1; then \
	    echo "→ ML service ready (PID $$(cat $(ML_PID)))"; exit 0; \
	  fi; \
	done; \
	echo "ML service did not become healthy in 30s — see $(ML_LOG)"; \
	exit 1

ml-stop:
	@if [ -f $(ML_PID) ]; then \
	  PID=$$(cat $(ML_PID)); \
	  if kill -0 $$PID 2>/dev/null; then \
	    echo "→ Stopping ML service (PID $$PID)"; \
	    kill $$PID 2>/dev/null || true; \
	    for i in 1 2 3 4 5; do sleep 1; kill -0 $$PID 2>/dev/null || break; done; \
	    kill -0 $$PID 2>/dev/null && kill -9 $$PID 2>/dev/null || true; \
	  fi; \
	  rm -f $(ML_PID); \
	else \
	  echo "→ ML service not running"; \
	fi

ml-status:
	@if [ -f $(ML_PID) ] && kill -0 $$(cat $(ML_PID)) 2>/dev/null; then \
	  echo "ML service: running (PID $$(cat $(ML_PID)))"; \
	  curl -sf http://$(ML_HOST):$(ML_PORT)/health || echo "  /health: unreachable"; \
	else \
	  echo "ML service: stopped"; \
	fi

ml-logs:
	@touch $(ML_LOG) && tail -n 200 -f $(ML_LOG)

ml-install:
	@if [ ! -d $(ML_VENV) ]; then python3 -m venv $(ML_VENV); fi
	$(ML_VENV)/bin/pip install -r ml-service/requirements.txt

# =====================================================================
# Database (Postgres in Docker — uses docker-compose.db.yml)
# =====================================================================

# Start Postgres and wait for pg_isready. Idempotent: if it's already
# running, we just confirm and exit.
db-start:
	@if ! command -v docker >/dev/null 2>&1; then \
	  echo "docker not installed — skipping Postgres. Set DB_USER/DB_NAME and run your own."; exit 1; \
	fi
	@if docker ps --filter "name=^$(DB_CONTAINER)$$" --filter "status=running" -q | grep -q .; then \
	  echo "→ Postgres already running ($(DB_CONTAINER))"; \
	else \
	  echo "→ Starting Postgres ($(DB_CONTAINER))..."; \
	  $(DC) -f $(DB_COMPOSE) up -d; \
	fi
	@for i in $$(seq 1 30); do \
	  if docker exec $(DB_CONTAINER) pg_isready -U $(DB_USER) -d $(DB_NAME) >/dev/null 2>&1; then \
	    echo "→ Postgres ready ($(DB_USER)@$(DB_NAME))"; exit 0; \
	  fi; \
	  sleep 1; \
	done; \
	echo "Postgres did not become ready in 30s"; \
	$(DC) -f $(DB_COMPOSE) logs --tail=50; \
	exit 1

db-stop:
	@$(DC) -f $(DB_COMPOSE) stop 2>/dev/null || true
	@echo "→ Postgres stopped (data volume preserved)"

db-status:
	@if docker ps --filter "name=^$(DB_CONTAINER)$$" --filter "status=running" -q | grep -q .; then \
	  echo "Postgres: running"; \
	  docker exec $(DB_CONTAINER) pg_isready -U $(DB_USER) -d $(DB_NAME) || true; \
	else \
	  echo "Postgres: stopped"; \
	fi

db-logs:
	@$(DC) -f $(DB_COMPOSE) logs -f --tail=200

# =====================================================================
# Aggregate stop targets
# =====================================================================

# Stop ML only (preserves running Postgres so the next `make run` is fast).
stop: ml-stop

# Stop everything — ML, WAF, AND Postgres.
down: ml-stop db-stop

clean:
	rm -rf bin ./tmp ./logs

docker:
	docker build -t waf:latest -f deployments/docker/Dockerfile .

docker-run:
	docker-compose -f deployments/docker/docker-compose.yml up -d
