# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A reverse-proxy WAF written in Go. Inspects HTTP requests through a rule engine (78 rules / 13 OWASP-aligned categories) using anomaly scoring; for requests whose score lands in a gray zone, calls out to a Python FastAPI ML service (DistilBERT) for a second opinion. Ships with a self-contained admin dashboard (vanilla HTML/CSS/JS embedded in the binary), JWT auth with three roles (admin/editor/viewer) backed by PostgreSQL.

## Common commands

```bash
# Full dev loop — boots Postgres + ML in background, runs WAF in foreground.
# Trap kills ML on WAF exit; Postgres is intentionally left running.
make run

# WAF only — ML service must already be running (or set ml.enabled=false in config).
make run-waf

# Tests (root cache pinned to .gocache to avoid polluting global cache)
make test
go test ./internal/engine/...            # one package
go test -run TestRuleLoader ./internal/engine
go test -v -count=1 ./internal/engine    # bypass test cache

# Build only
make build                                # produces ./bin/waf

# Service control
make ml-start / ml-stop / ml-status / ml-logs
make db-start / db-stop / db-status / db-logs
make stop                                # stop ML only (Postgres stays warm)
make down                                # stop ML + Postgres

# First-time ML setup (creates .venv, installs requirements.txt)
make ml-install
```

## Critical Makefile knob

`MODEL_DIR` defaults to `/Users/nguyenthang/BERT/model/final_model_v3` — a hard-coded absolute path on the author's machine. On any other machine, override it:

```bash
make run MODEL_DIR=/abs/path/to/final_model_v3
# or set persistently:
export MODEL_DIR=/abs/path/to/final_model_v3
```

If `MODEL_DIR` doesn't exist, `ml-start` fails fast with a clear message. The model itself is NOT in the repo — it lives in the user's separate `BERT/model/` tree.

## High-level architecture

### Request lifecycle (per HTTP request)

The pipeline lives in `cmd/waf/main.go`, which wires `internal/middleware/waf.go` in front of `httputil.ReverseProxy`. Each request flows through (in order):

1. **Admin access control** (`adminAccessControl` in main.go) — if the request hits `/dashboard/*`, `/login.html`, `/waf-api/*`, `/admin/*`, or `/metrics` AND the source IP isn't in `admin.allowed_cidrs`, returns flat 404. Default allow-list is loopback only. This gates *before* anything else.
2. **Bypass paths** — built-in skips for `/health`, `/metrics`, `/waf-api/`, `/socket.io/`, etc. (configurable via `decision.bypass_paths`).
3. **Parse → Normalize** — `internal/parser` + `internal/normalizer` produce a `ParsedRequest`.
4. **IP check** — blacklist/whitelist from `internal/statestore` (in-memory cache synced with Postgres).
5. **Rate limit** — `internal/ratelimit` (Token Bucket per-IP). Repeat offenders auto-added to dynamic blacklist.
6. **Rule engine** — `internal/engine/rule_engine.go` walks `inspect` selectors per rule, applies that rule's transform chain, runs REGEX or TOKEN proximity match. Hits accumulate `anomaly_score × severity_multiplier`.
7. **ML gray-zone hook** — if score ∈ `[ml.gray_lower, ml.gray_upper)` (default `[4.0, 5.0)`), `engine/ml_hook.go` calls `internal/ml.Client.Predict`. On attack with confidence ≥ `ml.confidence_threshold`: score += `ml.attack_bump`. On normal: score -= `ml.normal_penalty`. **Fail-open**: timeout/error leaves score untouched.
8. **Decision** — `internal/decision`: BLOCK ≥ `block_threshold`, CHALLENGE ≥ `challenge_threshold`, else allow.
9. **Audit** — `internal/audit` writes to Postgres + file fallback; `internal/training` mirrors the canonical text to JSONL (daily rotation) for future model fine-tuning.

### MLPredictor interface boundary

`internal/engine/ml_hook.go` declares the `MLPredictor` interface **inside the engine package** (Go idiom: accept interface at the consumer, return struct at the producer). `internal/ml.Client` satisfies it via implicit interface compliance — engine never imports `internal/ml`, breaking what would otherwise be a cycle. The `MLClientAdapter` wraps a raw `func(...)` so unit tests can plug in a mock predictor without spinning up HTTP.

When swapping ML backends (HTTP → gRPC → embedded), add a new implementation of `MLPredictor`. Engine code does not change.

### Rules: v1 + v2 dual schema

`internal/engine/loader.go` accepts both v1 (legacy) and v2 (canonical) rule JSON and converts v1 → v2 on load. `internal/engine/types.go` is the v2 struct (`Rule.Inspect`, `Rule.Detect`, `Rule.Action`, `Rule.Except` — see file header for full notes). Compiled regexes live in `compiledRule` populated lazily via `sync.Once`. Rule file: `configs/rules/all_rules.json`. Hot-reload via `POST /waf-api/rules/upload` (admin-gated).

### Routing convention

`internal/api/handlers.go::RegisterRoutes` uses `http.ServeMux` with **prefix paths** (e.g. `/waf-api/auth/users/`) and parses the trailing ID with `strings.TrimPrefix` + `strings.SplitN`. This is the Go 1.21-compatible style; the codebase deliberately avoids Go 1.22's `{id}` pattern syntax even though `go.mod` declares `go 1.24` — keep this convention when adding routes.

Middleware wrappers:
- `s.requireAuthN(handler)` — any authenticated user (admin/editor/viewer).
- `s.requireAdmin(handler)` — admin only.
- `s.requireAdminForWrite(handler)` — admin only on non-GET methods (read-allowed for non-admin).

### Auth invariants — DO NOT WEAKEN

The auth layer has hard rules that must hold:

1. **No client-controlled role**: `RegisterRequest` (`internal/api/auth_handlers.go`) does NOT have a `Role` field. `handleRegister` hard-codes `role = "viewer"`. Adding a `Role` field to the struct would reopen a privilege-escalation hole. Elevated roles only via admin `POST /waf-api/auth/users`.
2. **Last-admin protection**: Before deleting OR demoting any admin, the handler calls `models.UserRepository.CountByRole("admin")`. Operations that would leave zero admins return 400.
3. **Self-action protection**: Admin cannot delete or demote their own account. Checked at handler AND UI (button disabled in `users.html`) — defense-in-depth.
4. **Old-password requirement**: `PUT /waf-api/auth/me/password` requires the old password — prevents account takeover when only the JWT is stolen.
5. **Role enum at DB level**: `migrations/001_create_users.sql` declares `CHECK (role IN ('admin','editor','viewer'))`. Adding a new role requires a migration.

### Web assets embedding

`web/embed.go` uses `//go:embed *` to bundle all HTML/CSS/JS into the binary at compile time. No separate file server. The pages share a CSS-variable theme system (`[data-theme="dark"]` / `[data-theme="light"]`) plus a pre-paint bootstrap script reading `localStorage.waf_theme` to prevent FOUC. When adding a new page, copy the theme block + toggle button from `settings.html` or `users.html`.

`web/ip_management.html` is dead code — uses an old `/api/ips/*` prefix (current API is `/waf-api/ips/*`) and isn't linked from anywhere. The live IP management UI is the `renderIPs()` tab in `index.html`.

### Config + admin endpoint pairs

Most runtime knobs in `configs/config.yaml` have a corresponding `/waf-api/*` endpoint that mutates them live (persisted via `internal/configstore`). When adding a config field:
1. Add to `pkg/config` struct.
2. Add migration if it needs DB persistence.
3. Add a handler in `internal/api` gated with the right middleware.
4. Surface in `web/waf_config_ui.html` if it's operator-facing.

## Migrations

`migrations/00X_*.sql` is applied in numeric order by the migration runner on WAF startup. Each migration must be idempotent (use `CREATE TABLE IF NOT EXISTS`, `INSERT ... ON CONFLICT DO NOTHING`). To add a migration, create `005_*.sql` — do not edit existing ones.

## ML service contract

`ml-service/app.py` (FastAPI) loads the DistilBERT model from `MODEL_DIR`, exposes:
- `GET /health` — readiness + model version.
- `POST /predict` — request body `{"text": "<canonical>"}`, returns `{"label", "confidence", "latency_ms"}`.
- `POST /predict_batch` — array variant for offline evaluation, NOT on the WAF hot path.

The canonical text format is built by `internal/engine` (Go side) AND `ml-service/app.py` (Python side) — both must produce **byte-identical output** for the same input. There are 7 fixture test cases shared between sides; changes on one side without the other break inference quality silently.

## Default credentials & secrets

- `admin / admin123` — set by `migrations/002_fix_admin_password.sql`. Change immediately in any non-dev environment via the Settings page or `PUT /waf-api/auth/me/password`.
- `auth.jwt_secret` in `configs/config.yaml` is a placeholder — must be replaced for any non-loopback deployment.
- `configs/certs/key.pem` (if generated by `scripts/generate_certs.sh`) is mode 600 and ignored from git — never commit.

## Thesis assets (separate from runtime)

The `thesis/` directory contains LaTeX source for the author's graduation thesis describing this WAF. Six chapter files in `thesis/Chuong/` (1_Gioi_thieu.tex … 6_Ket_luan.tex). These are NOT part of the WAF runtime — do not modify them when working on code changes unless the user explicitly asks for thesis edits. The outline lives in `DATN_outline.md` at the repo root.

## Known dead / WIP files

- `web/ip_management.html` — dead (see above).
- `web/index.html.bak`, `web/index.html.bak2` — leftover backups, safe to delete.
- `model_v6/` — failed model checkpoint kept for reference; production runs `MODEL_DIR=…/final_model_v3` (effectively v5 in the thesis nomenclature).
- `train_export/` — exported training data snapshots, not consumed by runtime.
