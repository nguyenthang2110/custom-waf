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

`MODEL_DIR` defaults to `$(CURDIR)/model_v7/final_model_v7` — the in-repo v7 model (the `model_v*/` dir is `.gitignore`d, so the ~268 MB weights are never committed). The 10-class DistilBERT v7 model (`label_config.json`: normal + sqli/xss/cmdi/path_traversal/ssrf/xxe/log4shell/ssti/nosqli, `max_length` 256). Override on another machine:

```bash
make run MODEL_DIR=/abs/path/to/final_model_v7
# or set persistently:
export MODEL_DIR=/abs/path/to/final_model_v7
```

If `MODEL_DIR` doesn't exist, `ml-start` fails fast with a clear message.

## High-level architecture

### Request lifecycle (per HTTP request)

The pipeline lives in `cmd/waf/main.go`, which wires `internal/middleware/waf.go` in front of `httputil.ReverseProxy`. Each request flows through (in order):

1. **Admin access control** (`adminAccessControl` in main.go) — if the request hits `/dashboard/*`, `/login.html`, `/waf-api/*`, `/admin/*`, or `/metrics` AND the source IP isn't in `admin.allowed_cidrs`, returns flat 404. Default allow-list is loopback only. This gates *before* anything else.
2. **Bypass paths** — built-in skips only (`BypassReason` returns `health` for `/health`,`/healthz`,`/ping`,`/status`,`/metrics`,`/dashboard`,`/waf-api/` or `realtime` for `/socket.io/`,`/sockjs-node/`,`/ws/`). These lists are hardcoded; there is no operator-configurable bypass list (the old `decision.bypass_paths` knob was removed).
3. **Parse → Normalize** — `internal/parser` + `internal/normalizer` produce a `ParsedRequest`.
4. **IP check** — blacklist/whitelist from `internal/statestore` (in-memory cache synced with Postgres).
5. **Rate limit** — `internal/ratelimit` (Token Bucket per-IP). Repeat offenders auto-added to dynamic blacklist.
6. **Rule engine** — `internal/engine/rule_engine.go` walks `inspect` selectors per rule, applies that rule's transform chain, runs REGEX or TOKEN proximity match. Hits accumulate `anomaly_score × severity_multiplier`.
7. **ML gray-zone hook** — if score ∈ `[ml.gray_lower, ml.gray_upper)` (default `[3.0, 5.0)`), `middleware.runMLInference` calls `internal/ml.Client.Predict`. On attack with confidence ≥ `ml.confidence_threshold`: score += `ml.attack_bump` (→ typically BLOCK). On confident normal: score is **cleared to 0** (→ ALLOW; at least `ml.normal_penalty` is subtracted) — this is what lets the model rescue a matched-rule request from the MONITOR flag. **Fail-open**: timeout/error/low-confidence leaves score untouched (stays MONITOR).
8. **Decision** — `internal/decision`: two verdict tiers — BLOCK ≥ `block_threshold` (reject, 403) and MONITOR (forward to upstream but flag as suspicious in the access log) for any request that scored **> 0** (matched ≥1 rule). Only a fully-clean request (score 0) is ALLOW. `monitor_threshold` defaults to **0** ("any positive score") and is tunable live via `POST /waf-api/config` to suppress low-score noise. The ML gray-zone hook (step 7) can clear a confidently-normal request back to score 0 → ALLOW *before* this step, which is how the model removes gray-zone false positives. There is NO challenge/PoW tier — it was removed (the old `ChallengeEnabled` was never set, so it never fired).
9. **Logging** — two separate streams, both via the generic `internal/audit` logger (a rotating JSON-lines **file** + an in-memory ring buffer for the dashboard; **no Postgres** persistence for logs):
   - **Access log** (`access_log.log_path`, default `./logs/waf/access.log`) — every HTTP request + its WAF verdict (ALLOW/MONITOR/BLOCK), matched rules, anomaly score. High-volume traffic record. Written by `middleware.logAccessEntry`/`logWhitelistEntry` → `AccessLogger`. Dashboard: `/waf-api/logs*` (the "Access Log" tab).
   - **Audit log** (`audit_log.log_path`, default `./logs/waf/audit.log`) — admin & security events only (login, user CRUD, config changes, rule uploads, rate-limit trips). Low-volume accountability trail. Written by `LogSystemEvent`/`LogSecurityEvent` → `AuditLogger`. Dashboard: `/waf-api/audit*` (admin-only, the "Audit Log" tab).

   The two share the `audit.Logger` implementation and `audit.AuditEntry` record type but are **distinct logger instances + files + ring buffers**; do not merge them. `internal/training` separately mirrors the canonical text to JSONL (daily rotation) for future model fine-tuning.

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

1. **No public registration**: there is NO self-service sign-up endpoint or page. Accounts are created exclusively by an admin via `POST /waf-api/auth/users` (`handleAdminCreateUser`, admin-gated). The first admin (`admin/admin`) is seeded by `migrations/005_default_admin_password.sql`. Do NOT re-add a `/waf-api/auth/register` route, a `handleRegister` handler, or a `register.html` page — that would reopen an anonymous account-creation / privilege-escalation surface.
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

- `admin / admin` — the only bootstrap account, seeded by `migrations/005_default_admin_password.sql` (supersedes the earlier `admin/admin123` from `002`). There is no public registration, so this is the sole way in on a fresh DB. Change immediately in any non-dev environment via the Settings page or `PUT /waf-api/auth/me/password`.
- `auth.jwt_secret` in `configs/config.yaml` is a placeholder — must be replaced for any non-loopback deployment.
- `configs/certs/key.pem` (if generated by `scripts/generate_certs.sh`) is mode 600 and ignored from git — never commit.

## Thesis assets (separate from runtime)

The `thesis/` directory contains LaTeX source for the author's graduation thesis describing this WAF. Six chapter files in `thesis/Chuong/` (1_Gioi_thieu.tex … 6_Ket_luan.tex). These are NOT part of the WAF runtime — do not modify them when working on code changes unless the user explicitly asks for thesis edits. The outline lives in `DATN_outline.md` at the repo root.

## Known dead / WIP files

- `web/ip_management.html` — dead (see above).
- `web/index.html.bak`, `web/index.html.bak2` — leftover backups, safe to delete.
- `model_v7/` — current production model (`final_model_v7/` is what `MODEL_DIR` points to; also ships training `checkpoints/` + `confusion_v7.png`). 10-class, macro-F1 0.9959. `model_v6/` was a failed checkpoint (accuracy 0.8866, blocked by the hard gate); earlier `…/BERT/model/final_model_v3` was the v5 baseline.
- `train_export/` — exported training data snapshots, not consumed by runtime.
