-- Migration: Persist runtime WAF configuration so dashboard changes survive restarts.
-- Version: 003
-- Description: Key/value store for live config sections (decision, rate_limit, backend).
--
-- Each section is stored as a row keyed by name. The value is JSONB so we can
-- evolve the shape without ALTERing the table. The YAML config remains the
-- bootstrap default — DB rows are overlays applied on top at startup.

CREATE TABLE IF NOT EXISTS waf_runtime_config (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_runtime_config_updated_at
    ON waf_runtime_config (updated_at DESC);
