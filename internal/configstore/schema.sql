CREATE TABLE IF NOT EXISTS waf_runtime_config (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_runtime_config_updated_at
    ON waf_runtime_config (updated_at DESC);
