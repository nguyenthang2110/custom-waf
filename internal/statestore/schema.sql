CREATE TABLE IF NOT EXISTS waf_runtime_state (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_runtime_state_updated_at
    ON waf_runtime_state (updated_at DESC);
