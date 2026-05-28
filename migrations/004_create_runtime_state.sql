-- Migration: Persist runtime WAF state (counters, caches, stats) so security
-- and observability data survives WAF restarts.
-- Version: 004
-- Description: Generic key/value store for live runtime state snapshots.
--
-- Mirrors waf_runtime_config but holds the mutable runtime side: per-IP
-- behavior counters, rate-limit token buckets, action.track counters, ML
-- cache, notifier dedup/stats, decision/rule/metrics counters. Each
-- subsystem owns one row, snapshot-serialized as JSONB. The background
-- snapshotter writes every ~30s; on boot the loader restores each row
-- before traffic is accepted.
--
-- We keep state and config in separate tables so a "wipe runtime state"
-- admin action can TRUNCATE this without touching config.

CREATE TABLE IF NOT EXISTS waf_runtime_state (
    key        TEXT PRIMARY KEY,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_waf_runtime_state_updated_at
    ON waf_runtime_state (updated_at DESC);
