// Package configstore persists runtime WAF configuration to PostgreSQL so
// dashboard edits (thresholds, rate limits, bypass paths, backend URL) survive
// restarts. The YAML file is still the bootstrap default — DB rows are
// overlays applied on top during startup.
package configstore

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/ratelimit"
)

// migrationSQL is the schema applied on first boot. Embedded so the binary
// is self-contained and admins don't need to run psql by hand.
//
//go:embed schema.sql
var migrationSQL string

// Keys used as primary keys in waf_runtime_config. Each section round-trips
// independently so a partial update doesn't have to rewrite the whole blob.
const (
	KeyDecision  = "decision"
	KeyRateLimit = "rate_limit"
	KeyBackend   = "backend"
	KeyWhitelist = "whitelist_ips"
	KeyBlacklist = "blacklist_ips"
	KeyML        = "ml"
	KeyBehavior  = "behavior"
)

// Store is the typed wrapper around the waf_runtime_config table.
// A nil *Store is valid — every method is a no-op so callers don't need
// to branch on whether the database is reachable.
type Store struct {
	db *sql.DB
}

// New returns a Store backed by db, or nil if db is nil.
func New(db *sql.DB) *Store {
	if db == nil {
		return nil
	}
	return &Store{db: db}
}

// Migrate creates the waf_runtime_config table if it doesn't exist.
// Safe to call on every boot — the SQL is fully idempotent.
func (s *Store) Migrate() error {
	if s == nil {
		return nil
	}
	if _, err := s.db.Exec(migrationSQL); err != nil {
		return fmt.Errorf("configstore: migrate: %w", err)
	}
	return nil
}

// Save upserts a single config section.
func (s *Store) Save(key string, value any) error {
	if s == nil {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("configstore: marshal %s: %w", key, err)
	}
	const q = `
		INSERT INTO waf_runtime_config (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE
		    SET value = EXCLUDED.value,
		        updated_at = NOW()
	`
	if _, err := s.db.Exec(q, key, raw); err != nil {
		return fmt.Errorf("configstore: save %s: %w", key, err)
	}
	return nil
}

// LoadInto reads every persisted section and applies it to the live
// components. Returns the number of sections that were actually applied so
// callers can log a single line. Missing sections are silently skipped —
// they just mean the YAML bootstrap value is in effect.
//
// wafBackend can be nil if the WAF middleware isn't yet wired up; in that
// case the persisted backend URL is returned via outBackend so the caller
// can apply it manually.
func (s *Store) LoadInto(
	de *decision.DecisionEngine,
	rl *ratelimit.RateLimiter,
	bd *behavior.Detector,
	wafBackend BackendUpdater,
) (applied int, outBackend string, err error) {
	if s == nil {
		return 0, "", nil
	}
	rows, err := s.db.Query(`SELECT key, value FROM waf_runtime_config`)
	if err != nil {
		return 0, "", fmt.Errorf("configstore: load: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return applied, outBackend, fmt.Errorf("configstore: scan: %w", err)
		}

		switch key {
		case KeyDecision:
			var d struct {
				BlockThreshold   float64 `json:"block_threshold"`
				MonitorThreshold float64 `json:"monitor_threshold"`
			}
			if err := json.Unmarshal(raw, &d); err != nil {
				return applied, outBackend, fmt.Errorf("configstore: decode decision: %w", err)
			}
			cfg := de.GetConfig()
			if d.BlockThreshold > 0 {
				cfg.BlockThreshold = d.BlockThreshold
			}
			if d.MonitorThreshold > 0 {
				cfg.MonitorThreshold = d.MonitorThreshold
			}
			de.SetConfig(cfg)
			applied++

		case KeyRateLimit:
			var r struct {
				RequestsPerMin int                              `json:"requests_per_min"`
				BurstSize      int                              `json:"burst_size"`
				EndpointLimits map[string]ratelimit.LimitConfig `json:"endpoint_limits"`
			}
			if err := json.Unmarshal(raw, &r); err != nil {
				return applied, outBackend, fmt.Errorf("configstore: decode rate_limit: %w", err)
			}
			cfg := rl.GetConfig()
			if r.RequestsPerMin > 0 {
				cfg.RequestsPerMin = r.RequestsPerMin
			}
			if r.BurstSize > 0 {
				cfg.BurstSize = r.BurstSize
			}
			if r.EndpointLimits != nil {
				cfg.EndpointLimits = r.EndpointLimits
			}
			rl.SetConfig(cfg)
			applied++

		case KeyBehavior:
			if bd == nil {
				continue
			}
			var b struct {
				BruteForceThreshold int `json:"bruteforce_threshold"`
				BruteForceWindowSec int `json:"bruteforce_window_sec"`
				BlockDurationSec    int `json:"block_duration_sec"`
			}
			if err := json.Unmarshal(raw, &b); err != nil {
				return applied, outBackend, fmt.Errorf("configstore: decode behavior: %w", err)
			}
			cfg := bd.GetConfig()
			if b.BruteForceThreshold > 0 {
				cfg.BruteForceThreshold = b.BruteForceThreshold
			}
			if b.BruteForceWindowSec > 0 {
				cfg.BruteForceWindow = time.Duration(b.BruteForceWindowSec) * time.Second
			}
			if b.BlockDurationSec > 0 {
				cfg.BlockDuration = time.Duration(b.BlockDurationSec) * time.Second
			}
			bd.SetConfig(cfg)
			applied++

		case KeyML:
			// Only restorable when the WAF middleware implements the applier.
			applier, ok := wafBackend.(MLConfigApplier)
			if !ok {
				continue
			}
			var m struct {
				Enabled             bool    `json:"enabled"`
				AttackBump          float64 `json:"attack_bump"`
				NormalPenalty       float64 `json:"normal_penalty"`
				ConfidenceThreshold float64 `json:"confidence_threshold"`
			}
			if err := json.Unmarshal(raw, &m); err != nil {
				return applied, outBackend, fmt.Errorf("configstore: decode ml: %w", err)
			}
			applier.SetMLSettings(m.Enabled, m.AttackBump, m.NormalPenalty, m.ConfidenceThreshold)
			applied++

		case KeyBackend:
			var b struct {
				URL string `json:"url"`
			}
			if err := json.Unmarshal(raw, &b); err != nil {
				return applied, outBackend, fmt.Errorf("configstore: decode backend: %w", err)
			}
			if b.URL == "" {
				continue
			}
			outBackend = b.URL
			if wafBackend != nil {
				if err := wafBackend.UpdateBackend(b.URL); err != nil {
					return applied, outBackend, fmt.Errorf("configstore: apply backend: %w", err)
				}
				applied++
			}

		case KeyWhitelist:
			// v2 format is []IPListEntry with {ip, expires_at}.
			// v1 format was []string (permanent only). Try v2 first, fall
			// back to v1 so older rows still load cleanly.
			var entries []decision.IPListEntry
			if err := json.Unmarshal(raw, &entries); err == nil && len(entries) > 0 {
				de.SetWhitelistEntries(entries)
			} else {
				var ips []string
				if err := json.Unmarshal(raw, &ips); err != nil {
					return applied, outBackend, fmt.Errorf("configstore: decode whitelist: %w", err)
				}
				de.SetWhitelistIPs(ips)
			}
			applied++

		case KeyBlacklist:
			var entries []decision.IPListEntry
			if err := json.Unmarshal(raw, &entries); err == nil && len(entries) > 0 {
				de.SetBlacklistEntries(entries)
			} else {
				var ips []string
				if err := json.Unmarshal(raw, &ips); err != nil {
					return applied, outBackend, fmt.Errorf("configstore: decode blacklist: %w", err)
				}
				de.SetBlacklistIPs(ips)
			}
			applied++

		default:
			// Unknown key — ignore so old binaries don't choke on rows
			// written by newer versions.
		}
	}
	if err := rows.Err(); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return applied, outBackend, fmt.Errorf("configstore: rows: %w", err)
	}
	return applied, outBackend, nil
}

// BackendUpdater is the slice of WAFMiddleware needed to swap the upstream URL.
type BackendUpdater interface {
	UpdateBackend(url string) error
}

// MLConfigApplier is the optional slice of WAFMiddleware needed to restore the
// persisted ML gray-zone knobs. LoadInto type-asserts the BackendUpdater to
// this so older callers (and tests) that don't implement it still compile.
type MLConfigApplier interface {
	SetMLSettings(enabled bool, attackBump, normalPenalty, confidence float64)
}
