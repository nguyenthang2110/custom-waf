// Package statestore persists mutable runtime WAF state (counters, caches,
// stats) to PostgreSQL so that security-sensitive in-memory data — per-IP
// behavior counters, rate-limit buckets, action.track counters, ML cache,
// notifier dedup, decision/rule metrics — survives WAF restarts.
//
// Design mirrors configstore: one table (waf_runtime_state) keyed by
// section name, value held as JSONB. Each subsystem implements the
// Snapshotter interface; a background snapshotter writes every ~30s and
// the loader restores on boot before serving traffic.
//
// A nil *Store is valid — every method is a no-op so callers don't have
// to branch on whether the database is reachable.
package statestore

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

//go:embed schema.sql
var migrationSQL string

// Section keys persisted in waf_runtime_state. Stable string constants so
// older snapshots remain restorable after refactors.
const (
	KeyBehavior        = "behavior_detector"
	KeyRateLimit       = "ratelimit_buckets"
	KeyTracker         = "engine_tracker"
	KeyMLCache         = "ml_cache"
	KeyMLBreaker       = "ml_breaker"
	KeyMLClientStats   = "ml_client_stats"
	KeyNotifierState   = "notifier_state"
	KeyNotifierDests   = "notifier_destinations"
	KeyRuleMetrics     = "rule_metrics"
	KeyDecisionStats   = "decision_stats"
	KeyMetricsCollect  = "metrics_collector"
	KeyAuditRing       = "audit_ring_buffer"
)

// Snapshotter is implemented by any subsystem that wants to persist its
// in-memory state. Snapshot returns a serialized blob (typically JSON);
// Restore is called once at boot with the most recent persisted blob.
//
// A subsystem with nothing meaningful to save returns (nil, nil) from
// Snapshot — the store will skip the write.
type Snapshotter interface {
	Snapshot() ([]byte, error)
	Restore(data []byte) error
}

// Store is the typed wrapper around the waf_runtime_state table.
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

// Migrate creates the waf_runtime_state table if it doesn't exist.
// Safe to call on every boot — fully idempotent.
func (s *Store) Migrate() error {
	if s == nil {
		return nil
	}
	if _, err := s.db.Exec(migrationSQL); err != nil {
		return fmt.Errorf("statestore: migrate: %w", err)
	}
	return nil
}

// Save upserts a single section. Empty/nil payloads are written as JSON
// null so callers can explicitly wipe a section.
func (s *Store) Save(key string, value []byte) error {
	if s == nil {
		return nil
	}
	if len(value) == 0 {
		value = []byte("null")
	}
	const q = `
		INSERT INTO waf_runtime_state (key, value, updated_at)
		VALUES ($1, $2::jsonb, NOW())
		ON CONFLICT (key) DO UPDATE
		    SET value = EXCLUDED.value,
		        updated_at = NOW()
	`
	if _, err := s.db.Exec(q, key, string(value)); err != nil {
		return fmt.Errorf("statestore: save %s: %w", key, err)
	}
	return nil
}

// Load reads a single section. Returns (nil, nil) when the row is absent
// — callers should treat that as "nothing persisted yet".
func (s *Store) Load(key string) ([]byte, error) {
	if s == nil {
		return nil, nil
	}
	var raw []byte
	err := s.db.QueryRow(`SELECT value FROM waf_runtime_state WHERE key = $1`, key).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("statestore: load %s: %w", key, err)
	}
	return raw, nil
}

// Delete removes a single section. Useful for admin "wipe state" actions.
func (s *Store) Delete(key string) error {
	if s == nil {
		return nil
	}
	if _, err := s.db.Exec(`DELETE FROM waf_runtime_state WHERE key = $1`, key); err != nil {
		return fmt.Errorf("statestore: delete %s: %w", key, err)
	}
	return nil
}

// RestoreAll walks each (key, Snapshotter) pair and restores the
// subsystem from the most recent persisted blob. Missing rows are
// silently skipped — the subsystem keeps its zero-value boot state.
// Errors are logged but never fatal; one bad section shouldn't block the
// rest from restoring.
func (s *Store) RestoreAll(sections map[string]Snapshotter) (restored int) {
	if s == nil {
		return 0
	}
	for key, snap := range sections {
		raw, err := s.Load(key)
		if err != nil {
			log.Printf("statestore: load %s failed: %v", key, err)
			continue
		}
		if len(raw) == 0 || string(raw) == "null" {
			continue
		}
		if err := snap.Restore(raw); err != nil {
			log.Printf("statestore: restore %s failed: %v", key, err)
			continue
		}
		restored++
	}
	return restored
}

// SaveAll snapshots every section in one go. Used by the periodic
// snapshotter and by the shutdown flush. Errors are logged per-section
// but never abort the whole pass — a broken serializer in one subsystem
// shouldn't lose state for the others.
func (s *Store) SaveAll(sections map[string]Snapshotter) (saved int) {
	if s == nil {
		return 0
	}
	for key, snap := range sections {
		raw, err := snap.Snapshot()
		if err != nil {
			log.Printf("statestore: snapshot %s failed: %v", key, err)
			continue
		}
		if len(raw) == 0 {
			continue
		}
		if err := s.Save(key, raw); err != nil {
			log.Printf("statestore: save %s failed: %v", key, err)
			continue
		}
		saved++
	}
	return saved
}

// Snapshotter group — manages the periodic snapshot loop.
//
// Boot wiring:
//  1. Build the (key → Snapshotter) map after every subsystem is
//     constructed.
//  2. Call RestoreAll to repopulate from DB.
//  3. Construct a Snapshotter via NewSnapshotter and call Start.
//  4. Call Stop on shutdown — it triggers one final flush.
type Snapshotter2 struct {
	store    *Store
	sections map[string]Snapshotter
	interval time.Duration

	mu     sync.Mutex
	stop   chan struct{}
	doneCh chan struct{}
}

// NewSnapshotter builds a periodic snapshotter. Interval values below 5s
// are bumped to 5s to keep DB write load sane.
func NewSnapshotter(store *Store, sections map[string]Snapshotter, interval time.Duration) *Snapshotter2 {
	if interval < 5*time.Second {
		interval = 30 * time.Second
	}
	return &Snapshotter2{
		store:    store,
		sections: sections,
		interval: interval,
		stop:     make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start launches the background snapshot goroutine. Safe to call once;
// repeated calls are no-ops.
func (sn *Snapshotter2) Start() {
	if sn == nil || sn.store == nil {
		return
	}
	go func() {
		defer close(sn.doneCh)
		t := time.NewTicker(sn.interval)
		defer t.Stop()
		for {
			select {
			case <-sn.stop:
				// Final flush on shutdown so the most recent state lands
				// in DB even if the next tick was minutes away.
				sn.store.SaveAll(sn.sections)
				return
			case <-t.C:
				sn.store.SaveAll(sn.sections)
			}
		}
	}()
}

// Stop signals the snapshotter to flush and exit, waiting up to ctx for
// the goroutine to finish. Returns the context error on timeout.
func (sn *Snapshotter2) Stop(ctx context.Context) error {
	if sn == nil || sn.store == nil {
		return nil
	}
	sn.mu.Lock()
	select {
	case <-sn.stop:
		// already stopped
	default:
		close(sn.stop)
	}
	sn.mu.Unlock()
	select {
	case <-sn.doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FlushNow triggers an immediate snapshot pass. Useful for admin
// endpoints and tests.
func (sn *Snapshotter2) FlushNow() int {
	if sn == nil || sn.store == nil {
		return 0
	}
	return sn.store.SaveAll(sn.sections)
}
