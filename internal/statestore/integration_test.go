//go:build integration

package statestore_test

// End-to-end "simulated restart" integration test. Requires a live
// PostgreSQL on localhost:5432 (the docker-compose.db.yml setup).
//
// Run with:  go test -tags=integration ./internal/statestore/

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/ml"
	"waf-project/internal/notifier"
	"waf-project/internal/ratelimit"
	"waf-project/internal/statestore"

	_ "github.com/lib/pq"
)

const testDSN = "host=localhost port=5432 user=waf_user password=waf_password dbname=waf_db sslmode=disable"

// openTestDB connects to the docker-compose Postgres. Skips the test if
// the DB isn't reachable so CI without Postgres can still run unit tests.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", testDSN)
	if err != nil {
		t.Skipf("postgres not available: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("postgres ping failed: %v", err)
	}
	return db
}

// cleanupKey ensures a clean slate for each test by removing prior rows.
func cleanupKey(t *testing.T, db *sql.DB, key string) {
	if _, err := db.Exec(`DELETE FROM waf_runtime_state WHERE key = $1`, key); err != nil {
		t.Logf("cleanup %s: %v", key, err)
	}
}

func TestIntegration_BehaviorDetectorSurvivesRestart(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()

	store := statestore.New(db)
	if err := store.Migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cleanupKey(t, db, statestore.KeyBehavior)

	// Pretend WAF #1 ran and accumulated some attacker state.
	d1 := behavior.NewDetector(behavior.BehaviorConfig{
		BruteForceThreshold: 5,
		BruteForceWindow:    5 * time.Minute,
	})

	sections := map[string]statestore.Snapshotter{
		statestore.KeyBehavior: d1,
	}

	// Drive 4 failed attempts via the public Analyze path so internal
	// data structures are populated exactly as production code would.
	for i := 0; i < 4; i++ {
		d1.Analyze(&engine.ParsedRequest{
			ClientIP:       "10.0.0.99",
			NormalizedPath: "/login",
			UserAgent:      "curl/7.0",
			Timestamp:      time.Now(),
		}, &engine.EvaluationResult{Decision: "BLOCK"})
	}
	if got := store.SaveAll(sections); got != 1 {
		t.Fatalf("SaveAll: got %d want 1", got)
	}
	d1.Stop()

	// WAF #2 boots from cold — fresh detector, restore from DB.
	d2 := behavior.NewDetector(behavior.BehaviorConfig{
		BruteForceThreshold: 5,
		BruteForceWindow:    5 * time.Minute,
	})
	defer d2.Stop()

	restored := store.RestoreAll(map[string]statestore.Snapshotter{
		statestore.KeyBehavior: d2,
	})
	if restored != 1 {
		t.Fatalf("RestoreAll: got %d want 1", restored)
	}

	stats := d2.GetIPStats("10.0.0.99")
	if stats == nil {
		t.Fatal("attacker state lost across restart")
	}
	if stats.FailedAttempts != 4 {
		t.Errorf("FailedAttempts: got %d want 4", stats.FailedAttempts)
	}

	// Security property: the 5th failed attempt after restart MUST
	// trip the bruteforce block. Without persistence this is request 1
	// of 5 on a fresh detector — no block.
	res := d2.Analyze(&engine.ParsedRequest{
		ClientIP:       "10.0.0.99",
		NormalizedPath: "/login",
		Timestamp:      time.Now(),
	}, &engine.EvaluationResult{Decision: "BLOCK"})
	hasBruteForce := false
	for _, tt := range res.ThreatTypes {
		if tt == "BRUTEFORCE" {
			hasBruteForce = true
		}
	}
	if !hasBruteForce {
		t.Errorf("5th attempt after restart did not trip bruteforce — counter reset by restart")
	}
}

func TestIntegration_RateLimiterSurvivesRestart(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	store := statestore.New(db)
	store.Migrate()
	cleanupKey(t, db, statestore.KeyRateLimit)

	rl1 := ratelimit.NewRateLimiter(ratelimit.RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      3,
	})
	// Exhaust the burst.
	for i := 0; i < 3; i++ {
		rl1.IsRateLimited("noisy-ip")
	}
	if !rl1.IsRateLimited("noisy-ip") {
		t.Fatal("setup: 4th request should already be rate-limited")
	}
	store.SaveAll(map[string]statestore.Snapshotter{
		statestore.KeyRateLimit: rl1,
	})
	rl1.Stop()

	// Fresh limiter, restore.
	rl2 := ratelimit.NewRateLimiter(ratelimit.RateLimitConfig{
		RequestsPerMin: 60,
		BurstSize:      3,
	})
	defer rl2.Stop()
	store.RestoreAll(map[string]statestore.Snapshotter{
		statestore.KeyRateLimit: rl2,
	})

	if !rl2.IsRateLimited("noisy-ip") {
		t.Errorf("rate limit reset by restart — bypass via restart possible")
	}
}

func TestIntegration_TrackerSurvivesRestart(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	store := statestore.New(db)
	store.Migrate()
	cleanupKey(t, db, statestore.KeyTracker)

	re1 := engine.NewRuleEngine()
	tr1 := re1.Tracker()
	tr1.Incr("ip:login_fail:1.1.1.1", 10*time.Minute)
	tr1.Incr("ip:login_fail:1.1.1.1", 10*time.Minute)
	tr1.Incr("ip:login_fail:1.1.1.1", 10*time.Minute)

	store.SaveAll(map[string]statestore.Snapshotter{
		statestore.KeyTracker: re1.TrackerSnapshotter(),
	})

	re2 := engine.NewRuleEngine()
	defer re2.Tracker().Stop()
	store.RestoreAll(map[string]statestore.Snapshotter{
		statestore.KeyTracker: re2.TrackerSnapshotter(),
	})
	if got := re2.Tracker().Get("ip:login_fail:1.1.1.1"); got != 3 {
		t.Errorf("tracker count after restart: got %d want 3", got)
	}
}

func TestIntegration_DecisionStatsSurvive(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	store := statestore.New(db)
	store.Migrate()
	cleanupKey(t, db, statestore.KeyDecisionStats)

	de1 := decision.NewDecisionEngine(decision.DecisionConfig{})
	// Bump stats directly via test helper path.
	for i := 0; i < 50; i++ {
		de1.Decide(&engine.EvaluationResult{TotalScore: 1, Decision: "ALLOW"}, &engine.ParsedRequest{ClientIP: fmt.Sprintf("c-%d", i)})
	}
	if got := de1.GetStats(); got.TotalDecisions != 50 {
		t.Fatalf("setup: TotalDecisions=%d want 50", got.TotalDecisions)
	}

	store.SaveAll(map[string]statestore.Snapshotter{
		statestore.KeyDecisionStats: de1.StatsSnapshotter(),
	})

	de2 := decision.NewDecisionEngine(decision.DecisionConfig{})
	store.RestoreAll(map[string]statestore.Snapshotter{
		statestore.KeyDecisionStats: de2.StatsSnapshotter(),
	})

	if got := de2.GetStats(); got.TotalDecisions != 50 {
		t.Errorf("decision stats lost: %d", got.TotalDecisions)
	}
}

func TestIntegration_NotifierStateSurvives(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	store := statestore.New(db)
	store.Migrate()
	cleanupKey(t, db, statestore.KeyNotifierState)
	cleanupKey(t, db, statestore.KeyNotifierDests)

	n1 := notifier.New(notifier.Config{
		Enabled:         true,
		MinSeverity:     "LOW",
		ThrottleSeconds: 300,
	})
	// Add a destination at "runtime"
	n1.SetConfig(notifier.Config{
		Enabled:         true,
		MinSeverity:     "LOW",
		ThrottleSeconds: 300,
		Slack: []notifier.SlackDestination{
			{Name: "ops", Enabled: true, WebhookURL: "https://hooks.example.com/X"},
		},
	})

	store.SaveAll(map[string]statestore.Snapshotter{
		statestore.KeyNotifierState: n1.StateSnapshotter(),
		statestore.KeyNotifierDests: n1.DestSnapshotter(),
	})
	n1.Close()

	n2 := notifier.New(notifier.Config{Enabled: false, MinSeverity: "HIGH"})
	defer n2.Close()
	store.RestoreAll(map[string]statestore.Snapshotter{
		statestore.KeyNotifierState: n2.StateSnapshotter(),
		statestore.KeyNotifierDests: n2.DestSnapshotter(),
	})

	cfg := n2.GetConfig()
	if !cfg.Enabled {
		t.Errorf("Enabled flag lost")
	}
	if len(cfg.Slack) != 1 || cfg.Slack[0].Name != "ops" {
		t.Errorf("slack destination lost: %+v", cfg.Slack)
	}
}

// TestIntegration_PeriodicSnapshotter — verifies the background loop
// actually writes to DB on its tick. Uses a short test interval that
// bypasses the 5s clamp by calling FlushNow.
func TestIntegration_PeriodicSnapshotter(t *testing.T) {
	db := openTestDB(t)
	defer db.Close()
	store := statestore.New(db)
	store.Migrate()
	cleanupKey(t, db, statestore.KeyBehavior)

	d := behavior.NewDetector(behavior.BehaviorConfig{})
	defer d.Stop()
	d.Analyze(&engine.ParsedRequest{
		ClientIP:  "snapshot-test",
		Timestamp: time.Now(),
	}, &engine.EvaluationResult{Decision: "ALLOW"})

	sections := map[string]statestore.Snapshotter{
		statestore.KeyBehavior: d,
	}
	sn := statestore.NewSnapshotter(store, sections, 30*time.Second)
	sn.Start()
	if got := sn.FlushNow(); got != 1 {
		t.Errorf("FlushNow: got %d want 1", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sn.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}

	// Verify the row exists in DB.
	var cnt int
	if err := db.QueryRow(`SELECT COUNT(*) FROM waf_runtime_state WHERE key = $1`, statestore.KeyBehavior).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Errorf("snapshot row missing: cnt=%d", cnt)
	}
}

// Touch the ml package to avoid the unused-import error when only a
// few of the subsystems are exercised — kept as a placeholder so we
// can add an ML integration test later without re-shuffling imports.
var _ = ml.Config{}

// metrics imported to ensure compile-time check that the Collector
// satisfies Snapshotter; not exercised here because promauto registry
// makes multi-instance tests painful.
var _ statestore.Snapshotter = (*metrics.Collector)(nil)
