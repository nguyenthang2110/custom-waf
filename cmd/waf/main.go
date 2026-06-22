// cmd/waf/main.go - WITH DASHBOARD
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"waf-project/internal/api"
	"waf-project/internal/audit"
	"waf-project/internal/behavior"
	"waf-project/internal/configstore"
	"waf-project/internal/database"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/middleware"
	"waf-project/internal/ml"
	"waf-project/internal/normalizer"
	"waf-project/internal/notifier"
	"waf-project/internal/parser"
	"waf-project/internal/ratelimit"
	"waf-project/internal/statestore"
	"waf-project/internal/training"
	"waf-project/pkg/config"
	"waf-project/web"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// adminAccessControl wraps a handler so requests from outside the configured
// admin allow-list get a flat 404 — outsiders shouldn't even discover that an
// admin UI exists. When LocalOnly is false the wrapper is identity.
//
// We parse CIDRs once at startup and keep them in a slice; lookup is O(N)
// over a tiny list (usually 1-2 entries) so a trie isn't worth it.
type adminAccessControl struct {
	enabled bool
	allowed []*net.IPNet
}

func newAdminAccessControl(cfg config.AdminConfig) *adminAccessControl {
	ac := &adminAccessControl{enabled: cfg.LocalOnly}
	if !ac.enabled {
		return ac
	}
	for _, c := range cfg.AllowedCIDRs {
		// Bare IP → /32 (IPv4) or /128 (IPv6)
		if !strings.Contains(c, "/") {
			ip := net.ParseIP(c)
			if ip == nil {
				log.Printf("⚠️  admin.allowed_cidrs: skip invalid entry %q", c)
				continue
			}
			if ip.To4() != nil {
				c = c + "/32"
			} else {
				c = c + "/128"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			log.Printf("⚠️  admin.allowed_cidrs: skip %q (%v)", c, err)
			continue
		}
		ac.allowed = append(ac.allowed, n)
	}
	return ac
}

func (ac *adminAccessControl) check(r *http.Request) bool {
	if !ac.enabled {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, n := range ac.allowed {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Wrap returns a handler that returns 404 for disallowed clients.
func (ac *adminAccessControl) Wrap(next http.Handler) http.Handler {
	if !ac.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ac.check(r) {
			http.NotFound(w, r) // 404 — hide that this exists
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WrapFunc — same as Wrap but for http.HandlerFunc.
func (ac *adminAccessControl) WrapFunc(next http.HandlerFunc) http.HandlerFunc {
	if !ac.enabled {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !ac.check(r) {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to config file")
	rulesPath  = flag.String("rules", "configs/rules/all_rules.json", "Path to rules file")
	version    = flag.String("version", "1.0.0", "WAF version")
)

// classifySystemEventSeverity maps known system event types to alert
// severities so the notifier's MinSeverity gate stays meaningful.
//
//   - HIGH   — anything *_ERROR, plus admin actions that mutate WAF
//     behaviour or audit trails (config changes, log purges, role/user
//     deletions, password resets). These pass the default min_severity=HIGH
//     out of the box.
//   - MEDIUM — admin-initiated but lower-impact account ops
//     (user/email creation, password change).
//   - INFO   — operational chatter (login, register, profile edit).
//
// LogSecurityEvent may override via Metadata["severity"], which always wins.
func classifySystemEventSeverity(eventType string) string {
	if strings.HasSuffix(eventType, "_ERROR") {
		return "HIGH"
	}
	switch eventType {
	case "CONFIG_CHANGE",
		"LOGS_CLEARED",
		"USER_DELETED",
		"USER_ROLE_CHANGED",
		"USER_PASSWORD_RESET_BY_ADMIN":
		return "HIGH"
	case "USER_CREATED_BY_ADMIN",
		"USER_EMAIL_CHANGED_BY_ADMIN",
		"USER_PASSWORD_CHANGED":
		return "MEDIUM"
	}
	return "INFO"
}

func main() {
	flag.Parse()

	printBanner()

	log.Printf("Starting WAF v%s", *version)
	log.Printf("Config: %s", *configPath)
	log.Printf("Rules: %s", *rulesPath)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("WAF listening on %s", cfg.Server.Listen)
	log.Printf("Upstream backend: %s", cfg.Upstream.URL)
	log.Printf("Dashboard: http://%s/dashboard", cfg.Server.Listen)

	// Initialize components
	log.Println("Initializing components...")

	httpParser := parser.NewHTTPParser(cfg.Parser.MaxBodySize)
	log.Println("✓ HTTP Parser initialized")

	norm := normalizer.NewNormalizer()
	log.Println("✓ Normalizer initialized")

	ruleEngine := engine.NewRuleEngine()
	log.Println("✓ Rule Engine initialized")

	// Load rules
	if err := ruleEngine.LoadRulesFromFile(*rulesPath); err != nil {
		log.Fatalf("Failed to load rules: %v", err)
	}
	log.Printf("✓ Loaded %d rules successfully", ruleEngine.RuleCount())

	rateLimiter := ratelimit.NewRateLimiter(ratelimit.RateLimitConfig{
		RequestsPerMin: cfg.RateLimit.RequestsPerMin,
		BurstSize:      cfg.RateLimit.BurstSize,
		EndpointLimits: convertEndpointLimits(cfg.RateLimit.EndpointLimits),
	})
	log.Println("✓ Rate Limiter initialized")

	behaviorDetector := behavior.NewDetector(behavior.BehaviorConfig{
		BruteForceThreshold:  cfg.Behavior.BruteForceThreshold,
		BruteForceWindow:     cfg.Behavior.BruteForceWindow,
		BotDetectionEnabled:  cfg.Behavior.BotDetectionEnabled,
		BotScoreThreshold:    cfg.Behavior.BotScoreThreshold,
		VelocityEnabled:      cfg.Behavior.VelocityEnabled,
		MaxRequestsPerSecond: cfg.Behavior.MaxRequestsPerSecond,
	})
	log.Println("✓ Behavior Detector initialized")

	decisionEngine := decision.NewDecisionEngine(decision.DecisionConfig{
		BlockThreshold:  cfg.Decision.BlockThreshold,
		EnableWhitelist: cfg.Decision.EnableWhitelist,
		EnableBlacklist: cfg.Decision.EnableBlacklist,
	})
	log.Println("✓ Decision Engine initialized")

	// Periodically prune expired whitelist / blacklist entries. The
	// lookup path already filters them on every check so this is mostly
	// housekeeping — keeps the maps from accumulating stale TTL'd rows
	// across long-running sessions.
	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for range t.C {
			if wl, bl := decisionEngine.PruneExpiredIPs(); wl+bl > 0 {
				log.Printf("ip-list pruner: removed %d whitelist + %d blacklist expired entries", wl, bl)
			}
		}
	}()

	// Two independent log streams:
	//   accessLogger — every HTTP request + WAF verdict (high-volume traffic).
	//   auditLogger  — admin / security events only (accountability trail).
	accessLogger := audit.NewLogger(audit.AuditConfig{
		LogPath:    cfg.AccessLog.LogPath,
		AsyncWrite: true,
		BufferSize: 1000,
	})
	log.Printf("✓ Access Logger initialized → %s", cfg.AccessLog.LogPath)

	auditLogger := audit.NewLogger(audit.AuditConfig{
		LogPath:    cfg.AuditLog.LogPath,
		AsyncWrite: true,
		BufferSize: 1000,
	})
	log.Printf("✓ Audit Logger initialized → %s", cfg.AuditLog.LogPath)

	trainingLogger := training.NewLogger(training.Config{
		Enabled:          cfg.Training.Enabled,
		LogPath:          cfg.Training.LogPath,
		MaxTextLen:       cfg.Training.MaxTextLen,
		BufferSize:       cfg.Training.BufferSize,
		SkipPathPrefixes: cfg.Training.SkipPathPrefixes,
	})
	if trainingLogger.Enabled() {
		log.Printf("✓ Training Logger initialized → %s", cfg.Training.LogPath)
	} else {
		log.Println("✓ Training Logger disabled (set training.enabled: true to capture)")
	}

	metricsCollector := metrics.NewCollector()
	log.Println("✓ Metrics Collector initialized")

	// ML inference client — talks to the FastAPI DistilBERT service. Safe to
	// instantiate even when the service is unreachable; the breaker will trip
	// on the first batch of failures and the WAF falls back to rule-only.
	mlClient := ml.NewClient(ml.Config{
		Endpoint:         cfg.ML.Endpoint,
		Timeout:          cfg.ML.Timeout,
		Enabled:          cfg.ML.Enabled,
		MaxBodyLen:       cfg.ML.MaxBodyLen,
		CacheSize:        cfg.ML.CacheSize,
		CacheTTL:         cfg.ML.CacheTTL,
		BreakerThreshold: cfg.ML.BreakerThreshold,
		BreakerCooldown:  cfg.ML.BreakerCooldown,
	})
	if mlClient.Enabled() {
		// Quick reachability probe — failure is non-fatal so the WAF can boot
		// even if the ML service is still warming up. The breaker will sort
		// out flapping later.
		probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := mlClient.Health(probeCtx); err != nil {
			log.Printf("⚠️  ML service health probe failed (%v) — running in degraded mode at %s", err, cfg.ML.Endpoint)
		} else {
			log.Printf("✓ ML inference client ready (endpoint: %s, gray-zone: [%.2f, %.2f))",
				cfg.ML.Endpoint, cfg.ML.GrayLower, cfg.ML.GrayUpper)
		}
		cancel()
	} else {
		log.Println("✓ ML inference disabled (set ml.enabled: true to use the model)")
	}

	// Wire the ML client into the rule engine so per-rule `action.ml_confirm`
	// (schema v2) can call the same model the middleware uses.
	ruleEngine.SetMLPredictor(engine.NewMLAdapter(
		func(ctx context.Context, text string) (string, float64, bool, error) {
			resp, err := mlClient.Predict(ctx, text)
			if err != nil || resp == nil {
				return "", 0, false, err
			}
			return resp.Label, resp.Confidence, resp.IsAttack, nil
		},
		mlClient.Enabled,
	))
	ruleEngine.SetThresholds(cfg.Decision.BlockThreshold, 0.0) // monitor floor 0 = flag any score > 0

	// Connect to database
	db, err := database.Connect(cfg.Database)
	if err != nil {
		log.Printf("⚠️  Database connection failed: %v", err)
		log.Println("⚠️  Authentication features will be disabled")
		// Create API server without auth
		apiServer := api.NewAPIServer(
			ruleEngine,
			rateLimiter,
			behaviorDetector,
			decisionEngine,
			auditLogger,
			metricsCollector,
		)
		log.Println("✓ API Server initialized (no auth)")
		_ = apiServer // Use variable to create middleware setup
	} else {
		defer db.Close()
		log.Println("✓ Database connected")

		// Create API server with authentication
		apiServer, err := api.NewAPIServerWithAuth(
			ruleEngine,
			rateLimiter,
			behaviorDetector,
			decisionEngine,
			auditLogger,
			metricsCollector,
			db.DB,
			cfg,
		)
		if err != nil {
			log.Fatalf("Failed to create API server: %v", err)
		}
		log.Println("✓ API Server initialized with authentication")
		_ = apiServer // Use variable
	}

	// Note: We need to restructure to use apiServer outside if/else
	// For now, recreate without auth for compatibility
	apiServer := api.NewAPIServer(
		ruleEngine,
		rateLimiter,
		behaviorDetector,
		decisionEngine,
		auditLogger,
		metricsCollector,
	)

	// Try to add auth if DB is available
	if db, err := database.Connect(cfg.Database); err == nil {
		defer db.Close()
		apiServerAuth, authErr := api.NewAPIServerWithAuth(
			ruleEngine, rateLimiter, behaviorDetector, decisionEngine,
			auditLogger, metricsCollector, db.DB, cfg,
		)
		if authErr == nil {
			apiServer = apiServerAuth
			log.Println("✓ API Server with authentication enabled")
		}
	}
	log.Println("✓ API Server initialized")

	// Initialize outbound alerter (Slack / email / generic webhook).
	// Multi-destination — YAML lists become arrays of channel destinations.
	// Always-on goroutine — disabled config means Send() returns early.
	slackDests := make([]notifier.SlackDestination, len(cfg.Alerts.Slack))
	for i, d := range cfg.Alerts.Slack {
		slackDests[i] = notifier.SlackDestination{
			ID:              d.ID,
			Name:            d.Name,
			Enabled:         d.Enabled,
			WebhookURL:      d.WebhookURL,
			Channel:         d.Channel,
			Username:        d.Username,
			MessageTemplate: d.MessageTemplate,
		}
	}
	emailDests := make([]notifier.EmailDestination, len(cfg.Alerts.Email))
	for i, d := range cfg.Alerts.Email {
		emailDests[i] = notifier.EmailDestination{
			ID:              d.ID,
			Name:            d.Name,
			Enabled:         d.Enabled,
			Host:            d.Host,
			Port:            d.Port,
			Username:        d.Username,
			Password:        d.Password,
			From:            d.From,
			To:              d.To,
			UseTLS:          d.UseTLS,
			SubjectTemplate: d.SubjectTemplate,
			BodyTemplate:    d.BodyTemplate,
		}
	}
	webhookDests := make([]notifier.WebhookDestination, len(cfg.Alerts.Webhook))
	for i, d := range cfg.Alerts.Webhook {
		webhookDests[i] = notifier.WebhookDestination{
			ID:              d.ID,
			Name:            d.Name,
			Enabled:         d.Enabled,
			URL:             d.URL,
			Method:          d.Method,
			Headers:         d.Headers,
			PayloadTemplate: d.PayloadTemplate,
		}
	}
	alertNotifier := notifier.New(notifier.Config{
		Enabled:           cfg.Alerts.Enabled,
		MinSeverity:       cfg.Alerts.MinSeverity,
		ThrottleSeconds:   cfg.Alerts.ThrottleSeconds,
		SendRequestEvents: cfg.Alerts.SendRequestEvents,
		SendSystemEvents:  cfg.Alerts.SendSystemEvents,
		Slack:             slackDests,
		Email:             emailDests,
		Webhook:           webhookDests,
	})
	defer alertNotifier.Close()
	if cfg.Alerts.Enabled {
		log.Printf("✓ Alerts enabled — min_severity=%s, throttle=%ds", cfg.Alerts.MinSeverity, cfg.Alerts.ThrottleSeconds)
	} else {
		log.Println("○ Alerts disabled (enable via /dashboard or alerts.enabled in YAML)")
	}

	// Wire the audit logger's system-event hook → dashboard buffer and
	// alert notifier. Without this, LogSystemEvent calls (config change,
	// persist error, log clear) end up in the file log but never reach
	// the live dashboard or any alert channel. The sink callback runs
	// synchronously on the goroutine that triggered the event, but both
	// targets are non-blocking (in-memory append + bounded send queue).
	auditLogger.SetSystemSink(func(e *audit.AuditEntry) {
		api.AddToAuditBuffer(e)
		eventType, _ := e.Metadata["event_type"].(string)
		severity := classifySystemEventSeverity(eventType)
		// LogSecurityEvent injects an explicit severity in Metadata —
		// prefer that when present.
		if s, ok := e.Metadata["severity"].(string); ok && s != "" {
			severity = strings.ToUpper(s)
		}
		alertNotifier.Send(notifier.Event{
			Kind:      notifier.KindSystem,
			Timestamp: e.Timestamp,
			Decision:  e.Decision,
			Severity:  severity,
			ClientIP:  e.ClientIP,
			Reason:    e.BlockReason,
			RuleID:    eventType,
			RequestID: e.RequestID,
		})
	})

	// Create WAF middleware with log buffer integration
	wafMiddleware := middleware.NewWAFWithLogBuffer(&middleware.WAFConfig{
		Parser:              httpParser,
		Normalizer:          norm,
		RuleEngine:          ruleEngine,
		RateLimiter:         rateLimiter,
		BehaviorDetector:    behaviorDetector,
		DecisionEngine:      decisionEngine,
		AccessLogger:        accessLogger,
		AuditLogger:         auditLogger,
		TrainingLogger:      trainingLogger,
		Notifier:            alertNotifier,
		Metrics:             metricsCollector,
		Upstream:            cfg.Upstream.URL,
		MLClient:            mlClient,
		MLGrayLower:         cfg.ML.GrayLower,
		MLGrayUpper:         cfg.ML.GrayUpper,
		MLAttackBump:        cfg.ML.AttackBump,
		MLNormalPenalty:     cfg.ML.NormalPenalty,
		MLConfidenceMinimum: cfg.ML.ConfidenceThreshold,
		MLMaxTextLen:        cfg.ML.MaxBodyLen,
	})
	apiServer.SetNotifier(alertNotifier)
	log.Println("✓ WAF Middleware initialized")

	// Connect API server with WAF middleware for backend configuration
	apiServer.SetWAFMiddleware(wafMiddleware)
	log.Println("✓ Backend configuration enabled")

	// Persistent runtime config — overlays YAML defaults with whatever the
	// dashboard saved last time, then keeps every subsequent edit on disk.
	//
	// Same DB connection also hosts the runtime *state* store (behavior
	// counters, rate-limit buckets, tracker counters, ML cache, notifier
	// dedup, decision/metrics stats). State restore happens BEFORE traffic
	// starts and the periodic snapshotter goroutine launches just below.
	var stateSnapshotter *statestore.Snapshotter2
	if db, err := database.Connect(cfg.Database); err == nil {
		defer db.Close()
		store := configstore.New(db.DB)
		if err := store.Migrate(); err != nil {
			log.Printf("⚠️  Config store migration failed: %v — runtime changes will not persist", err)
		} else {
			applied, persistedBackend, err := store.LoadInto(decisionEngine, rateLimiter, wafMiddleware)
			switch {
			case err != nil:
				log.Printf("⚠️  Failed to load persisted config: %v", err)
			case applied > 0:
				if persistedBackend != "" {
					log.Printf("✓ Restored %d config section(s) from DB (backend → %s)", applied, persistedBackend)
				} else {
					log.Printf("✓ Restored %d config section(s) from DB", applied)
				}
			default:
				log.Println("✓ Config store ready (no persisted overrides)")
			}
			apiServer.SetConfigStore(store)
		}

		// Runtime state — the security-sensitive in-memory data that
		// would otherwise be wiped on every restart.
		sstate := statestore.New(db.DB)
		if err := sstate.Migrate(); err != nil {
			log.Printf("⚠️  State store migration failed: %v — runtime state will not persist", err)
		} else {
			sections := map[string]statestore.Snapshotter{
				statestore.KeyBehavior:       behaviorDetector,
				statestore.KeyRateLimit:      rateLimiter,
				statestore.KeyTracker:        ruleEngine.TrackerSnapshotter(),
				statestore.KeyMLCache:        mlClient.CacheSnapshotter(),
				statestore.KeyMLBreaker:      mlClient.BreakerSnapshotter(),
				statestore.KeyMLClientStats:  mlClient.StatsSnapshotter(),
				statestore.KeyNotifierState:  alertNotifier.StateSnapshotter(),
				statestore.KeyNotifierDests:  alertNotifier.DestSnapshotter(),
				statestore.KeyRuleMetrics:    ruleEngine.MetricsSnapshotter(),
				statestore.KeyDecisionStats:  decisionEngine.StatsSnapshotter(),
				statestore.KeyMetricsCollect: metricsCollector,
			}
			if restored := sstate.RestoreAll(sections); restored > 0 {
				log.Printf("✓ Restored %d runtime state section(s) from DB", restored)
			} else {
				log.Println("✓ State store ready (no persisted state)")
			}
			stateSnapshotter = statestore.NewSnapshotter(sstate, sections, 30*time.Second)
			stateSnapshotter.Start()
			log.Println("✓ Runtime state snapshotter running (interval=30s)")
		}
	} else {
		log.Printf("⚠️  Config persistence disabled (DB unavailable: %v)", err)
	}

	// Rebuild the dashboard's ring buffers from the log files on disk so
	// they aren't empty for the first minute after every restart. The
	// access log and audit log are restored independently.
	if n, err := api.RestoreAccessBufferFromFile(cfg.AccessLog.LogPath); err != nil {
		log.Printf("⚠️  Failed to restore access ring buffer: %v", err)
	} else if n > 0 {
		log.Printf("✓ Restored %d access entries into dashboard ring buffer", n)
	}
	if n, err := api.RestoreAuditBufferFromFile(cfg.AuditLog.LogPath); err != nil {
		log.Printf("⚠️  Failed to restore audit ring buffer: %v", err)
	} else if n > 0 {
		log.Printf("✓ Restored %d audit entries into dashboard ring buffer", n)
	}

	// Setup HTTP server
	mux := http.NewServeMux()

	// Admin access control — non-local clients get a 404 for every admin
	// surface (pages + API), so outsiders can't even discover that the
	// management UI exists. Default is LocalOnly=true with loopback CIDRs;
	// flip in configs/config.yaml if you need to admin from another box.
	adminAC := newAdminAccessControl(cfg.Admin)
	if adminAC.enabled {
		log.Printf("✓ Admin access control: local-only (%v)", cfg.Admin.AllowedCIDRs)
	} else {
		log.Println("⚠️  Admin access control: DISABLED (admin endpoints exposed to anyone)")
	}

	// Authentication pages (serve directly, don't proxy).
	// Only /login.html exists — there is no public registration page;
	// accounts are created by an admin from the dashboard.
	mux.HandleFunc("/login.html", adminAC.WrapFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web.FS, "login.html")
	}))
	log.Println("✓ Authentication page: /login.html")

	// Dashboard (serve embedded files) — gated by adminAC (network) THEN
	// PageGuard (auth). Outsider → 404. Logged-out local → 302 /login.html.
	mux.HandleFunc("/dashboard", adminAC.WrapFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusPermanentRedirect)
	}))
	dashboardFS := http.StripPrefix("/dashboard/", http.FileServer(http.FS(web.FS)))
	mux.Handle("/dashboard/", adminAC.Wrap(apiServer.PageGuard(dashboardFS)))
	log.Println("✓ Dashboard endpoint: /dashboard (PageGuard active when require_auth=true)")

	// API endpoints — register on a private mux, then mount the whole tree
	// behind adminAC at /waf-api/. This wraps every API route with the
	// access-control check in one shot.
	apiMux := http.NewServeMux()
	apiServer.RegisterRoutes(apiMux)
	mux.Handle("/waf-api/", adminAC.Wrap(apiMux))
	log.Println("✓ API endpoints registered (admin-gated)")

	// Metrics endpoint (Prometheus) — admin-gated; exposes per-rule hit
	// counts, request totals, etc. which leak inventory of protected apps.
	mux.Handle("/metrics", adminAC.Wrap(promhttp.Handler()))
	log.Println("✓ Metrics endpoint: /metrics (admin-gated)")

	// Health check endpoint — intentionally PUBLIC so external monitors
	// (load balancer probes, uptime checks) can verify the WAF is alive.
	// Returns only version + rule count; no per-rule details.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","version":"%s","rules":%d}`,
			*version, ruleEngine.RuleCount())
	})
	log.Println("✓ Health endpoint: /health (public)")

	// Admin stats endpoint — full metrics dump, must be local-only.
	mux.HandleFunc("/admin/stats", adminAC.WrapFunc(func(w http.ResponseWriter, r *http.Request) {
		metrics := ruleEngine.GetMetrics()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{
            "total_evaluations": %d,
            "total_matches": %d,
            "total_blocks": %d,
            "rule_count": %d
        }`, metrics.TotalEvaluations, metrics.TotalMatches,
			metrics.TotalBlocks, ruleEngine.RuleCount())
	}))
	log.Println("✓ Admin endpoint: /admin/stats (admin-gated)")

	// WAF protected proxy - handles all other traffic
	mux.Handle("/", wafMiddleware)
	log.Println("✓ WAF proxy: / (all traffic)")

	// Prepare for graceful shutdown
	var httpServer, httpsServer *http.Server
	serverErrors := make(chan error, 2)

	// Check if TLS is enabled
	if cfg.TLS.Enabled {
		// Create HTTPS server
		httpsServer = &http.Server{
			Addr:         cfg.Server.HTTPSListen,
			Handler:      mux,
			ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
			WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
			IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
		}

		// Start HTTPS server
		go func() {
			log.Println("==========================================")
			log.Printf("🛡️  HTTPS WAF is now ACTIVE on %s", cfg.Server.HTTPSListen)
			log.Println("==========================================")
			log.Printf("Endpoints:")
			log.Printf("  - Dashboard: https://%s/dashboard", cfg.Server.HTTPSListen)
			log.Printf("  - Proxy:     https://%s/", cfg.Server.HTTPSListen)
			log.Printf("  - API:       https://%s/api/*", cfg.Server.HTTPSListen)
			log.Printf("  - Health:    https://%s/health", cfg.Server.HTTPSListen)
			log.Printf("  - Metrics:   https://%s/metrics", cfg.Server.HTTPSListen)
			log.Printf("  - Stats:     https://%s/admin/stats", cfg.Server.HTTPSListen)
			log.Println("==========================================")

			if err := httpsServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				serverErrors <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()

		// If auto-redirect is enabled, start HTTP redirect server
		if cfg.TLS.AutoRedirect {
			// Extract port from HTTPS listen address
			httpsPort := "8443"
			if parts := strings.Split(cfg.Server.HTTPSListen, ":"); len(parts) == 2 {
				httpsPort = parts[1]
			}

			httpServer = &http.Server{
				Addr:         cfg.Server.Listen,
				Handler:      middleware.HTTPSRedirect(httpsPort),
				ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
				WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
				IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
			}

			go func() {
				log.Printf("🔀 HTTP redirect server on %s → HTTPS", cfg.Server.Listen)
				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					serverErrors <- fmt.Errorf("HTTP redirect server error: %w", err)
				}
			}()
		}
	} else {
		// TLS disabled - run HTTP only
		httpServer = &http.Server{
			Addr:         cfg.Server.Listen,
			Handler:      mux,
			ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
			WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
			IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
		}

		go func() {
			log.Println("==========================================")
			log.Printf("🛡️  WAF is now ACTIVE on %s (HTTP only)", cfg.Server.Listen)
			log.Println("==========================================")
			log.Printf("Endpoints:")
			log.Printf("  - Dashboard: http://%s/dashboard", cfg.Server.Listen)
			log.Printf("  - Proxy:     http://%s/", cfg.Server.Listen)
			log.Printf("  - API:       http://%s/api/*", cfg.Server.Listen)
			log.Printf("  - Health:    http://%s/health", cfg.Server.Listen)
			log.Printf("  - Metrics:   http://%s/metrics", cfg.Server.Listen)
			log.Printf("  - Stats:     http://%s/admin/stats", cfg.Server.Listen)
			log.Println("==========================================")

			if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				serverErrors <- fmt.Errorf("HTTP server error: %w", err)
			}
		}()
	}

	// Wait for shutdown signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatalf("Server error: %v", err)
	case sig := <-quit:
		log.Printf("Received signal: %v", sig)
		log.Println("Shutting down WAF gracefully...")
	}

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown servers
	if httpsServer != nil {
		log.Println("Shutting down HTTPS server...")
		if err := httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server forced to shutdown: %v", err)
		}
	}
	if httpServer != nil {
		log.Println("Shutting down HTTP server...")
		if err := httpServer.Shutdown(ctx); err != nil {
			log.Printf("HTTP server forced to shutdown: %v", err)
		}
	}

	// Flush in-memory runtime state to DB so brute-force counters,
	// rate-limit buckets, tracker counts, ML cache, etc. survive this
	// shutdown. Bounded by a short timeout so a wedged DB can't hang
	// the whole shutdown — at worst we lose ~30s of state.
	if stateSnapshotter != nil {
		log.Println("Flushing runtime state to DB...")
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := stateSnapshotter.Stop(flushCtx); err != nil {
			log.Printf("⚠️  State flush timed out: %v", err)
		}
		flushCancel()
	}

	// Cleanup resources
	log.Println("Closing access + audit loggers...")
	accessLogger.Close()
	auditLogger.Close()
	if trainingLogger.Enabled() {
		log.Println("Closing training logger...")
		_ = trainingLogger.Close()
	}

	// Print final statistics
	finalMetrics := ruleEngine.GetMetrics()
	log.Println("==========================================")
	log.Println("Final Statistics:")
	log.Printf("  Total Evaluations: %d", finalMetrics.TotalEvaluations)
	log.Printf("  Total Matches:     %d", finalMetrics.TotalMatches)
	log.Printf("  Total Blocks:      %d", finalMetrics.TotalBlocks)
	if finalMetrics.TotalEvaluations > 0 {
		blockRate := float64(finalMetrics.TotalBlocks) / float64(finalMetrics.TotalEvaluations) * 100
		log.Printf("  Block Rate:        %.2f%%", blockRate)
	}
	log.Println("==========================================")

	log.Println("WAF stopped successfully")
}

func printBanner() {
	banner := `
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   ██╗    ██╗ █████╗ ███████╗                        ║
    ║   ██║    ██║██╔══██╗██╔════╝                        ║
    ║   ██║ █╗ ██║███████║█████╗                          ║
    ║   ██║███╗██║██╔══██║██╔══╝                          ║
    ║   ╚███╔███╔╝██║  ██║██║                             ║
    ║    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝                             ║
    ║                                                      ║
    ║   Custom Web Application Firewall                   ║
    ║   With Real-time Dashboard                          ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    `
	fmt.Println(banner)
}
