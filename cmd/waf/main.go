// cmd/waf/main.go - WITH DASHBOARD
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"waf-project/internal/api"
	"waf-project/internal/audit"
	"waf-project/internal/behavior"
	"waf-project/internal/database"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/middleware"
	"waf-project/internal/normalizer"
	"waf-project/internal/parser"
	"waf-project/internal/ratelimit"
	"waf-project/internal/training"
	"waf-project/pkg/config"
	"waf-project/web"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to config file")
	rulesPath  = flag.String("rules", "configs/rules/all_rules.json", "Path to rules file")
	version    = flag.String("version", "1.0.0", "WAF version")
)

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
		BruteForceThreshold: cfg.Behavior.BruteForceThreshold,
		BruteForceWindow:    cfg.Behavior.BruteForceWindow,
	})
	log.Println("✓ Behavior Detector initialized")

	decisionEngine := decision.NewDecisionEngine(decision.DecisionConfig{
		BlockThreshold:     cfg.Decision.BlockThreshold,
		ChallengeThreshold: cfg.Decision.ChallengeThreshold,
		EnableWhitelist:    cfg.Decision.EnableWhitelist,
		EnableBlacklist:    cfg.Decision.EnableBlacklist,
	})
	log.Println("✓ Decision Engine initialized")

	auditLogger := audit.NewLogger(audit.AuditConfig{
		LogPath:    cfg.Audit.LogPath,
		AsyncWrite: true,
		BufferSize: 1000,
	})
	log.Println("✓ Audit Logger initialized")

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

	// Create WAF middleware with log buffer integration
	wafMiddleware := middleware.NewWAFWithLogBuffer(&middleware.WAFConfig{
		Parser:           httpParser,
		Normalizer:       norm,
		RuleEngine:       ruleEngine,
		RateLimiter:      rateLimiter,
		BehaviorDetector: behaviorDetector,
		DecisionEngine:   decisionEngine,
		AuditLogger:      auditLogger,
		TrainingLogger:   trainingLogger,
		Metrics:          metricsCollector,
		Upstream:         cfg.Upstream.URL,
	})
	log.Println("✓ WAF Middleware initialized")

	// Connect API server with WAF middleware for backend configuration
	apiServer.SetWAFMiddleware(wafMiddleware)
	log.Println("✓ Backend configuration enabled")

	// Setup HTTP server
	mux := http.NewServeMux()

	// Authentication pages (serve directly, don't proxy)
	mux.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web.FS, "login.html")
	})
	mux.HandleFunc("/register.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web.FS, "register.html")
	})
	log.Println("✓ Authentication pages: /login.html, /register.html")

	// Dashboard (serve embedded files)
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusPermanentRedirect)
	})
	mux.Handle("/dashboard/", http.StripPrefix("/dashboard/", http.FileServer(http.FS(web.FS))))
	log.Println("✓ Dashboard endpoint: /dashboard")

	// API endpoints
	apiServer.RegisterRoutes(mux)
	log.Println("✓ API endpoints registered")

	// Metrics endpoint (Prometheus)
	mux.Handle("/metrics", promhttp.Handler())
	log.Println("✓ Metrics endpoint: /metrics")

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","version":"%s","rules":%d}`,
			*version, ruleEngine.RuleCount())
	})
	log.Println("✓ Health endpoint: /health")

	// Admin stats endpoint
	mux.HandleFunc("/admin/stats", func(w http.ResponseWriter, r *http.Request) {
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
	})
	log.Println("✓ Admin endpoint: /admin/stats")

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

	// Cleanup resources
	log.Println("Closing audit logger...")
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
