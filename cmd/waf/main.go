// cmd/waf/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"waf-project/internal/audit"
	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/middleware"
	"waf-project/internal/normalizer"
	"waf-project/internal/parser"
	"waf-project/internal/ratelimit"
	"waf-project/pkg/config"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "Path to config file")
	rulesPath  = flag.String("rules", "configs/rules/all_rules.json", "Path to rules file")
	version    = "1.0.0"
)

func init() {
	flag.StringVar(&version, "version", version, "WAF version")
}

func main() {
	flag.Parse()

	// Print banner
	printBanner()

	log.Printf("Starting WAF v%s", version)
	log.Printf("Config: %s", *configPath)
	log.Printf("Rules: %s", *rulesPath)

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Printf("WAF listening on %s", cfg.Server.Listen)
	log.Printf("Upstream backend: %s", cfg.Upstream.URL)

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
	})
	log.Println("✓ Decision Engine initialized")

	auditLogger := audit.NewLogger(audit.AuditConfig{
		LogPath: cfg.Audit.LogPath,
	})
	log.Println("✓ Audit Logger initialized")

	metricsCollector := metrics.NewCollector()
	log.Println("✓ Metrics Collector initialized")

	// Create WAF middleware
	wafMiddleware := middleware.NewWAF(&middleware.WAFConfig{
		Parser:           httpParser,
		Normalizer:       norm,
		RuleEngine:       ruleEngine,
		RateLimiter:      rateLimiter,
		BehaviorDetector: behaviorDetector,
		DecisionEngine:   decisionEngine,
		AuditLogger:      auditLogger,
		Metrics:          metricsCollector,
		Upstream:         cfg.Upstream.URL,
	})
	log.Println("✓ WAF Middleware initialized")

	// Setup HTTP server
	mux := http.NewServeMux()

	// Metrics endpoint (Prometheus)
	mux.Handle("/metrics", promhttp.Handler())
	log.Println("✓ Metrics endpoint: /metrics")

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"healthy","version":"%s","rules":%d}`,
			version, ruleEngine.RuleCount())
	})
	log.Println("✓ Health endpoint: /health")

	// Admin endpoints
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

	// Create HTTP server
	server := &http.Server{
		Addr:         cfg.Server.Listen,
		Handler:      mux,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Println("==========================================")
		log.Printf("🛡️  WAF is now ACTIVE on %s", cfg.Server.Listen)
		log.Println("==========================================")
		log.Printf("Endpoints:")
		log.Printf("  - Proxy:   http://%s/", cfg.Server.Listen)
		log.Printf("  - Health:  http://%s/health", cfg.Server.Listen)
		log.Printf("  - Metrics: http://%s/metrics", cfg.Server.Listen)
		log.Printf("  - Stats:   http://%s/admin/stats", cfg.Server.Listen)
		log.Println("==========================================")

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	sig := <-quit

	log.Printf("Received signal: %v", sig)
	log.Println("Shutting down WAF gracefully...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Cleanup resources
	log.Println("Closing audit logger...")
	auditLogger.Close()

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
    ║   Signature-based Detection Engine                  ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    `
	fmt.Println(banner)
}
