// Helper function to create APIServer with auth support
package api

import (
	"database/sql"

	"waf-project/internal/audit"
	"waf-project/internal/auth"
	"waf-project/internal/behavior"
	"waf-project/internal/decision"
	"waf-project/internal/engine"
	"waf-project/internal/metrics"
	"waf-project/internal/models"
	"waf-project/internal/ratelimit"
	"waf-project/pkg/config"
)

// NewAPIServerWithAuth creates API server with authentication support
func NewAPIServerWithAuth(
	ruleEngine *engine.RuleEngine,
	rateLimiter *ratelimit.RateLimiter,
	behaviorDetector *behavior.Detector,
	decisionEngine *decision.DecisionEngine,
	auditLogger *audit.Logger,
	metricsCollector *metrics.Collector,
	db *sql.DB,
	cfg *config.Config,
) (*APIServer, error) {
	// Create JWT manager
	jwtManager, err := auth.NewJWTManager(cfg.Auth.JWTSecret, cfg.Auth.JWTExpiry)
	if err != nil {
		return nil, err
	}

	// Create user repository
	userRepo := models.NewUserRepository(db)

	return &APIServer{
		ruleEngine:       ruleEngine,
		rateLimiter:      rateLimiter,
		behaviorDetector: behaviorDetector,
		decisionEngine:   decisionEngine,
		auditLogger:      auditLogger,
		metricsCollector: metricsCollector,
		userRepo:         userRepo,
		jwtManager:       jwtManager,
		bcryptCost:       cfg.Auth.BcryptCost,
		requireAuth:      cfg.Auth.RequireAuth,
	}, nil
}
