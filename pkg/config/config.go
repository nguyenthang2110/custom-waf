package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config represents the full YAML configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Parser    ParserConfig    `yaml:"parser"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
	Behavior  BehaviorConfig  `yaml:"behavior"`
	Decision  DecisionConfig  `yaml:"decision"`
	Database  DatabaseConfig  `yaml:"database"`
	Auth      AuthConfig      `yaml:"auth"`
	Admin     AdminConfig     `yaml:"admin"`
	TLS       TLSConfig       `yaml:"tls"`
	Audit     AuditConfig     `yaml:"audit"`
	Training  TrainingConfig  `yaml:"training"`
	ML        MLConfig        `yaml:"ml"`
	Alerts    AlertsConfig    `yaml:"alerts"`
}

// AlertsConfig configures outbound notifications. Each channel type holds
// a *list* of destinations — operators can register multiple Slack workspaces,
// multiple email recipient groups, or multiple webhook receivers, each with
// its own enabled flag and templates. Events fan out to every enabled
// destination across every channel.
//
// Defaults applied in Load(): MinSeverity=HIGH, ThrottleSeconds=300.
//
// This struct must mirror internal/notifier.Config exactly — notifier
// converts it field-for-field in cmd/waf wiring (pkg/config can't import
// internal/* due to layering).
type AlertsConfig struct {
	Enabled         bool                      `yaml:"enabled"`
	MinSeverity     string                    `yaml:"min_severity"`     // INFO/LOW/MEDIUM/HIGH/CRITICAL
	ThrottleSeconds int                       `yaml:"throttle_seconds"` // dedup window per (ip, rule_id)
	Slack           []AlertSlackDestination   `yaml:"slack"`
	Email           []AlertEmailDestination   `yaml:"email"`
	Webhook         []AlertWebhookDestination `yaml:"webhook"`
}

type AlertSlackDestination struct {
	ID              string `yaml:"id"`
	Name            string `yaml:"name"`
	Enabled         bool   `yaml:"enabled"`
	WebhookURL      string `yaml:"webhook_url"`
	Channel         string `yaml:"channel"`
	Username        string `yaml:"username"`
	MessageTemplate string `yaml:"message_template"`
}

type AlertEmailDestination struct {
	ID              string   `yaml:"id"`
	Name            string   `yaml:"name"`
	Enabled         bool     `yaml:"enabled"`
	Host            string   `yaml:"host"`
	Port            int      `yaml:"port"`
	Username        string   `yaml:"username"`
	Password        string   `yaml:"password"`
	From            string   `yaml:"from"`
	To              []string `yaml:"to"`
	UseTLS          bool     `yaml:"use_tls"`
	SubjectTemplate string   `yaml:"subject_template"`
	BodyTemplate    string   `yaml:"body_template"`
}

type AlertWebhookDestination struct {
	ID              string            `yaml:"id"`
	Name            string            `yaml:"name"`
	Enabled         bool              `yaml:"enabled"`
	URL             string            `yaml:"url"`
	Method          string            `yaml:"method"`
	Headers         map[string]string `yaml:"headers"`
	PayloadTemplate string            `yaml:"payload_template"`
}

// AdminConfig controls network-level access to management surfaces.
// When LocalOnly is true, /dashboard/*, /login.html, /register.html and
// /waf-api/* return 404 (not 403) for requests from anywhere outside
// AllowedCIDRs — outsiders can't even discover the admin UI exists.
//
// Defaults (when section omitted from YAML):
//   - LocalOnly:    true
//   - AllowedCIDRs: ["127.0.0.0/8", "::1/128"]  // loopback only
type AdminConfig struct {
	LocalOnly    bool     `yaml:"local_only"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
}

// MLConfig configures the bridge to the FastAPI DistilBERT inference service.
// The ML client is consulted only when the rule-engine score lands in the
// gray zone [GrayLower, GrayUpper) — clearly-benign and clearly-malicious
// requests skip the model so we don't pay its latency on the hot path.
type MLConfig struct {
	Enabled    bool          `yaml:"enabled"`
	Endpoint   string        `yaml:"endpoint"`     // e.g. http://127.0.0.1:8000
	Timeout    time.Duration `yaml:"timeout"`      // per request (default 800ms)
	MaxBodyLen int           `yaml:"max_body_len"` // truncate input text (default 4096)

	// Gray-zone bounds in rule-score units. Score ∈ [GrayLower, GrayUpper)
	// triggers a model call. Outside the band the model is skipped.
	GrayLower float64 `yaml:"gray_lower"`
	GrayUpper float64 `yaml:"gray_upper"`

	// Score adjustments applied when ML confidence ≥ ConfidenceThreshold.
	// AttackBump pushes a borderline request over BlockThreshold; NormalPenalty
	// pulls it back below ChallengeThreshold. Both are added to / subtracted
	// from the rule score before the decision engine runs.
	AttackBump          float64 `yaml:"attack_bump"`
	NormalPenalty       float64 `yaml:"normal_penalty"`
	ConfidenceThreshold float64 `yaml:"confidence_threshold"`

	// Prediction cache (LRU, value-TTL). 0 disables.
	CacheSize int           `yaml:"cache_size"`
	CacheTTL  time.Duration `yaml:"cache_ttl"`

	// Circuit breaker. 0 disables. When open, ML calls return immediately
	// and the WAF falls back to the rule-only decision.
	BreakerThreshold int           `yaml:"breaker_threshold"`
	BreakerCooldown  time.Duration `yaml:"breaker_cooldown"`
}

type ServerConfig struct {
	Listen       string `yaml:"listen"`
	HTTPSListen  string `yaml:"https_listen"`
	ReadTimeout  int    `yaml:"read_timeout"`
	WriteTimeout int    `yaml:"write_timeout"`
	IdleTimeout  int    `yaml:"idle_timeout"`
}

type UpstreamConfig struct {
	URL string `yaml:"url"`
}

type ParserConfig struct {
	MaxBodySize int64 `yaml:"max_body_size"`
}

type RateLimitConfig struct {
	RequestsPerMin int                    `yaml:"requests_per_min"`
	BurstSize      int                    `yaml:"burst_size"`
	EndpointLimits map[string]LimitConfig `yaml:"endpoint_limits"`
}

type LimitConfig struct {
	RequestsPerMin int `yaml:"requests_per_min"`
	BurstSize      int `yaml:"burst_size"`
}

type BehaviorConfig struct {
	BruteForceThreshold int           `yaml:"bruteforce_threshold"`
	BruteForceWindow    time.Duration `yaml:"bruteforce_window"`

	BotDetectionEnabled bool    `yaml:"bot_detection_enabled"`
	BotScoreThreshold   float64 `yaml:"bot_score_threshold"`

	VelocityEnabled      bool `yaml:"velocity_enabled"`
	MaxRequestsPerSecond int  `yaml:"max_requests_per_second"`
}

type DecisionConfig struct {
	BlockThreshold     float64  `yaml:"block_threshold"`
	ChallengeThreshold float64  `yaml:"challenge_threshold"`
	EnableWhitelist    bool     `yaml:"enable_whitelist"`
	EnableBlacklist    bool     `yaml:"enable_blacklist"`
	BypassPaths        []string `yaml:"bypass_paths"` // path prefixes silently bypassed (in addition to built-in /socket.io/, /ws/, etc.)
}

type TLSConfig struct {
	Enabled      bool   `yaml:"enabled"`
	CertFile     string `yaml:"cert_file"`
	KeyFile      string `yaml:"key_file"`
	AutoRedirect bool   `yaml:"auto_redirect"`
}

type DatabaseConfig struct {
	Host           string `yaml:"host"`
	Port           int    `yaml:"port"`
	Name           string `yaml:"name"`
	User           string `yaml:"user"`
	Password       string `yaml:"password"`
	SSLMode        string `yaml:"sslmode"`
	MaxConnections int    `yaml:"max_connections"`
}

type AuthConfig struct {
	JWTSecret   string `yaml:"jwt_secret"`
	JWTExpiry   string `yaml:"jwt_expiry"`
	BcryptCost  int    `yaml:"bcrypt_cost"`
	RequireAuth bool   `yaml:"require_auth"`
}

type AuditConfig struct {
	LogPath string `yaml:"log_path"`
}

// TrainingConfig configures the dedicated ML-training log writer.
// Each entry mirrors the {"text": ...} payload that buildMLInput
// would send to the model, so the file is ready to ingest as-is.
//
// File rotation: if LogPath is "./logs/waf/training.jsonl", actual files
// land at "./logs/waf/training-YYYY-MM-DD.jsonl" (one per UTC day).
type TrainingConfig struct {
	Enabled    bool   `yaml:"enabled"`      // master switch
	LogPath    string `yaml:"log_path"`     // base path; date is inserted before ext
	MaxTextLen int    `yaml:"max_text_len"` // truncate text to this many bytes (default 1000)
	BufferSize int    `yaml:"buffer_size"`  // async write buffer (default 4096)

	// User-supplied path prefixes that should be skipped on top of the
	// built-in skip list (static assets, /socket.io/, /health, /waf-api/...).
	// Example: ["/internal/heartbeat", "/v2/probe"].
	SkipPathPrefixes []string `yaml:"skip_path_prefixes"`
}

// Load reads and parses configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// Defaults must be applied before unmarshal so an omitted YAML key
	// keeps the safe default (true / loopback) instead of zero values.
	cfg := Config{
		Admin: AdminConfig{
			LocalOnly:    true,
			AllowedCIDRs: []string{"127.0.0.0/8", "::1/128"},
		},
		Alerts: AlertsConfig{
			Enabled:         false,
			MinSeverity:     "HIGH",
			ThrottleSeconds: 300,
		},
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// If the user provided an `admin:` section but left AllowedCIDRs empty,
	// fall back to loopback-only — never an empty allow-list (which would
	// disable admin entirely).
	if cfg.Admin.LocalOnly && len(cfg.Admin.AllowedCIDRs) == 0 {
		cfg.Admin.AllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}
	}

	// Alert defaults — fill blanks left by user YAML.
	if cfg.Alerts.MinSeverity == "" {
		cfg.Alerts.MinSeverity = "HIGH"
	}
	if cfg.Alerts.ThrottleSeconds <= 0 {
		cfg.Alerts.ThrottleSeconds = 300
	}

	return &cfg, nil
}
