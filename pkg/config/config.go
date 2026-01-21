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
	TLS       TLSConfig       `yaml:"tls"`
	Audit     AuditConfig     `yaml:"audit"`
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
}

type DecisionConfig struct {
	BlockThreshold     float64 `yaml:"block_threshold"`
	ChallengeThreshold float64 `yaml:"challenge_threshold"`
	EnableWhitelist    bool    `yaml:"enable_whitelist"`
	EnableBlacklist    bool    `yaml:"enable_blacklist"`
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

// Load reads and parses configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
