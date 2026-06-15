package config

import (
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Redis  RedisConfig  `yaml:"redis"`
	WAF    WAFConfig    `yaml:"waf"`
	Apps   []AppConfig  `yaml:"apps"`
}

type ServerConfig struct {
	ListenAddr     string   `yaml:"listen_addr"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type RedisConfig struct {
	Enabled bool   `yaml:"enabled"`
	Addr    string `yaml:"addr"`
}

type WAFConfig struct {
	Enabled               bool   `yaml:"enabled"`
	Engine                string `yaml:"engine"`
	RuleEngine            string `yaml:"rule_engine"`
	RequestBodyLimitBytes int64  `yaml:"request_body_limit_bytes"`
	DirectivesFile        string `yaml:"directives_file"`
	DebugBodyPreview      bool   `yaml:"debug_body_preview"`
	BodyPreviewBytes      int64  `yaml:"body_preview_bytes"`
}

type AppConfig struct {
	ID        string       `yaml:"id"`
	Hostnames []string     `yaml:"hostnames"`
	Origin    OriginConfig `yaml:"origin"`
	Policy    PolicyConfig `yaml:"policy"`
}

type OriginConfig struct {
	URL string `yaml:"url"`
}

type PolicyConfig struct {
	Mode          string            `yaml:"mode"`
	DefaultAction string            `yaml:"default_action"`
	IPBlocklist   []string          `yaml:"ip_blocklist"`
	IPAllowlist   []string          `yaml:"ip_allowlist"`
	RateLimits    []RateLimitConfig `yaml:"rate_limits"`
}

type RateLimitConfig struct {
	Name          string `yaml:"name"`
	Key           string `yaml:"key"`
	Limit         int    `yaml:"limit"`
	WindowSeconds int    `yaml:"window_seconds"`
	Action        string `yaml:"action"`
}

func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	applyDefaults(&cfg)
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.ListenAddr == "" {
		cfg.Server.ListenAddr = ":8080"
	}
	if cfg.Redis.Addr == "" {
		cfg.Redis.Addr = "localhost:6379"
	}
	if cfg.WAF.Engine == "" {
		cfg.WAF.Engine = "coraza"
	}
	if cfg.WAF.RuleEngine == "" {
		cfg.WAF.RuleEngine = "DetectionOnly"
	}
	if cfg.WAF.RequestBodyLimitBytes == 0 {
		cfg.WAF.RequestBodyLimitBytes = 1 << 20
	}
	if cfg.WAF.BodyPreviewBytes == 0 {
		cfg.WAF.BodyPreviewBytes = 512
	}
	for i := range cfg.Apps {
		if cfg.Apps[i].Policy.Mode == "" {
			cfg.Apps[i].Policy.Mode = "count"
		}
		if cfg.Apps[i].Policy.DefaultAction == "" {
			cfg.Apps[i].Policy.DefaultAction = "allow"
		}
	}
}

func validate(cfg Config) error {
	if len(cfg.Apps) == 0 {
		return fmt.Errorf("at least one app is required")
	}
	for _, app := range cfg.Apps {
		if app.ID == "" {
			return fmt.Errorf("app id is required")
		}
		if len(app.Hostnames) == 0 {
			return fmt.Errorf("app %q requires at least one hostname", app.ID)
		}
		if app.Origin.URL == "" {
			return fmt.Errorf("app %q requires origin url", app.ID)
		}
		parsed, err := url.Parse(app.Origin.URL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("app %q has invalid origin url %q", app.ID, app.Origin.URL)
		}
		if app.Policy.Mode != "count" && app.Policy.Mode != "block" {
			return fmt.Errorf("app %q has invalid policy mode %q", app.ID, app.Policy.Mode)
		}
	}
	if cfg.WAF.Enabled {
		if cfg.WAF.Engine != "coraza" {
			return fmt.Errorf("unsupported waf engine %q", cfg.WAF.Engine)
		}
		switch cfg.WAF.RuleEngine {
		case "On", "DetectionOnly", "Off":
		default:
			return fmt.Errorf("invalid waf rule_engine %q", cfg.WAF.RuleEngine)
		}
		if cfg.WAF.RequestBodyLimitBytes < 0 {
			return fmt.Errorf("waf request_body_limit_bytes must be non-negative")
		}
	}
	return nil
}
