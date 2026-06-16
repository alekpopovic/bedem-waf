package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Redis      RedisConfig      `yaml:"redis"`
	WAF        WAFConfig        `yaml:"waf"`
	ControlAPI ControlAPIConfig `yaml:"control_api"`
	Apps       []AppConfig      `yaml:"apps"`
}

type ServerConfig struct {
	ListenAddr     string   `yaml:"listen_addr"`
	TrustedProxies []string `yaml:"trusted_proxies"`
}

type RedisConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Addr     string `yaml:"addr"`
	FailMode string `yaml:"fail_mode"`
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

type ControlAPIConfig struct {
	Enabled         bool   `yaml:"enabled"`
	BaseURL         string `yaml:"base_url"`
	GatewayAPIKey   string `yaml:"gateway_api_key"`
	CacheTTLSeconds int    `yaml:"cache_ttl_seconds"`
	FailBehavior    string `yaml:"fail_behavior"`
}

type AppConfig struct {
	ID        string       `yaml:"id"`
	TenantID  string       `yaml:"tenant_id"`
	Hostnames []string     `yaml:"hostnames"`
	Origin    OriginConfig `yaml:"origin"`
	Policy    PolicyConfig `yaml:"policy"`
}

type OriginConfig struct {
	URL string `yaml:"url"`
}

type PolicyConfig struct {
	Mode          string              `yaml:"mode"`
	DefaultAction string              `yaml:"default_action"`
	IPBlocklist   []string            `yaml:"ip_blocklist"`
	IPAllowlist   []string            `yaml:"ip_allowlist"`
	IPSets        map[string][]string `yaml:"ip_sets"`
	RateLimits    []RateLimitConfig   `yaml:"rate_limits"`
	CustomRules   []CustomRuleConfig  `yaml:"custom_rules"`
}

type RateLimitConfig struct {
	ID              string          `yaml:"id" json:"id"`
	Name            string          `yaml:"name" json:"name"`
	Enabled         bool            `yaml:"enabled" json:"enabled"`
	Priority        int             `yaml:"priority" json:"priority"`
	MatchExpression ConditionConfig `yaml:"match" json:"match"`
	KeyType         string          `yaml:"key_type" json:"key_type"`
	KeyHeader       string          `yaml:"key_header" json:"key_header"`
	Limit           int             `yaml:"limit" json:"limit"`
	WindowSeconds   int             `yaml:"window_seconds" json:"window_seconds"`
	Action          string          `yaml:"action" json:"action"`
	StatusCode      int             `yaml:"status_code" json:"status_code"`

	// Deprecated compatibility alias for older sample configs.
	Key string `yaml:"key" json:"key"`
}

type CustomRuleConfig struct {
	ID            string          `yaml:"id" json:"id"`
	Name          string          `yaml:"name" json:"name"`
	Priority      int             `yaml:"priority" json:"priority"`
	Enabled       bool            `yaml:"enabled" json:"enabled"`
	Action        string          `yaml:"action" json:"action"`
	StatusCode    int             `yaml:"status_code" json:"status_code"`
	TerminalAllow bool            `yaml:"terminal_allow" json:"terminal_allow"`
	When          ConditionConfig `yaml:"when" json:"when"`
}

type ConditionConfig struct {
	All                []ConditionConfig `yaml:"all" json:"all"`
	Any                []ConditionConfig `yaml:"any" json:"any"`
	MethodEquals       string            `yaml:"method_equals" json:"method_equals"`
	PathEquals         string            `yaml:"path_equals" json:"path_equals"`
	PathStartsWith     string            `yaml:"path_starts_with" json:"path_starts_with"`
	HostEquals         string            `yaml:"host_equals" json:"host_equals"`
	HeaderContains     *HeaderMatch      `yaml:"header_contains" json:"header_contains"`
	HeaderEquals       *HeaderMatch      `yaml:"header_equals" json:"header_equals"`
	QueryParamContains *QueryParamMatch  `yaml:"query_parameter_contains" json:"query_parameter_contains"`
	ClientIPInIPSet    string            `yaml:"client_ip_in_ip_set" json:"client_ip_in_ip_set"`
	ClientIPNotInIPSet string            `yaml:"client_ip_not_in_ip_set" json:"client_ip_not_in_ip_set"`
}

type HeaderMatch struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

type QueryParamMatch struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

func LoadFile(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader([]byte(os.ExpandEnv(string(data)))))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
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
	if cfg.Redis.FailMode == "" {
		cfg.Redis.FailMode = "open"
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
	if cfg.ControlAPI.BaseURL == "" {
		cfg.ControlAPI.BaseURL = "http://localhost:8081"
	}
	if cfg.ControlAPI.CacheTTLSeconds == 0 {
		cfg.ControlAPI.CacheTTLSeconds = 30
	}
	if cfg.ControlAPI.FailBehavior == "" {
		cfg.ControlAPI.FailBehavior = "use_stale_then_fail_open"
	}
	for i := range cfg.Apps {
		if cfg.Apps[i].Policy.Mode == "" {
			cfg.Apps[i].Policy.Mode = "count"
		}
		if cfg.Apps[i].Policy.DefaultAction == "" {
			cfg.Apps[i].Policy.DefaultAction = "allow"
		}
		for j := range cfg.Apps[i].Policy.RateLimits {
			if cfg.Apps[i].Policy.RateLimits[j].ID == "" {
				cfg.Apps[i].Policy.RateLimits[j].ID = cfg.Apps[i].Policy.RateLimits[j].Name
			}
			if cfg.Apps[i].Policy.RateLimits[j].KeyType == "" {
				cfg.Apps[i].Policy.RateLimits[j].KeyType = cfg.Apps[i].Policy.RateLimits[j].Key
			}
			if cfg.Apps[i].Policy.RateLimits[j].KeyType == "" {
				cfg.Apps[i].Policy.RateLimits[j].KeyType = "ip"
			}
			if cfg.Apps[i].Policy.RateLimits[j].Action == "" {
				cfg.Apps[i].Policy.RateLimits[j].Action = "count"
			}
			if cfg.Apps[i].Policy.RateLimits[j].StatusCode == 0 {
				cfg.Apps[i].Policy.RateLimits[j].StatusCode = 429
			}
		}
		for j := range cfg.Apps[i].Policy.CustomRules {
			if cfg.Apps[i].Policy.CustomRules[j].Action == "" {
				cfg.Apps[i].Policy.CustomRules[j].Action = "count"
			}
			if cfg.Apps[i].Policy.CustomRules[j].StatusCode == 0 {
				cfg.Apps[i].Policy.CustomRules[j].StatusCode = 403
			}
		}
	}
}

func validate(cfg Config) error {
	if len(cfg.Apps) == 0 && !cfg.ControlAPI.Enabled {
		return fmt.Errorf("at least one app is required")
	}
	if cfg.ControlAPI.Enabled {
		parsed, err := url.Parse(cfg.ControlAPI.BaseURL)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return fmt.Errorf("control_api base_url is invalid")
		}
		if cfg.ControlAPI.GatewayAPIKey == "" {
			return fmt.Errorf("control_api gateway_api_key is required when enabled")
		}
		if cfg.ControlAPI.CacheTTLSeconds <= 0 {
			return fmt.Errorf("control_api cache_ttl_seconds must be positive")
		}
		switch cfg.ControlAPI.FailBehavior {
		case "fail_open", "fail_closed", "use_stale_then_fail_open":
		default:
			return fmt.Errorf("invalid control_api fail_behavior %q", cfg.ControlAPI.FailBehavior)
		}
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
	switch cfg.Redis.FailMode {
	case "open", "closed":
	default:
		return fmt.Errorf("invalid redis fail_mode %q", cfg.Redis.FailMode)
	}
	return nil
}
