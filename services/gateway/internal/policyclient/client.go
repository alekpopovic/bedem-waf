package policyclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
)

const (
	FailOpen             = "fail_open"
	FailClosed           = "fail_closed"
	UseStaleThenFailOpen = "use_stale_then_fail_open"
)

type Client struct {
	baseURL       *url.URL
	gatewayAPIKey string
	httpClient    *http.Client
	timeout       time.Duration
}

func NewClient(cfg config.ControlAPIConfig, httpClient *http.Client) (*Client, error) {
	base, err := url.Parse(strings.TrimRight(cfg.BaseURL, "/"))
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid control api base_url")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}
	return &Client{
		baseURL:       base,
		gatewayAPIKey: cfg.GatewayAPIKey,
		httpClient:    httpClient,
		timeout:       3 * time.Second,
	}, nil
}

func (c *Client) FetchPolicy(ctx context.Context, hostname string) (*policy.App, error) {
	if c.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}
	endpoint := c.baseURL.ResolveReference(&url.URL{
		Path: "/v1/gateway/apps/" + url.PathEscape(policy.NormalizeHost(hostname)) + "/policy",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.gatewayAPIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control api returned status %d", resp.StatusCode)
	}
	var remote gatewayPolicy
	decoder := json.NewDecoder(resp.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&remote); err != nil {
		return nil, err
	}
	return remote.toApp(hostname)
}

type Metrics struct {
	policyCacheHitTotal   atomic.Uint64
	policyCacheMissTotal  atomic.Uint64
	policyFetchErrorTotal atomic.Uint64
}

func (m *Metrics) PolicyCacheHitTotal() uint64 {
	return m.policyCacheHitTotal.Load()
}

func (m *Metrics) PolicyCacheMissTotal() uint64 {
	return m.policyCacheMissTotal.Load()
}

func (m *Metrics) PolicyFetchErrorTotal() uint64 {
	return m.policyFetchErrorTotal.Load()
}

type Provider struct {
	client       *Client
	ttl          time.Duration
	failBehavior string
	logger       *slog.Logger
	now          func() time.Time
	metrics      *Metrics

	mu    sync.Mutex
	cache map[string]cacheEntry
	locks map[string]*sync.Mutex
}

type cacheEntry struct {
	app       *policy.App
	expiresAt time.Time
}

func NewProvider(client *Client, cfg config.ControlAPIConfig, logger *slog.Logger) *Provider {
	if logger == nil {
		logger = slog.Default()
	}
	ttl := time.Duration(cfg.CacheTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	failBehavior := cfg.FailBehavior
	if failBehavior == "" {
		failBehavior = UseStaleThenFailOpen
	}
	return &Provider{
		client:       client,
		ttl:          ttl,
		failBehavior: failBehavior,
		logger:       logger,
		now:          time.Now,
		metrics:      &Metrics{},
		cache:        make(map[string]cacheEntry),
		locks:        make(map[string]*sync.Mutex),
	}
}

func (p *Provider) Lookup(ctx context.Context, host string) policy.LookupResult {
	host = policy.NormalizeHost(host)
	if host == "" {
		return policy.LookupResult{Found: false, Reason: "empty_host"}
	}
	now := p.now().UTC()
	if entry, ok := p.cached(host); ok && now.Before(entry.expiresAt) {
		p.metrics.policyCacheHitTotal.Add(1)
		return policy.LookupResult{App: entry.app, Found: true}
	}
	p.metrics.policyCacheMissTotal.Add(1)

	lock := p.hostLock(host)
	lock.Lock()
	defer lock.Unlock()

	now = p.now().UTC()
	if entry, ok := p.cached(host); ok && now.Before(entry.expiresAt) {
		p.metrics.policyCacheHitTotal.Add(1)
		return policy.LookupResult{App: entry.app, Found: true}
	}

	app, err := p.client.FetchPolicy(ctx, host)
	if err == nil {
		p.store(host, cacheEntry{app: app, expiresAt: now.Add(p.ttl)})
		return policy.LookupResult{App: app, Found: true}
	}
	p.metrics.policyFetchErrorTotal.Add(1)
	p.logger.Warn("policy_fetch_failed", "host", host, "error", err)

	if stale, ok := p.cached(host); ok && stale.app != nil {
		return policy.LookupResult{App: stale.app, Found: true, Stale: true, Warning: "policy_fetch_failed_using_stale"}
	}

	switch p.failBehavior {
	case FailClosed:
		return policy.LookupResult{Found: false, StatusCode: http.StatusServiceUnavailable, Reason: "policy_fetch_failed"}
	case FailOpen, UseStaleThenFailOpen:
		return policy.LookupResult{Found: false, FailOpen: true, Reason: "policy_fetch_failed_fail_open", Warning: "policy_fetch_failed_fail_open"}
	default:
		return policy.LookupResult{Found: false, FailOpen: true, Reason: "policy_fetch_failed_fail_open", Warning: "policy_fetch_failed_fail_open"}
	}
}

func (p *Provider) Metrics() *Metrics {
	return p.metrics
}

func (p *Provider) cached(host string) (cacheEntry, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.cache[host]
	return entry, ok
}

func (p *Provider) store(host string, entry cacheEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cache[host] = entry
}

func (p *Provider) hostLock(host string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	lock := p.locks[host]
	if lock == nil {
		lock = &sync.Mutex{}
		p.locks[host] = lock
	}
	return lock
}

type gatewayPolicy struct {
	TenantID        string          `json:"tenant_id"`
	AppID           string          `json:"app_id"`
	PolicyID        string          `json:"policy_id"`
	PolicyVersionID string          `json:"policy_version_id"`
	Mode            string          `json:"mode"`
	Origin          remoteOrigin    `json:"origin"`
	IPSets          json.RawMessage `json:"ip_sets"`
	CustomRules     json.RawMessage `json:"custom_rules"`
	RateLimits      json.RawMessage `json:"rate_limits"`
	WAF             json.RawMessage `json:"waf"`
	PublishedAt     string          `json:"published_at"`
}

type remoteOrigin struct {
	URL    string `json:"url"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

func (p gatewayPolicy) toApp(hostname string) (*policy.App, error) {
	if p.TenantID == "" || p.AppID == "" || p.PolicyID == "" || p.PolicyVersionID == "" {
		return nil, errors.New("gateway policy missing required identifiers")
	}
	originURL := p.Origin.URL
	if originURL == "" && p.Origin.Scheme != "" && p.Origin.Host != "" {
		originURL = fmt.Sprintf("%s://%s", p.Origin.Scheme, p.Origin.Host)
		if p.Origin.Port > 0 {
			originURL = fmt.Sprintf("%s:%d", originURL, p.Origin.Port)
		}
	}
	if originURL == "" {
		return nil, errors.New("gateway policy missing origin")
	}
	ipSets, err := decodeIPSets(p.IPSets)
	if err != nil {
		return nil, err
	}
	customRules, err := decodeCustomRules(p.CustomRules)
	if err != nil {
		return nil, err
	}
	rateLimits, err := decodeRateLimits(p.RateLimits)
	if err != nil {
		return nil, err
	}
	return policy.NewApp(config.AppConfig{
		ID:        p.AppID,
		TenantID:  p.TenantID,
		Hostnames: []string{policy.NormalizeHost(hostname)},
		Origin:    config.OriginConfig{URL: originURL},
		Policy: config.PolicyConfig{
			Mode:          p.Mode,
			DefaultAction: "allow",
			IPSets:        ipSets,
			CustomRules:   customRules,
			RateLimits:    rateLimits,
		},
	})
}

func decodeIPSets(raw json.RawMessage) (map[string][]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var got map[string][]string
	if err := json.Unmarshal(raw, &got); err != nil {
		return nil, fmt.Errorf("decode ip_sets: %w", err)
	}
	return got, nil
}

func decodeCustomRules(raw json.RawMessage) ([]config.CustomRuleConfig, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var got []customRule
	if err := json.Unmarshal(raw, &got); err != nil {
		return nil, fmt.Errorf("decode custom_rules: %w", err)
	}
	out := make([]config.CustomRuleConfig, 0, len(got))
	for _, rule := range got {
		out = append(out, config.CustomRuleConfig{
			ID:            rule.ID,
			Name:          rule.Name,
			Priority:      rule.Priority,
			Enabled:       rule.Enabled,
			Action:        rule.Action,
			StatusCode:    rule.StatusCode,
			TerminalAllow: rule.TerminalAllow,
			When:          rule.When,
		})
	}
	return out, nil
}

func decodeRateLimits(raw json.RawMessage) ([]config.RateLimitConfig, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var got []rateLimit
	if err := json.Unmarshal(raw, &got); err != nil {
		return nil, fmt.Errorf("decode rate_limits: %w", err)
	}
	out := make([]config.RateLimitConfig, 0, len(got))
	for _, rule := range got {
		out = append(out, config.RateLimitConfig{
			ID:              rule.ID,
			Name:            rule.Name,
			Enabled:         rule.Enabled,
			Priority:        rule.Priority,
			MatchExpression: rule.Match,
			KeyType:         rule.KeyType,
			KeyHeader:       rule.KeyHeader,
			Limit:           rule.Limit,
			WindowSeconds:   rule.WindowSeconds,
			Action:          rule.Action,
			StatusCode:      rule.StatusCode,
		})
	}
	return out, nil
}

type customRule struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Priority      int                    `json:"priority"`
	Enabled       bool                   `json:"enabled"`
	Action        string                 `json:"action"`
	StatusCode    int                    `json:"status_code"`
	TerminalAllow bool                   `json:"terminal_allow"`
	When          config.ConditionConfig `json:"when"`
}

type rateLimit struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Enabled       bool                   `json:"enabled"`
	Priority      int                    `json:"priority"`
	Match         config.ConditionConfig `json:"match"`
	KeyType       string                 `json:"key_type"`
	KeyHeader     string                 `json:"key_header"`
	Limit         int                    `json:"limit"`
	WindowSeconds int                    `json:"window_seconds"`
	Action        string                 `json:"action"`
	StatusCode    int                    `json:"status_code"`
}
