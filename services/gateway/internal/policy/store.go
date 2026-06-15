package policy

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
)

type App struct {
	ID              string
	Hostnames       []string
	Origin          *url.URL
	Mode            decision.Mode
	DefaultAction   decision.Action
	IPBlocklist     []netip.Prefix
	IPAllowlist     []netip.Prefix
	RateLimits      []RateLimitRule
	RawOriginString string
}

type RateLimitRule struct {
	Name          string
	Key           string
	Limit         int
	WindowSeconds int
	Action        decision.Action
}

type Store struct {
	byHost map[string]*App
}

func NewStore(apps []config.AppConfig) (*Store, error) {
	store := &Store{byHost: make(map[string]*App)}
	for _, appCfg := range apps {
		app, err := newApp(appCfg)
		if err != nil {
			return nil, err
		}
		for _, hostname := range app.Hostnames {
			host := NormalizeHost(hostname)
			if existing := store.byHost[host]; existing != nil {
				return nil, fmt.Errorf("hostname %q configured for both %q and %q", host, existing.ID, app.ID)
			}
			store.byHost[host] = app
		}
	}
	return store, nil
}

func newApp(appCfg config.AppConfig) (*App, error) {
	origin, err := url.Parse(appCfg.Origin.URL)
	if err != nil {
		return nil, fmt.Errorf("parse origin for app %q: %w", appCfg.ID, err)
	}
	if origin.Scheme == "" || origin.Host == "" {
		return nil, fmt.Errorf("origin for app %q must include scheme and host", appCfg.ID)
	}

	blocklist, err := parsePrefixes(appCfg.Policy.IPBlocklist)
	if err != nil {
		return nil, fmt.Errorf("parse blocklist for app %q: %w", appCfg.ID, err)
	}
	allowlist, err := parsePrefixes(appCfg.Policy.IPAllowlist)
	if err != nil {
		return nil, fmt.Errorf("parse allowlist for app %q: %w", appCfg.ID, err)
	}

	app := &App{
		ID:              appCfg.ID,
		Hostnames:       appCfg.Hostnames,
		Origin:          origin,
		Mode:            decision.Mode(appCfg.Policy.Mode),
		DefaultAction:   decision.Action(appCfg.Policy.DefaultAction),
		IPBlocklist:     blocklist,
		IPAllowlist:     allowlist,
		RawOriginString: appCfg.Origin.URL,
	}
	for _, limit := range appCfg.Policy.RateLimits {
		app.RateLimits = append(app.RateLimits, RateLimitRule{
			Name:          limit.Name,
			Key:           limit.Key,
			Limit:         limit.Limit,
			WindowSeconds: limit.WindowSeconds,
			Action:        decision.Action(limit.Action),
		})
	}
	return app, nil
}

func (s *Store) MatchHost(host string) (*App, bool) {
	app, ok := s.byHost[NormalizeHost(host)]
	return app, ok
}

func NormalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			return strings.Trim(parsedHost, "[]")
		}
	}
	return strings.Trim(host, "[]")
}

func (a *App) EvaluateIP(clientIP netip.Addr) decision.Decision {
	for _, prefix := range a.IPBlocklist {
		if prefix.Contains(clientIP) {
			return decision.Block("ip_blocklist", "ip_blocklist:"+prefix.String())
		}
	}
	return decision.Allow()
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}
