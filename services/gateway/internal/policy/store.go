package policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
)

type App struct {
	ID              string
	TenantID        string
	Hostnames       []string
	Origin          *url.URL
	Mode            decision.Mode
	DefaultAction   decision.Action
	IPBlocklist     []netip.Prefix
	IPAllowlist     []netip.Prefix
	IPSets          map[string][]netip.Prefix
	RateLimits      []RateLimitRule
	CustomRules     []CustomRule
	RawOriginString string
}

type RateLimitRule struct {
	ID              string
	Name            string
	Enabled         bool
	Priority        int
	MatchExpression *Condition
	KeyType         string
	KeyHeader       string
	Limit           int
	WindowSeconds   int
	Action          decision.Action
	StatusCode      int
}

type CustomRule struct {
	ID            string
	Name          string
	Priority      int
	Enabled       bool
	Action        decision.Action
	StatusCode    int
	TerminalAllow bool
	When          Condition
}

type RequestContext struct {
	Method   string
	Path     string
	Host     string
	Headers  http.Header
	Query    url.Values
	ClientIP netip.Addr
}

type Condition struct {
	All                []Condition
	Any                []Condition
	MethodEquals       string
	PathEquals         string
	PathStartsWith     string
	HostEquals         string
	HeaderContains     *HeaderCondition
	HeaderEquals       *HeaderCondition
	QueryParamContains *QueryParamCondition
	ClientIPInIPSet    string
	ClientIPNotInIPSet string
}

type HeaderCondition struct {
	Name  string
	Value string
}

type QueryParamCondition struct {
	Name  string
	Value string
}

type Store struct {
	byHost map[string]*App
}

type LookupResult struct {
	App        *App
	Found      bool
	FailOpen   bool
	StatusCode int
	Reason     string
	Warning    string
	Stale      bool
}

type Provider interface {
	Lookup(ctx context.Context, host string) LookupResult
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

func NewApp(appCfg config.AppConfig) (*App, error) {
	return newApp(appCfg)
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
	ipSets, err := parseIPSets(appCfg.Policy.IPSets)
	if err != nil {
		return nil, fmt.Errorf("parse ip sets for app %q: %w", appCfg.ID, err)
	}
	customRules, err := parseCustomRules(appCfg.Policy.CustomRules, ipSets)
	if err != nil {
		return nil, fmt.Errorf("parse custom rules for app %q: %w", appCfg.ID, err)
	}

	app := &App{
		ID:              appCfg.ID,
		TenantID:        appCfg.TenantID,
		Hostnames:       appCfg.Hostnames,
		Origin:          origin,
		Mode:            decision.Mode(appCfg.Policy.Mode),
		DefaultAction:   decision.Action(appCfg.Policy.DefaultAction),
		IPBlocklist:     blocklist,
		IPAllowlist:     allowlist,
		IPSets:          ipSets,
		CustomRules:     customRules,
		RawOriginString: appCfg.Origin.URL,
	}
	if app.TenantID == "" {
		app.TenantID = "default"
	}
	rateLimits, err := parseRateLimitRules(appCfg.Policy.RateLimits, ipSets)
	if err != nil {
		return nil, fmt.Errorf("parse rate limits for app %q: %w", appCfg.ID, err)
	}
	app.RateLimits = rateLimits
	return app, nil
}

func (s *Store) MatchHost(host string) (*App, bool) {
	app, ok := s.byHost[NormalizeHost(host)]
	return app, ok
}

func (s *Store) Lookup(_ context.Context, host string) LookupResult {
	app, ok := s.MatchHost(host)
	if !ok {
		return LookupResult{Found: false, Reason: "no_matching_app"}
	}
	return LookupResult{App: app, Found: true}
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

func (a *App) EvaluateCustomRules(ctx RequestContext) decision.Decision {
	var firstCount decision.Decision
	for _, rule := range a.CustomRules {
		if !rule.Enabled {
			continue
		}
		if !rule.When.Match(ctx, a.IPSets) {
			continue
		}
		switch rule.Action {
		case decision.ActionBlock:
			got := decision.WithStatus(decision.Block("custom_rule", rule.ID), rule.StatusCode)
			got.MatchedRuleName = rule.Name
			got.RuleGroup = "custom"
			got.Tags = []string{"custom_rule"}
			return got
		case decision.ActionCount:
			if firstCount.Action == "" {
				firstCount = decision.Count("custom_rule", rule.ID)
				firstCount.MatchedRuleName = rule.Name
				firstCount.RuleGroup = "custom"
				firstCount.Tags = []string{"custom_rule"}
			}
		case decision.ActionAllow:
			if rule.TerminalAllow {
				got := decision.AllowRule("custom_rule_allow", rule.ID)
				got.MatchedRuleName = rule.Name
				got.RuleGroup = "custom"
				got.Tags = []string{"custom_rule", "terminal_allow"}
				return got
			}
		}
	}
	if firstCount.Action != "" {
		return firstCount
	}
	return decision.Allow()
}

func (c Condition) Match(ctx RequestContext, ipSets map[string][]netip.Prefix) bool {
	if len(c.All) > 0 {
		for _, child := range c.All {
			if !child.Match(ctx, ipSets) {
				return false
			}
		}
		return true
	}
	if len(c.Any) > 0 {
		for _, child := range c.Any {
			if child.Match(ctx, ipSets) {
				return true
			}
		}
		return false
	}
	if c.MethodEquals != "" {
		return strings.EqualFold(ctx.Method, c.MethodEquals)
	}
	if c.PathEquals != "" {
		return ctx.Path == c.PathEquals
	}
	if c.PathStartsWith != "" {
		return strings.HasPrefix(ctx.Path, c.PathStartsWith)
	}
	if c.HostEquals != "" {
		return NormalizeHost(ctx.Host) == NormalizeHost(c.HostEquals)
	}
	if c.HeaderContains != nil {
		return headerContains(ctx.Headers, c.HeaderContains.Name, c.HeaderContains.Value)
	}
	if c.HeaderEquals != nil {
		return headerEquals(ctx.Headers, c.HeaderEquals.Name, c.HeaderEquals.Value)
	}
	if c.QueryParamContains != nil {
		for _, value := range ctx.Query[c.QueryParamContains.Name] {
			if strings.Contains(value, c.QueryParamContains.Value) {
				return true
			}
		}
		return false
	}
	if c.ClientIPInIPSet != "" {
		return ipInSet(ctx.ClientIP, ipSets[c.ClientIPInIPSet])
	}
	if c.ClientIPNotInIPSet != "" {
		return !ipInSet(ctx.ClientIP, ipSets[c.ClientIPNotInIPSet])
	}
	return false
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

func parseIPSets(values map[string][]string) (map[string][]netip.Prefix, error) {
	sets := make(map[string][]netip.Prefix, len(values))
	for name, cidrs := range values {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("ip set name cannot be empty")
		}
		prefixes, err := parsePrefixes(cidrs)
		if err != nil {
			return nil, fmt.Errorf("ip set %q: %w", name, err)
		}
		sets[name] = prefixes
	}
	return sets, nil
}

func parseCustomRules(values []config.CustomRuleConfig, ipSets map[string][]netip.Prefix) ([]CustomRule, error) {
	rules := make([]CustomRule, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value.ID) == "" {
			return nil, fmt.Errorf("custom rule id is required")
		}
		if _, ok := seen[value.ID]; ok {
			return nil, fmt.Errorf("duplicate custom rule id %q", value.ID)
		}
		seen[value.ID] = struct{}{}
		if value.Name == "" {
			return nil, fmt.Errorf("custom rule %q name is required", value.ID)
		}
		action := decision.Action(value.Action)
		switch action {
		case decision.ActionAllow, decision.ActionCount, decision.ActionBlock:
		default:
			return nil, fmt.Errorf("custom rule %q has unsupported action %q", value.ID, value.Action)
		}
		if value.StatusCode < 0 || value.StatusCode > 999 {
			return nil, fmt.Errorf("custom rule %q has invalid status_code %d", value.ID, value.StatusCode)
		}
		condition, err := parseCondition(value.When, ipSets)
		if err != nil {
			return nil, fmt.Errorf("custom rule %q: %w", value.ID, err)
		}
		rules = append(rules, CustomRule{
			ID:            value.ID,
			Name:          value.Name,
			Priority:      value.Priority,
			Enabled:       value.Enabled,
			Action:        action,
			StatusCode:    value.StatusCode,
			TerminalAllow: value.TerminalAllow,
			When:          condition,
		})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	return rules, nil
}

func parseRateLimitRules(values []config.RateLimitConfig, ipSets map[string][]netip.Prefix) ([]RateLimitRule, error) {
	rules := make([]RateLimitRule, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value.ID) == "" {
			return nil, fmt.Errorf("rate limit id is required")
		}
		if _, ok := seen[value.ID]; ok {
			return nil, fmt.Errorf("duplicate rate limit id %q", value.ID)
		}
		seen[value.ID] = struct{}{}
		if value.Name == "" {
			return nil, fmt.Errorf("rate limit %q name is required", value.ID)
		}
		if value.Limit <= 0 {
			return nil, fmt.Errorf("rate limit %q limit must be positive", value.ID)
		}
		if value.WindowSeconds <= 0 {
			return nil, fmt.Errorf("rate limit %q window_seconds must be positive", value.ID)
		}
		action := decision.Action(value.Action)
		if action != decision.ActionCount && action != decision.ActionBlock {
			return nil, fmt.Errorf("rate limit %q has unsupported action %q", value.ID, value.Action)
		}
		switch value.KeyType {
		case "ip", "host", "path", "header", "api_key_placeholder":
		default:
			return nil, fmt.Errorf("rate limit %q has unsupported key_type %q", value.ID, value.KeyType)
		}
		if value.KeyType == "header" && value.KeyHeader == "" {
			return nil, fmt.Errorf("rate limit %q key_header is required for header key_type", value.ID)
		}
		if value.StatusCode < 0 || value.StatusCode > 999 {
			return nil, fmt.Errorf("rate limit %q has invalid status_code %d", value.ID, value.StatusCode)
		}
		var match *Condition
		if hasCondition(value.MatchExpression) {
			condition, err := parseCondition(value.MatchExpression, ipSets)
			if err != nil {
				return nil, fmt.Errorf("rate limit %q match: %w", value.ID, err)
			}
			match = &condition
		}
		rules = append(rules, RateLimitRule{
			ID:              value.ID,
			Name:            value.Name,
			Enabled:         value.Enabled,
			Priority:        value.Priority,
			MatchExpression: match,
			KeyType:         value.KeyType,
			KeyHeader:       canonicalHeaderName(value.KeyHeader),
			Limit:           value.Limit,
			WindowSeconds:   value.WindowSeconds,
			Action:          action,
			StatusCode:      value.StatusCode,
		})
	}
	sort.SliceStable(rules, func(i, j int) bool {
		return rules[i].Priority < rules[j].Priority
	})
	return rules, nil
}

func parseCondition(value config.ConditionConfig, ipSets map[string][]netip.Prefix) (Condition, error) {
	if err := validateCondition(value, ipSets); err != nil {
		return Condition{}, err
	}
	condition := Condition{
		MethodEquals:       value.MethodEquals,
		PathEquals:         value.PathEquals,
		PathStartsWith:     value.PathStartsWith,
		HostEquals:         value.HostEquals,
		ClientIPInIPSet:    value.ClientIPInIPSet,
		ClientIPNotInIPSet: value.ClientIPNotInIPSet,
	}
	for _, child := range value.All {
		parsed, err := parseCondition(child, ipSets)
		if err != nil {
			return Condition{}, err
		}
		condition.All = append(condition.All, parsed)
	}
	for _, child := range value.Any {
		parsed, err := parseCondition(child, ipSets)
		if err != nil {
			return Condition{}, err
		}
		condition.Any = append(condition.Any, parsed)
	}
	if value.HeaderContains != nil {
		condition.HeaderContains = &HeaderCondition{Name: canonicalHeaderName(value.HeaderContains.Name), Value: value.HeaderContains.Value}
	}
	if value.HeaderEquals != nil {
		condition.HeaderEquals = &HeaderCondition{Name: canonicalHeaderName(value.HeaderEquals.Name), Value: value.HeaderEquals.Value}
	}
	if value.QueryParamContains != nil {
		condition.QueryParamContains = &QueryParamCondition{Name: value.QueryParamContains.Name, Value: value.QueryParamContains.Value}
	}
	return condition, nil
}

func validateCondition(value config.ConditionConfig, ipSets map[string][]netip.Prefix) error {
	operators := 0
	check := func(ok bool) {
		if ok {
			operators++
		}
	}
	check(len(value.All) > 0)
	check(len(value.Any) > 0)
	check(value.MethodEquals != "")
	check(value.PathEquals != "")
	check(value.PathStartsWith != "")
	check(value.HostEquals != "")
	check(value.HeaderContains != nil)
	check(value.HeaderEquals != nil)
	check(value.QueryParamContains != nil)
	check(value.ClientIPInIPSet != "")
	check(value.ClientIPNotInIPSet != "")
	if operators != 1 {
		return fmt.Errorf("when condition must contain exactly one operator, got %d", operators)
	}
	if value.HeaderContains != nil && (value.HeaderContains.Name == "" || value.HeaderContains.Value == "") {
		return fmt.Errorf("header_contains requires name and value")
	}
	if value.HeaderEquals != nil && (value.HeaderEquals.Name == "" || value.HeaderEquals.Value == "") {
		return fmt.Errorf("header_equals requires name and value")
	}
	if value.QueryParamContains != nil && (value.QueryParamContains.Name == "" || value.QueryParamContains.Value == "") {
		return fmt.Errorf("query_parameter_contains requires name and value")
	}
	if value.ClientIPInIPSet != "" {
		if _, ok := ipSets[value.ClientIPInIPSet]; !ok {
			return fmt.Errorf("unknown ip set %q", value.ClientIPInIPSet)
		}
	}
	if value.ClientIPNotInIPSet != "" {
		if _, ok := ipSets[value.ClientIPNotInIPSet]; !ok {
			return fmt.Errorf("unknown ip set %q", value.ClientIPNotInIPSet)
		}
	}
	return nil
}

func hasCondition(value config.ConditionConfig) bool {
	return len(value.All) > 0 ||
		len(value.Any) > 0 ||
		value.MethodEquals != "" ||
		value.PathEquals != "" ||
		value.PathStartsWith != "" ||
		value.HostEquals != "" ||
		value.HeaderContains != nil ||
		value.HeaderEquals != nil ||
		value.QueryParamContains != nil ||
		value.ClientIPInIPSet != "" ||
		value.ClientIPNotInIPSet != ""
}

func headerContains(headers http.Header, name string, value string) bool {
	for _, got := range headers[canonicalHeaderName(name)] {
		if strings.Contains(got, value) {
			return true
		}
	}
	return false
}

func headerEquals(headers http.Header, name string, value string) bool {
	for _, got := range headers[canonicalHeaderName(name)] {
		if got == value {
			return true
		}
	}
	return false
}

func ipInSet(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func canonicalHeaderName(name string) string {
	return http.CanonicalHeaderKey(strings.TrimSpace(name))
}
