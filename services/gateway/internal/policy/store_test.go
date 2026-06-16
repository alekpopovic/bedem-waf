package policy

import (
	"net/http"
	"net/netip"
	"net/url"
	"testing"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
)

func TestHostMatchingNormalizesHostAndPort(t *testing.T) {
	store, err := NewStore([]config.AppConfig{{
		ID:        "app-local",
		Hostnames: []string{"Example.Local", "localhost"},
		Origin:    config.OriginConfig{URL: "http://localhost:9000"},
		Policy:    config.PolicyConfig{Mode: "count", DefaultAction: "allow"},
	}})
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}

	app, ok := store.MatchHost("example.local:8080")
	if !ok {
		t.Fatal("expected host match")
	}
	if app.ID != "app-local" {
		t.Fatalf("app.ID = %q, want app-local", app.ID)
	}
}

func TestCIDRIPBlocklist(t *testing.T) {
	store, err := NewStore([]config.AppConfig{{
		ID:        "app-local",
		Hostnames: []string{"example.local"},
		Origin:    config.OriginConfig{URL: "http://localhost:9000"},
		Policy: config.PolicyConfig{
			Mode:          "block",
			DefaultAction: "allow",
			IPBlocklist:   []string{"203.0.113.10/32"},
		},
	}})
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	app, _ := store.MatchHost("example.local")

	got := app.EvaluateIP(netip.MustParseAddr("203.0.113.10"))
	if got.Action != decision.ActionBlock {
		t.Fatalf("blocked IP action = %q, want block", got.Action)
	}

	got = app.EvaluateIP(netip.MustParseAddr("203.0.113.11"))
	if got.Action != decision.ActionAllow {
		t.Fatalf("allowed IP action = %q, want allow", got.Action)
	}
}

func TestCountModeDoesNotEnforceBlockDecision(t *testing.T) {
	block := decision.Block("ip_blocklist", "ip_blocklist:203.0.113.10/32")
	if got := decision.EnforcedAction(decision.ModeCount, block); got != decision.ActionCount {
		t.Fatalf("count mode enforced action = %q, want count", got)
	}
	if got := decision.EnforcedAction(decision.ModeBlock, block); got != decision.ActionBlock {
		t.Fatalf("block mode enforced action = %q, want block", got)
	}
}

func TestCustomRulePathPrefixMatch(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:         "rule-admin",
		Name:       "Admin block",
		Priority:   100,
		Enabled:    true,
		Action:     "block",
		StatusCode: 403,
		When:       config.ConditionConfig{PathStartsWith: "/admin"},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Path = "/admin/settings"
	}))
	if got.Action != decision.ActionBlock || got.MatchedRuleID != "rule-admin" {
		t.Fatalf("decision = %+v, want block from rule-admin", got)
	}
}

func TestCustomRulePathEqualsMatch(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-path",
		Name:     "Exact path",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When:     config.ConditionConfig{PathEquals: "/login"},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Path = "/login"
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleMethodMatch(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-post",
		Name:     "Count POST",
		Priority: 100,
		Enabled:  true,
		Action:   "count",
		When:     config.ConditionConfig{MethodEquals: http.MethodPost},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Method = http.MethodPost
	}))
	if got.Action != decision.ActionCount {
		t.Fatalf("decision = %+v, want count", got)
	}
}

func TestCustomRuleHostEqualsMatch(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-host",
		Name:     "Host",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When:     config.ConditionConfig{HostEquals: "Admin.Example.Local"},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Host = "admin.example.local"
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleHeaderContains(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-ua",
		Name:     "Bad UA",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When: config.ConditionConfig{HeaderContains: &config.HeaderMatch{
			Name:  "user-agent",
			Value: "bad-bot-test",
		}},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Headers.Set("User-Agent", "friendly bad-bot-test client")
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleHeaderEquals(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-header",
		Name:     "Header",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When: config.ConditionConfig{HeaderEquals: &config.HeaderMatch{
			Name:  "x-bedem-test",
			Value: "block-me",
		}},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Headers.Set("X-Bedem-Test", "block-me")
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleQueryParameterContains(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-query",
		Name:     "Query",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When: config.ConditionConfig{QueryParamContains: &config.QueryParamMatch{
			Name:  "next",
			Value: "/admin",
		}},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Query.Set("next", "/admin/settings")
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleIPSetMatch(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-office",
		Name:     "Office only",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When:     config.ConditionConfig{ClientIPNotInIPSet: "office_ips"},
	}}, map[string][]string{"office_ips": {"198.51.100.0/24"}})

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.ClientIP = netip.MustParseAddr("203.0.113.10")
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("outside office decision = %+v, want block", got)
	}

	got = app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.ClientIP = netip.MustParseAddr("198.51.100.10")
	}))
	if got.Action != decision.ActionAllow {
		t.Fatalf("inside office decision = %+v, want allow", got)
	}
}

func TestCustomRuleClientIPInIPSet(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-ip-in",
		Name:     "IP in set",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When:     config.ConditionConfig{ClientIPInIPSet: "blocked_ips"},
	}}, map[string][]string{"blocked_ips": {"203.0.113.0/24"}})

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.ClientIP = netip.MustParseAddr("203.0.113.10")
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleAllConditions(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-all",
		Name:     "All",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When: config.ConditionConfig{All: []config.ConditionConfig{
			{PathStartsWith: "/admin"},
			{MethodEquals: http.MethodPost},
		}},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Path = "/admin"
		ctx.Method = http.MethodPost
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestCustomRuleAnyConditions(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-any",
		Name:     "Any",
		Priority: 100,
		Enabled:  true,
		Action:   "block",
		When: config.ConditionConfig{Any: []config.ConditionConfig{
			{PathEquals: "/private"},
			{HostEquals: "admin.example.local"},
		}},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Host = "admin.example.local"
	}))
	if got.Action != decision.ActionBlock {
		t.Fatalf("decision = %+v, want block", got)
	}
}

func TestDisabledCustomRulesIgnored(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{{
		ID:       "rule-disabled",
		Name:     "Disabled",
		Priority: 100,
		Enabled:  false,
		Action:   "block",
		When:     config.ConditionConfig{PathStartsWith: "/"},
	}}, nil)

	got := app.EvaluateCustomRules(testRequestContext(nil))
	if got.Action != decision.ActionAllow {
		t.Fatalf("decision = %+v, want allow", got)
	}
}

func TestCustomRulePriorityOrder(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{
		{
			ID:       "rule-late",
			Name:     "Late",
			Priority: 200,
			Enabled:  true,
			Action:   "block",
			When:     config.ConditionConfig{PathStartsWith: "/"},
		},
		{
			ID:       "rule-early",
			Name:     "Early",
			Priority: 100,
			Enabled:  true,
			Action:   "block",
			When:     config.ConditionConfig{PathStartsWith: "/"},
		},
	}, nil)

	got := app.EvaluateCustomRules(testRequestContext(nil))
	if got.MatchedRuleID != "rule-early" {
		t.Fatalf("matched rule = %q, want rule-early", got.MatchedRuleID)
	}
}

func TestCustomRuleTerminalAllowShortCircuitsLaterBlock(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{
		{
			ID:            "rule-allow",
			Name:          "Allow",
			Priority:      100,
			Enabled:       true,
			Action:        "allow",
			TerminalAllow: true,
			When:          config.ConditionConfig{PathStartsWith: "/admin"},
		},
		{
			ID:       "rule-block",
			Name:     "Block",
			Priority: 200,
			Enabled:  true,
			Action:   "block",
			When:     config.ConditionConfig{PathStartsWith: "/admin"},
		},
	}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Path = "/admin"
	}))
	if got.Action != decision.ActionAllow || got.MatchedRuleID != "rule-allow" {
		t.Fatalf("decision = %+v, want terminal allow", got)
	}
}

func TestCustomRuleAllowWithoutTerminalDoesNotShortCircuitLaterBlock(t *testing.T) {
	app := testPolicyApp(t, []config.CustomRuleConfig{
		{
			ID:       "rule-allow",
			Name:     "Non-terminal allow",
			Priority: 100,
			Enabled:  true,
			Action:   "allow",
			When:     config.ConditionConfig{PathStartsWith: "/blocked-test"},
		},
		{
			ID:       "rule-block",
			Name:     "Block test path",
			Priority: 200,
			Enabled:  true,
			Action:   "block",
			When:     config.ConditionConfig{PathStartsWith: "/blocked-test"},
		},
	}, nil)

	got := app.EvaluateCustomRules(testRequestContext(func(ctx *RequestContext) {
		ctx.Path = "/blocked-test"
	}))
	if got.Action != decision.ActionBlock || got.MatchedRuleID != "rule-block" {
		t.Fatalf("decision = %+v, want later block to win", got)
	}
}

func TestCustomRuleInvalidValidation(t *testing.T) {
	_, err := NewStore([]config.AppConfig{{
		ID:        "app-local",
		Hostnames: []string{"example.local"},
		Origin:    config.OriginConfig{URL: "http://localhost:9000"},
		Policy: config.PolicyConfig{
			Mode:          "count",
			DefaultAction: "allow",
			CustomRules: []config.CustomRuleConfig{{
				ID:      "rule-invalid",
				Name:    "Invalid",
				Enabled: true,
				Action:  "block",
				When: config.ConditionConfig{
					MethodEquals:   http.MethodGet,
					PathStartsWith: "/admin",
				},
			}},
		},
	}})
	if err == nil {
		t.Fatal("NewStore() error = nil, want invalid rule validation error")
	}
}

func TestCustomRuleUnknownIPSetValidation(t *testing.T) {
	_, err := NewStore([]config.AppConfig{{
		ID:        "app-local",
		Hostnames: []string{"example.local"},
		Origin:    config.OriginConfig{URL: "http://localhost:9000"},
		Policy: config.PolicyConfig{
			Mode:          "count",
			DefaultAction: "allow",
			CustomRules: []config.CustomRuleConfig{{
				ID:      "rule-missing-ip-set",
				Name:    "Missing IP set",
				Enabled: true,
				Action:  "block",
				When:    config.ConditionConfig{ClientIPInIPSet: "office_ips"},
			}},
		},
	}})
	if err == nil {
		t.Fatal("NewStore() error = nil, want unknown IP set validation error")
	}
}

func testPolicyApp(t *testing.T, rules []config.CustomRuleConfig, ipSets map[string][]string) *App {
	t.Helper()
	store, err := NewStore([]config.AppConfig{{
		ID:        "app-local",
		Hostnames: []string{"example.local"},
		Origin:    config.OriginConfig{URL: "http://localhost:9000"},
		Policy: config.PolicyConfig{
			Mode:          "count",
			DefaultAction: "allow",
			IPSets:        ipSets,
			CustomRules:   rules,
		},
	}})
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	app, ok := store.MatchHost("example.local")
	if !ok {
		t.Fatal("expected app match")
	}
	return app
}

func testRequestContext(mutator func(*RequestContext)) RequestContext {
	ctx := RequestContext{
		Method:   http.MethodGet,
		Path:     "/",
		Host:     "example.local",
		Headers:  http.Header{},
		Query:    url.Values{},
		ClientIP: netip.MustParseAddr("198.51.100.10"),
	}
	if mutator != nil {
		mutator(&ctx)
	}
	return ctx
}
