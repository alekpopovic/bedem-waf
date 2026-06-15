package policy

import (
	"net/netip"
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
