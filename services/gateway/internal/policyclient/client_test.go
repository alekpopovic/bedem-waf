package policyclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
)

func TestCacheHit(t *testing.T) {
	var calls atomic.Int64
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writePolicy(t, w)
	})
	provider := testProvider(t, server.URL, FailClosed, time.Minute)

	first := provider.Lookup(context.Background(), "Example.Local")
	second := provider.Lookup(context.Background(), "example.local")

	if !first.Found || !second.Found {
		t.Fatalf("lookups found = %v/%v, want true/true", first.Found, second.Found)
	}
	if calls.Load() != 1 {
		t.Fatalf("control api calls = %d, want 1", calls.Load())
	}
	if provider.Metrics().PolicyCacheHitTotal() == 0 {
		t.Fatal("policy_cache_hit_total = 0, want hit recorded")
	}
}

func TestCacheMiss(t *testing.T) {
	var calls atomic.Int64
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writePolicy(t, w)
	})
	provider := testProvider(t, server.URL, FailClosed, time.Minute)

	got := provider.Lookup(context.Background(), "example.local")

	if !got.Found {
		t.Fatalf("lookup found = false, want true")
	}
	if calls.Load() != 1 {
		t.Fatalf("control api calls = %d, want 1", calls.Load())
	}
	if provider.Metrics().PolicyCacheMissTotal() != 1 {
		t.Fatalf("policy_cache_miss_total = %d, want 1", provider.Metrics().PolicyCacheMissTotal())
	}
}

func TestExpiredPolicyRefresh(t *testing.T) {
	var calls atomic.Int64
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		writePolicy(t, w)
	})
	provider := testProvider(t, server.URL, FailClosed, time.Second)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	provider.now = func() time.Time { return now }

	_ = provider.Lookup(context.Background(), "example.local")
	now = now.Add(2 * time.Second)
	_ = provider.Lookup(context.Background(), "example.local")

	if calls.Load() != 2 {
		t.Fatalf("control api calls = %d, want 2", calls.Load())
	}
}

func TestStaleFallback(t *testing.T) {
	var fail atomic.Bool
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		writePolicy(t, w)
	})
	provider := testProvider(t, server.URL, FailClosed, time.Second)
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	provider.now = func() time.Time { return now }

	_ = provider.Lookup(context.Background(), "example.local")
	fail.Store(true)
	now = now.Add(2 * time.Second)
	got := provider.Lookup(context.Background(), "example.local")

	if !got.Found || !got.Stale {
		t.Fatalf("lookup = %+v, want stale policy", got)
	}
	if provider.Metrics().PolicyFetchErrorTotal() != 1 {
		t.Fatalf("policy_fetch_error_total = %d, want 1", provider.Metrics().PolicyFetchErrorTotal())
	}
}

func TestFailOpenBehavior(t *testing.T) {
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	provider := testProvider(t, server.URL, FailOpen, time.Second)

	got := provider.Lookup(context.Background(), "example.local")

	if !got.FailOpen || got.Found {
		t.Fatalf("lookup = %+v, want fail-open without app", got)
	}
}

func TestFailClosedBehavior(t *testing.T) {
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	})
	provider := testProvider(t, server.URL, FailClosed, time.Second)

	got := provider.Lookup(context.Background(), "example.local")

	if got.Found || got.FailOpen || got.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("lookup = %+v, want fail-closed 503", got)
	}
}

func TestInvalidPolicyRejected(t *testing.T) {
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenant_id":         "tenant-1",
			"app_id":            "app-1",
			"policy_id":         "policy-1",
			"policy_version_id": "version-1",
			"mode":              "count",
		})
	})
	provider := testProvider(t, server.URL, FailClosed, time.Second)

	got := provider.Lookup(context.Background(), "example.local")

	if got.Found || got.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("lookup = %+v, want invalid policy to fail closed", got)
	}
}

func TestHostNormalization(t *testing.T) {
	var gotPath string
	server := policyServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writePolicy(t, w)
	})
	provider := testProvider(t, server.URL, FailClosed, time.Minute)

	result := provider.Lookup(context.Background(), "Example.Local:443")

	if !result.Found {
		t.Fatalf("lookup found = false, want true")
	}
	if !strings.HasSuffix(gotPath, "/example.local/policy") {
		t.Fatalf("request path = %q, want normalized hostname", gotPath)
	}
}

func testProvider(t *testing.T, baseURL string, failBehavior string, ttl time.Duration) *Provider {
	t.Helper()
	client, err := NewClient(config.ControlAPIConfig{
		BaseURL:       baseURL,
		GatewayAPIKey: "test-gateway-key",
	}, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	return NewProvider(client, config.ControlAPIConfig{
		CacheTTLSeconds: int(ttl.Seconds()),
		FailBehavior:    failBehavior,
	}, nil)
}

func policyServer(t *testing.T, handler func(http.ResponseWriter, *http.Request)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-gateway-key" {
			t.Fatalf("Authorization = %q, want gateway bearer", r.Header.Get("Authorization"))
		}
		handler(w, r)
	}))
}

func writePolicy(t *testing.T, w http.ResponseWriter) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tenant_id":         "tenant-1",
		"app_id":            "app-1",
		"policy_id":         "policy-1",
		"policy_version_id": "version-1",
		"mode":              "count",
		"origin": map[string]any{
			"url": "http://origin.local:9000",
		},
		"ip_sets": map[string][]string{
			"office": []string{"198.51.100.0/24"},
		},
		"custom_rules": []map[string]any{},
		"rate_limits":  []map[string]any{},
		"waf":          map[string]any{"enabled": true},
	})
}
