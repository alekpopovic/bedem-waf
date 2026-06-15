package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/audit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/ratelimit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/waf"
	corazawaf "github.com/bedemwaf/bedemwaf/services/gateway/internal/waf/coraza"
)

func TestNoMatchingAppReturns404(t *testing.T) {
	gateway := testGateway(t, "block", "http://127.0.0.1:9000", ratelimit.NoopLimiter{})
	req := httptest.NewRequest(http.MethodGet, "http://unknown.local/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestBlockModeReturns403ForBlockedIP(t *testing.T) {
	gateway := testGateway(t, "block", "http://127.0.0.1:9000", ratelimit.NoopLimiter{})
	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestCountModeAllowsWouldBlockIP(t *testing.T) {
	gateway := testGateway(t, "count", "http://127.0.0.1:1", ratelimit.NoopLimiter{})
	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("status = %d, want count mode to proxy instead of enforcing 403", rec.Code)
	}
}

func TestReverseProxyTargetConstruction(t *testing.T) {
	target, err := NewTarget("http://localhost:9000/base")
	if err != nil {
		t.Fatalf("NewTarget() error = %v", err)
	}
	if target.Scheme != "http" || target.Host != "localhost:9000" || target.Path != "/base" {
		t.Fatalf("target = %s, want http://localhost:9000/base", target.String())
	}

	if _, err := NewTarget("localhost:9000"); err == nil {
		t.Fatal("NewTarget() error = nil, want invalid target error")
	}
}

func TestRateLimitBlockReturns403(t *testing.T) {
	limiter := fakeLimiter{decision: decision.RateLimit("rate_limit", "rate_limit:test")}
	gateway := testGateway(t, "block", "http://127.0.0.1:9000", limiter)
	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestCorazaCountModeAllowsButLogsWouldBlock(t *testing.T) {
	var auditOutput bytes.Buffer
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return textResponse(req, http.StatusNoContent, "")
	})
	gateway := testGatewayWithOptions(t, testGatewayOptions{
		mode:      "count",
		originURL: "http://origin.local",
		limiter:   ratelimit.NoopLimiter{},
		waf:       testCorazaEngine(t, "On"),
		transport: transport,
		auditOut:  &auditOutput,
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.Header.Set("X-Bedem-Test", "block-me")
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	event := decodeAuditEvent(t, auditOutput.Bytes())
	if event["action"] != string(decision.ActionCount) {
		t.Fatalf("audit action = %v, want count", event["action"])
	}
	if event["matched_rule_id"] != "coraza:1000001" {
		t.Fatalf("matched_rule_id = %v, want coraza:1000001", event["matched_rule_id"])
	}
}

func TestCorazaBlockModeReturns403(t *testing.T) {
	gateway := testGatewayWithOptions(t, testGatewayOptions{
		mode:      "block",
		originURL: "http://origin.local",
		limiter:   ratelimit.NoopLimiter{},
		waf:       testCorazaEngine(t, "On"),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			t.Fatal("origin should not be called for blocked request")
			return nil, nil
		}),
		auditOut: io.Discard,
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.Header.Set("X-Bedem-Test", "block-me")
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestCorazaDetectionOnlyAllowsInBlockMode(t *testing.T) {
	gateway := testGatewayWithOptions(t, testGatewayOptions{
		mode:      "block",
		originURL: "http://origin.local",
		limiter:   ratelimit.NoopLimiter{},
		waf:       testCorazaEngine(t, "DetectionOnly"),
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return textResponse(req, http.StatusAccepted, "")
		}),
		auditOut: io.Discard,
	})

	req := httptest.NewRequest(http.MethodGet, "http://example.local/", nil)
	req.Header.Set("X-Bedem-Test", "block-me")
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}
}

func TestRequestBodyRestoredBeforeProxying(t *testing.T) {
	const body = "hello from client"
	var gotBody string
	gateway := testGatewayWithOptions(t, testGatewayOptions{
		mode:      "count",
		originURL: "http://origin.local",
		limiter:   ratelimit.NoopLimiter{},
		waf:       waf.AllowEngine{},
		transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			data, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("origin read body: %v", err)
			}
			gotBody = string(data)
			return textResponse(req, http.StatusCreated, "ok")
		}),
		auditOut: io.Discard,
	})

	req := httptest.NewRequest(http.MethodPost, "http://example.local/upload", strings.NewReader(body))
	req.RemoteAddr = "198.51.100.10:12345"
	rec := httptest.NewRecorder()

	gateway.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if gotBody != body {
		t.Fatalf("origin body = %q, want %q", gotBody, body)
	}
}

func testGateway(t *testing.T, mode string, originURL string, limiter ratelimit.Limiter) *Gateway {
	return testGatewayWithOptions(t, testGatewayOptions{
		mode:      mode,
		originURL: originURL,
		limiter:   limiter,
		waf:       waf.AllowEngine{},
		auditOut:  io.Discard,
	})
}

type testGatewayOptions struct {
	mode      string
	originURL string
	limiter   ratelimit.Limiter
	waf       waf.Engine
	transport http.RoundTripper
	auditOut  io.Writer
}

func testGatewayWithOptions(t *testing.T, opts testGatewayOptions) *Gateway {
	t.Helper()
	cfg := config.Config{
		Server: config.ServerConfig{ListenAddr: ":8080"},
		WAF: config.WAFConfig{
			Enabled:               true,
			Engine:                "coraza",
			RuleEngine:            "On",
			RequestBodyLimitBytes: 1 << 20,
			BodyPreviewBytes:      256,
		},
		Apps: []config.AppConfig{{
			ID:        "app-local",
			Hostnames: []string{"example.local"},
			Origin:    config.OriginConfig{URL: opts.originURL},
			Policy: config.PolicyConfig{
				Mode:          opts.mode,
				DefaultAction: "allow",
				IPBlocklist:   []string{"203.0.113.10/32"},
				RateLimits: []config.RateLimitConfig{{
					Name:          "test-limit",
					Key:           "ip",
					Limit:         1,
					WindowSeconds: 60,
					Action:        "block",
				}},
			},
		}},
	}
	store, err := policy.NewStore(cfg.Apps)
	if err != nil {
		t.Fatalf("NewStore() error = %v", err)
	}
	var auditOutput bytes.Buffer
	auditOut := opts.auditOut
	if auditOut == nil {
		auditOut = io.Discard
	}
	gateway, err := NewGateway(Options{
		Config:      cfg,
		Policies:    store,
		RateLimiter: opts.limiter,
		Auditor:     audit.NewJSONLogger(auditOut),
		WAF:         opts.waf,
		Logger:      slog.New(slog.NewTextHandler(&auditOutput, nil)),
		Transport:   opts.transport,
	})
	if err != nil {
		t.Fatalf("NewGateway() error = %v", err)
	}
	return gateway
}

func testCorazaEngine(t *testing.T, ruleEngine string) waf.Engine {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "coraza.conf")
	directives := `
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecRule REQUEST_HEADERS:X-Bedem-Test "@streq block-me" "id:1000001,phase:1,deny,status:403,log,msg:'BedemWAF harmless test header blocked'"
`
	if err := os.WriteFile(path, []byte(directives), 0o600); err != nil {
		t.Fatalf("write coraza test config: %v", err)
	}
	engine, err := corazawaf.New(config.WAFConfig{
		Enabled:               true,
		Engine:                "coraza",
		RuleEngine:            ruleEngine,
		RequestBodyLimitBytes: 1 << 20,
		DirectivesFile:        path,
	})
	if err != nil {
		t.Fatalf("new coraza engine: %v", err)
	}
	return engine
}

type fakeLimiter struct {
	decision decision.Decision
}

func (f fakeLimiter) Check(context.Context, string, string, policy.RateLimitRule) decision.Decision {
	if f.decision.Action == "" {
		return decision.Allow()
	}
	return f.decision
}

func TestAuditJSONIncludesRequiredFields(t *testing.T) {
	var out bytes.Buffer
	logger := audit.NewJSONLogger(&out)
	logger.Log(audit.Event{
		RequestID: "req-test",
		AppID:     "app-local",
		Host:      "example.local",
		ClientIP:  "198.51.100.10",
		Method:    http.MethodGet,
		Path:      "/",
		Action:    "allow",
		Mode:      "count",
		Status:    200,
	})
	var event map[string]any
	if err := json.Unmarshal(out.Bytes(), &event); err != nil {
		t.Fatalf("audit json invalid: %v", err)
	}
	if event["request_id"] != "req-test" {
		t.Fatalf("request_id = %v, want req-test", event["request_id"])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func textResponse(req *http.Request, status int, body string) (*http.Response, error) {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}, nil
}

func decodeAuditEvent(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var event map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
		t.Fatalf("audit json invalid: %v\n%s", err, string(data))
	}
	return event
}
