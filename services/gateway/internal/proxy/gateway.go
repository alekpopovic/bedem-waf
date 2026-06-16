package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/bedemwaf/bedemwaf/services/gateway/internal/audit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/audit/redaction"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/ratelimit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/waf"
)

type Options struct {
	Config      config.Config
	Policies    *policy.Store
	Provider    policy.Provider
	RateLimiter ratelimit.Limiter
	Auditor     audit.Logger
	WAF         waf.Engine
	Logger      *slog.Logger
	Transport   http.RoundTripper
}

type Gateway struct {
	cfg            config.Config
	policies       *policy.Store
	provider       policy.Provider
	limiter        ratelimit.Limiter
	auditor        audit.Logger
	waf            waf.Engine
	logger         *slog.Logger
	transport      http.RoundTripper
	trustedProxies []netip.Prefix
}

func NewGateway(opts Options) (*Gateway, error) {
	if opts.Provider == nil {
		if opts.Policies == nil {
			return nil, errors.New("policy provider is required")
		}
		opts.Provider = opts.Policies
	}
	if opts.RateLimiter == nil {
		opts.RateLimiter = ratelimit.NoopLimiter{}
	}
	if opts.WAF == nil {
		opts.WAF = waf.AllowEngine{}
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	trusted, err := parseTrustedProxies(opts.Config.Server.TrustedProxies)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		cfg:            opts.Config,
		policies:       opts.Policies,
		provider:       opts.Provider,
		limiter:        opts.RateLimiter,
		auditor:        opts.Auditor,
		waf:            opts.WAF,
		logger:         opts.Logger,
		transport:      opts.Transport,
		trustedProxies: trusted,
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recovered := recover(); recovered != nil {
			g.logger.Error("gateway_panic_recovered", "panic", recovered)
			writeJSONError(w, http.StatusInternalServerError, "", "internal server error")
		}
	}()
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
		return
	}
	start := time.Now()
	requestID := requestID()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	clientIP := g.clientIP(r)
	host := policy.NormalizeHost(r.Host)
	if !policy.ValidHost(host) {
		writeJSONError(recorder, http.StatusBadRequest, requestID, "invalid host")
		return
	}
	event := audit.Event{
		Timestamp:     time.Now().UTC(),
		RequestID:     requestID,
		Host:          host,
		ClientIP:      clientIP.String(),
		Country:       "ZZ",
		Method:        r.Method,
		Path:          r.URL.Path,
		QueryRedacted: redaction.Query(r.URL.RawQuery),
		Action:        string(decision.ActionAllow),
		UserAgent:     r.UserAgent(),
	}
	defer func() {
		event.Status = recorder.status
		event.LatencyMS = time.Since(start).Milliseconds()
		if g.auditor != nil {
			g.auditor.Log(event)
		}
	}()

	lookup := g.provider.Lookup(r.Context(), host)
	if lookup.Warning != "" {
		event.Reason = lookup.Warning
		g.logger.Warn("policy_lookup_warning", "host", host, "reason", lookup.Warning, "request_id", requestID)
	}
	if lookup.FailOpen {
		event.Action = string(decision.ActionAllow)
		event.Reason = lookup.Reason
		return
	}
	if !lookup.Found {
		event.Action = string(decision.ActionBlock)
		event.Reason = lookup.Reason
		status := lookup.StatusCode
		if status == 0 {
			status = http.StatusNotFound
		}
		message := "no matching app"
		if status == http.StatusServiceUnavailable {
			message = "policy unavailable"
		}
		writeJSONError(recorder, status, requestID, message)
		return
	}
	app := lookup.App
	event.TenantID = app.TenantID
	event.AppID = app.ID
	event.Mode = string(app.Mode)

	bodyPreview, bodyExceeded, err := g.prepareRequestBody(r)
	if err != nil {
		event.Action = string(decision.ActionBlock)
		event.Reason = "request_body_read_failed"
		g.logger.Warn("request_body_read_failed", "error", err, "app_id", app.ID, "request_id", requestID)
		writeJSONError(recorder, http.StatusBadRequest, requestID, "invalid request body")
		return
	}
	if g.cfg.WAF.DebugBodyPreview && len(bodyPreview) > 0 {
		event.BodyPreview = redactedPreview(bodyPreview, g.cfg.WAF.BodyPreviewBytes)
	}

	final := app.EvaluateIP(clientIP)
	if final.Action == decision.ActionAllow {
		final = g.evaluateRateLimits(r.Context(), r, app, clientIP.String(), host)
	}
	if final.Action == decision.ActionAllow && bodyExceeded {
		final = decision.Block("request_body_limit_exceeded", "waf:request_body_limit")
	}
	if final.Action == decision.ActionAllow {
		customDecision := app.EvaluateCustomRules(policy.RequestContext{
			Method:   r.Method,
			Path:     r.URL.Path,
			Host:     host,
			Headers:  r.Header,
			Query:    r.URL.Query(),
			ClientIP: clientIP,
		})
		if customDecision.Action == decision.ActionBlock || customDecision.Reason == "custom_rule_allow" {
			final = customDecision
		} else if customDecision.Action == decision.ActionCount {
			final = customDecision
		}
	}
	if final.Action == decision.ActionAllow {
		wafDecision, err := g.waf.InspectRequest(r.Context(), r, bodyPreview, waf.PolicyContext{
			RequestID: requestID,
			AppID:     app.ID,
			Host:      host,
			ClientIP:  clientIP.String(),
			Mode:      app.Mode,
		})
		if err != nil {
			event.Action = string(decision.ActionBlock)
			event.Reason = "waf_error"
			g.logger.Warn("waf_inspection_failed", "error", err, "app_id", app.ID, "request_id", requestID)
			writeJSONError(recorder, http.StatusBadRequest, requestID, "waf inspection failed")
			return
		}
		if wafDecision != nil {
			final = *wafDecision
		}
	} else if final.Action == decision.ActionCount && final.Reason == "custom_rule" {
		wafDecision, err := g.waf.InspectRequest(r.Context(), r, bodyPreview, waf.PolicyContext{
			RequestID: requestID,
			AppID:     app.ID,
			Host:      host,
			ClientIP:  clientIP.String(),
			Mode:      app.Mode,
		})
		if err != nil {
			event.Action = string(decision.ActionBlock)
			event.Reason = "waf_error"
			g.logger.Warn("waf_inspection_failed", "error", err, "app_id", app.ID, "request_id", requestID)
			writeJSONError(recorder, http.StatusBadRequest, requestID, "waf inspection failed")
			return
		}
		if wafDecision != nil && wafDecision.Action != decision.ActionAllow {
			final = *wafDecision
		}
	}
	if final.Action == decision.ActionAllow && app.DefaultAction == decision.ActionBlock {
		final = decision.Block("default_action", "default_action")
	}

	enforced := decision.EnforcedAction(app.Mode, final)
	event.Action = string(final.Action)
	event.Enforced = app.Mode == decision.ModeBlock && final.WouldBlock()
	event.WouldBlock = final.WouldBlock()
	event.Reason = final.Reason
	event.MatchedRuleID = final.MatchedRuleID
	event.MatchedRuleName = final.MatchedRuleName
	event.RuleGroup = final.RuleGroup
	event.Tags = final.Tags
	event.AnomalyScore = final.AnomalyScore
	if final.RateLimit != nil {
		event.RateLimit = &audit.RateLimit{
			Limit:     final.RateLimit.Limit,
			Remaining: final.RateLimit.Remaining,
			ResetAt:   final.RateLimit.ResetAt,
			RuleID:    final.RateLimit.RuleID,
			Action:    string(final.RateLimit.Action),
		}
	}

	if enforced != decision.ActionAllow && app.Mode == decision.ModeBlock && final.WouldBlock() {
		status := final.StatusCode
		if status == 0 {
			status = http.StatusForbidden
		}
		writeJSONError(recorder, status, requestID, "request blocked")
		return
	}

	r.Header.Set("X-BedemWAF-Request-ID", requestID)
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", schemeForRequest(r))
	originStart := time.Now()
	proxy := httputil.NewSingleHostReverseProxy(app.Origin)
	if g.transport != nil {
		proxy.Transport = g.transport
	}
	proxy.ModifyResponse = func(resp *http.Response) error {
		event.OriginStatus = resp.StatusCode
		event.OriginLatencyMS = time.Since(originStart).Milliseconds()
		return nil
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		event.OriginLatencyMS = time.Since(originStart).Milliseconds()
		g.logger.Warn("origin_proxy_failed", "error", err, "app_id", app.ID, "request_id", requestID)
		writeJSONError(rw, http.StatusBadGateway, requestID, "origin unavailable")
	}
	proxy.ServeHTTP(recorder, r)
}

func (g *Gateway) prepareRequestBody(r *http.Request) ([]byte, bool, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, false, nil
	}
	limit := g.cfg.WAF.RequestBodyLimitBytes
	if limit <= 0 {
		return nil, false, nil
	}

	original := r.Body
	data, err := io.ReadAll(io.LimitReader(original, limit+1))
	if err != nil {
		return nil, false, err
	}

	exceeded := int64(len(data)) > limit
	preview := data
	if exceeded {
		preview = data[:limit]
		r.Body = &multiReadCloser{
			Reader: io.MultiReader(bytes.NewReader(data), original),
			closer: original,
		}
		return preview, true, nil
	}

	if err := original.Close(); err != nil {
		return nil, false, err
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	return preview, false, nil
}

func (g *Gateway) evaluateRateLimits(ctx context.Context, r *http.Request, app *policy.App, clientIP string, host string) decision.Decision {
	for _, rule := range app.RateLimits {
		got := g.limiter.Check(ctx, app, ratelimit.Request{
			ClientIP: clientIP,
			Method:   r.Method,
			Host:     host,
			Path:     r.URL.Path,
			Headers:  r.Header,
			Query:    r.URL.Query(),
		}, rule)
		if got.Action != decision.ActionAllow {
			return got
		}
	}
	return decision.Allow()
}

func (g *Gateway) clientIP(r *http.Request) netip.Addr {
	remoteIP := parseRemoteAddr(r.RemoteAddr)
	if len(g.trustedProxies) == 0 || !containsAddr(g.trustedProxies, remoteIP) {
		return remoteIP
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return remoteIP
	}
	first := strings.TrimSpace(strings.Split(xff, ",")[0])
	if parsed, err := netip.ParseAddr(first); err == nil {
		return parsed
	}
	return remoteIP
}

func parseRemoteAddr(value string) netip.Addr {
	host, _, err := net.SplitHostPort(value)
	if err != nil {
		host = value
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.IPv4Unspecified()
	}
	return addr
}

func parseTrustedProxies(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func writeJSONError(w http.ResponseWriter, status int, requestID string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":      message,
		"request_id": requestID,
	})
}

func requestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hex.EncodeToString([]byte(time.Now().Format(time.RFC3339Nano)))
	}
	return hex.EncodeToString(b[:])
}

func schemeForRequest(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func NewTarget(rawURL string) (*url.URL, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("target URL must include scheme and host")
	}
	return parsed, nil
}

type multiReadCloser struct {
	io.Reader
	closer io.Closer
}

func (m *multiReadCloser) Close() error {
	return m.closer.Close()
}

func redactedPreview(body []byte, maxBytes int64) string {
	if maxBytes <= 0 {
		return ""
	}
	if int64(len(body)) > maxBytes {
		body = body[:maxBytes]
	}
	return fmt.Sprintf("[redacted preview: %d bytes]", len(body))
}
