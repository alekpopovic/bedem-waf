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
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/config"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/decision"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/policy"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/ratelimit"
	"github.com/bedemwaf/bedemwaf/services/gateway/internal/waf"
)

type Options struct {
	Config      config.Config
	Policies    *policy.Store
	RateLimiter ratelimit.Limiter
	Auditor     audit.Logger
	WAF         waf.Engine
	Logger      *slog.Logger
	Transport   http.RoundTripper
}

type Gateway struct {
	cfg            config.Config
	policies       *policy.Store
	limiter        ratelimit.Limiter
	auditor        audit.Logger
	waf            waf.Engine
	logger         *slog.Logger
	transport      http.RoundTripper
	trustedProxies []netip.Prefix
}

func NewGateway(opts Options) (*Gateway, error) {
	if opts.Policies == nil {
		return nil, errors.New("policy store is required")
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
		limiter:        opts.RateLimiter,
		auditor:        opts.Auditor,
		waf:            opts.WAF,
		logger:         opts.Logger,
		transport:      opts.Transport,
		trustedProxies: trusted,
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	requestID := requestID()
	recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

	clientIP := g.clientIP(r)
	host := policy.NormalizeHost(r.Host)
	event := audit.Event{
		Timestamp: time.Now().UTC(),
		RequestID: requestID,
		Host:      host,
		ClientIP:  clientIP.String(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Action:    string(decision.ActionAllow),
		UserAgent: r.UserAgent(),
	}
	defer func() {
		event.Status = recorder.status
		event.LatencyMS = time.Since(start).Milliseconds()
		if g.auditor != nil {
			g.auditor.Log(event)
		}
	}()

	app, ok := g.policies.MatchHost(host)
	if !ok {
		event.Action = string(decision.ActionBlock)
		event.Reason = "no_matching_app"
		writeJSONError(recorder, http.StatusNotFound, requestID, "no matching app")
		return
	}
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
		final = g.evaluateRateLimits(r.Context(), app, clientIP.String())
	}
	if final.Action == decision.ActionAllow && bodyExceeded {
		final = decision.Block("request_body_limit_exceeded", "waf:request_body_limit")
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
	}
	if final.Action == decision.ActionAllow && app.DefaultAction == decision.ActionBlock {
		final = decision.Block("default_action", "default_action")
	}

	enforced := decision.EnforcedAction(app.Mode, final)
	event.Action = string(enforced)
	event.Reason = final.Reason
	event.MatchedRuleID = final.MatchedRuleID

	if app.Mode == decision.ModeBlock && final.WouldBlock() {
		writeJSONError(recorder, http.StatusForbidden, requestID, "request blocked")
		return
	}

	r.Header.Set("X-BedemWAF-Request-ID", requestID)
	r.Header.Set("X-Forwarded-Host", r.Host)
	r.Header.Set("X-Forwarded-Proto", schemeForRequest(r))
	proxy := httputil.NewSingleHostReverseProxy(app.Origin)
	if g.transport != nil {
		proxy.Transport = g.transport
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
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

func (g *Gateway) evaluateRateLimits(ctx context.Context, app *policy.App, clientIP string) decision.Decision {
	for _, rule := range app.RateLimits {
		got := g.limiter.Check(ctx, app.ID, clientIP, rule)
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
