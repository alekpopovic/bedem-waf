package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bedemwaf/bedemwaf/services/control-api/internal/auth"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/db"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/events"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/metrics"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/models"
)

const tenantIDContextKey contextKey = "tenant_id"

type Server struct {
	repo                  db.Repository
	eventStore            events.Store
	adminAuth             auth.StaticBearer
	gatewayAuth           auth.StaticBearer
	logger                *slog.Logger
	requestBodyLimitBytes int64
	corsAllowedOrigins    map[string]struct{}
}

type SecurityConfig struct {
	RequestBodyLimitBytes int64
	CORSAllowedOrigins    []string
}

func NewServer(repo db.Repository, eventStore events.Store, adminAuth auth.StaticBearer, gatewayAuth auth.StaticBearer, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	server := &Server{repo: repo, eventStore: eventStore, adminAuth: adminAuth, gatewayAuth: gatewayAuth, logger: logger, requestBodyLimitBytes: 1 << 20}
	server.ConfigureSecurity(SecurityConfig{CORSAllowedOrigins: []string{"http://localhost:3000", "http://127.0.0.1:3000"}})
	return server
}

func (s *Server) ConfigureSecurity(cfg SecurityConfig) {
	if cfg.RequestBodyLimitBytes > 0 {
		s.requestBodyLimitBytes = cfg.RequestBodyLimitBytes
	}
	if len(cfg.CORSAllowedOrigins) > 0 {
		s.corsAllowedOrigins = make(map[string]struct{}, len(cfg.CORSAllowedOrigins))
		for _, origin := range cfg.CORSAllowedOrigins {
			origin = strings.TrimSpace(origin)
			if origin != "" && origin != "*" {
				s.corsAllowedOrigins[origin] = struct{}{}
			}
		}
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	adminGlobal := func(handler http.HandlerFunc) http.Handler {
		return s.requireAuth(handler)
	}
	adminTenant := func(handler http.HandlerFunc) http.Handler {
		return s.requireAuth(s.requireTenant(handler))
	}
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.Handle("GET /metrics", metrics.Handler())
	mux.Handle("GET /v1/tenants", adminGlobal(s.listTenants))
	mux.Handle("POST /v1/tenants", adminGlobal(s.createTenant))
	mux.Handle("GET /v1/apps", adminTenant(s.listApps))
	mux.Handle("POST /v1/apps", adminTenant(s.createApp))
	mux.Handle("GET /v1/apps/{app_id}", adminTenant(s.getApp))
	mux.Handle("PATCH /v1/apps/{app_id}", adminTenant(s.patchApp))
	mux.Handle("GET /v1/apps/{app_id}/policies", adminTenant(s.listPolicies))
	mux.Handle("POST /v1/apps/{app_id}/policies", adminTenant(s.createPolicy))
	mux.Handle("GET /v1/apps/{app_id}/active-policy", adminTenant(s.getActivePolicy))
	mux.Handle("GET /v1/policies/{policy_id}", adminTenant(s.getPolicy))
	mux.Handle("PATCH /v1/policies/{policy_id}", adminTenant(s.patchPolicy))
	mux.Handle("POST /v1/policies/{policy_id}/publish", adminTenant(s.publishPolicy))
	mux.Handle("GET /v1/policies/{policy_id}/simulation-summary", adminTenant(s.getPolicySimulationSummary))
	mux.Handle("GET /v1/managed-rule-sets", adminGlobal(s.listManagedRuleSets))
	mux.Handle("GET /v1/managed-rule-sets/{id}/versions", adminGlobal(s.listManagedRuleVersions))
	mux.Handle("POST /v1/managed-rule-sets/{id}/versions/{version_id}/activate", adminGlobal(s.activateManagedRuleVersion))
	mux.Handle("GET /v1/gateway/apps/{hostname}/policy", s.requireGatewayAuth(http.HandlerFunc(s.getGatewayPolicy)))
	mux.Handle("GET /v1/events", adminTenant(s.listEvents))
	mux.Handle("GET /v1/events/{event_id}", adminTenant(s.getEvent))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "route not found")
	})
	return requestIDMiddleware(recoveryMiddleware(s.logger, loggingMiddleware(s.logger, s.corsMiddleware(secureHeaders(requestSizeLimitMiddleware(s.requestBodyLimitBytes, mux))))))
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.repo.Ping(ctx); err != nil {
		writeError(w, r, http.StatusServiceUnavailable, "not_ready", "database is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) listTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.repo.ListTenants(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenants": tenants})
}

func (s *Server) createTenant(w http.ResponseWriter, r *http.Request) {
	var req models.CreateTenantRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)
	if req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}
	if err := validateSlug("slug", req.Slug); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validateJSON(req.Metadata, "metadata"); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	tenant, err := s.repo.CreateTenant(r.Context(), req)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, tenant)
}

func (s *Server) listApps(w http.ResponseWriter, r *http.Request) {
	apps, err := s.repo.ListApps(r.Context(), tenantIDFromContext(r.Context()))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"apps": apps})
}

func (s *Server) createApp(w http.ResponseWriter, r *http.Request) {
	var req models.CreateAppRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	tenantID := tenantIDFromContext(r.Context())
	req.TenantID = strings.TrimSpace(req.TenantID)
	if req.TenantID == "" {
		req.TenantID = tenantID
	} else if req.TenantID != tenantID {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "tenant_id must match tenant context")
		return
	}
	originURL, ok := s.validateCreateApp(w, r, &req)
	if !ok {
		return
	}
	app, err := s.repo.CreateApp(r.Context(), req, originURL)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, app)
}

func (s *Server) getApp(w http.ResponseWriter, r *http.Request) {
	app, err := s.repo.GetApp(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("app_id"))
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) patchApp(w http.ResponseWriter, r *http.Request) {
	var req models.UpdateAppRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	parsedOrigin, ok := s.validatePatchApp(w, r, &req)
	if !ok {
		return
	}
	app, err := s.repo.UpdateApp(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("app_id"), req, parsedOrigin)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.repo.ListPoliciesByApp(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("app_id"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req models.CreatePolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "name is required")
		return
	}
	if req.Mode == "" {
		req.Mode = "count"
	}
	if err := validateMode(req.Mode); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := validatePolicySnapshot(req.Snapshot); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	policy, err := s.repo.CreatePolicy(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("app_id"), req)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.repo.GetPolicy(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("policy_id"))
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) patchPolicy(w http.ResponseWriter, r *http.Request) {
	var req models.UpdatePolicyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if !s.validateUpdatePolicy(w, r, &req) {
		return
	}
	policy, err := s.repo.UpdatePolicy(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("policy_id"), req)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) publishPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := r.PathValue("policy_id")
	tenantID := tenantIDFromContext(r.Context())
	policy, err := s.repo.GetPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	if err := validatePolicySnapshot(policy.Snapshot); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	published, err := s.repo.PublishPolicy(r.Context(), tenantID, policyID)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, published)
}

func (s *Server) getPolicySimulationSummary(w http.ResponseWriter, r *http.Request) {
	filters, ok := parseSimulationFilters(w, r, tenantIDFromContext(r.Context()), r.PathValue("policy_id"))
	if !ok {
		return
	}
	found, err := s.eventStore.Search(r.Context(), filters)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy_id": filters.PolicyID,
		"from":      filters.From,
		"to":        filters.To,
		"rules":     events.BuildSimulationSummary(found),
	})
}

func (s *Server) getActivePolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.repo.GetActivePolicyByApp(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("app_id"))
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func parseSimulationFilters(w http.ResponseWriter, r *http.Request, tenantID string, policyID string) (events.SearchFilters, bool) {
	policyID = strings.TrimSpace(policyID)
	if policyID == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "policy_id is required")
		return events.SearchFilters{}, false
	}
	filters := events.SearchFilters{TenantID: tenantID, PolicyID: policyID, Limit: events.MaxLimit}
	values := r.URL.Query()
	if raw := values.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "from must be RFC3339")
			return events.SearchFilters{}, false
		}
		filters.From = parsed
	}
	if raw := values.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "to must be RFC3339")
			return events.SearchFilters{}, false
		}
		filters.To = parsed
	}
	if !filters.From.IsZero() && !filters.To.IsZero() && filters.From.After(filters.To) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "from must be before to")
		return events.SearchFilters{}, false
	}
	return filters, true
}

func (s *Server) getGatewayPolicy(w http.ResponseWriter, r *http.Request) {
	hostname := strings.TrimSpace(strings.ToLower(r.PathValue("hostname")))
	if err := validateDNSName(hostname); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "hostname is invalid")
		return
	}
	policy, err := s.repo.GetGatewayPolicyByHostname(r.Context(), hostname)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) listManagedRuleSets(w http.ResponseWriter, r *http.Request) {
	sets, err := s.repo.ListManagedRuleSets(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"managed_rule_sets": sets})
}

func (s *Server) listManagedRuleVersions(w http.ResponseWriter, r *http.Request) {
	versions, err := s.repo.ListManagedRuleVersions(r.Context(), r.PathValue("id"))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"versions": versions})
}

func (s *Server) activateManagedRuleVersion(w http.ResponseWriter, r *http.Request) {
	response, err := s.repo.ActivateManagedRuleVersion(r.Context(), r.PathValue("id"), r.PathValue("version_id"))
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusAccepted, response)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	filters, ok := parseEventFilters(w, r, tenantIDFromContext(r.Context()))
	if !ok {
		return
	}
	events, err := s.eventStore.Search(r.Context(), filters)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func parseEventFilters(w http.ResponseWriter, r *http.Request, tenantID string) (events.SearchFilters, bool) {
	values := r.URL.Query()
	if queryTenant := strings.TrimSpace(values.Get("tenant_id")); queryTenant != "" && queryTenant != tenantID {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "tenant_id query parameter must match tenant context")
		return events.SearchFilters{}, false
	}
	limit := events.DefaultLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > events.MaxLimit {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "limit must be between 1 and 1000")
			return events.SearchFilters{}, false
		}
		limit = parsed
	}
	filters := events.SearchFilters{
		TenantID:      tenantID,
		AppID:         values.Get("app_id"),
		Host:          values.Get("host"),
		Action:        values.Get("action"),
		ClientIP:      values.Get("client_ip"),
		MatchedRuleID: values.Get("matched_rule_id"),
		Limit:         limit,
	}
	if raw := values.Get("from"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "from must be RFC3339")
			return events.SearchFilters{}, false
		}
		filters.From = parsed
	}
	if raw := values.Get("to"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "to must be RFC3339")
			return events.SearchFilters{}, false
		}
		filters.To = parsed
	}
	if !filters.From.IsZero() && !filters.To.IsZero() && filters.From.After(filters.To) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "from must be before to")
		return events.SearchFilters{}, false
	}
	return filters, true
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	event, err := s.eventStore.GetByRequestID(r.Context(), tenantIDFromContext(r.Context()), r.PathValue("event_id"))
	if err != nil {
		if errors.Is(err, events.ErrNotFound) {
			writeError(w, r, http.StatusNotFound, "not_found", "event not found")
			return
		}
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, event)
}

func (s *Server) validateCreateApp(w http.ResponseWriter, r *http.Request, req *models.CreateAppRequest) (*url.URL, bool) {
	req.TenantID = strings.TrimSpace(req.TenantID)
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(req.Slug)
	if req.TenantID == "" || req.Name == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "tenant_id and name are required")
		return nil, false
	}
	if err := validateSlug("slug", req.Slug); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, false
	}
	if err := validateHostnames(req.Hostnames); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, false
	}
	originURL, err := parseOriginURL(req.OriginURL)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, false
	}
	if err := validateJSON(req.Metadata, "metadata"); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, false
	}
	return originURL, true
}

func (s *Server) validatePatchApp(w http.ResponseWriter, r *http.Request, req *models.UpdateAppRequest) (*url.URL, bool) {
	if req.Name != nil {
		*req.Name = strings.TrimSpace(*req.Name)
		if *req.Name == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "name cannot be empty")
			return nil, false
		}
	}
	if len(req.Hostnames) > 0 {
		if err := validateHostnames(req.Hostnames); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
			return nil, false
		}
	}
	if req.Status != nil && *req.Status != "active" && *req.Status != "disabled" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "status must be active or disabled")
		return nil, false
	}
	var originURL *url.URL
	if req.OriginURL != nil {
		parsed, err := parseOriginURL(*req.OriginURL)
		if err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
			return nil, false
		}
		originURL = parsed
	}
	if err := validateJSON(req.Metadata, "metadata"); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return nil, false
	}
	return originURL, true
}

func validatePolicySnapshot(snapshot json.RawMessage) error {
	if len(snapshot) == 0 {
		return nil
	}
	if err := validateJSON(snapshot, "snapshot"); err != nil {
		return err
	}
	var decoded policySnapshot
	if err := json.Unmarshal(snapshot, &decoded); err != nil {
		return err
	}
	if decoded.Mode != "" {
		if err := validateMode(decoded.Mode); err != nil {
			return err
		}
	}
	for _, cidr := range decoded.IPBlocks {
		if err := validateCIDR(cidr); err != nil {
			return err
		}
	}
	for _, cidrs := range decoded.IPSets {
		for _, cidr := range cidrs {
			if err := validateCIDR(cidr); err != nil {
				return err
			}
		}
	}
	for _, rule := range decoded.Rules {
		if action := rule["action"]; action != "" {
			if err := validateAction(action); err != nil {
				return err
			}
		}
	}
	for _, rule := range decoded.CustomRules {
		if strings.TrimSpace(rule.ID) == "" {
			return errors.New("custom rule id is required")
		}
		if strings.TrimSpace(rule.Name) == "" {
			return errors.New("custom rule name is required")
		}
		switch rule.Action {
		case "allow", "count", "block":
		default:
			return errors.New("custom rule action must be allow, count, or block")
		}
		if err := validatePolicyCondition(rule.When, decoded.IPSets); err != nil {
			return err
		}
	}
	for _, rule := range decoded.RateLimits {
		if strings.TrimSpace(rule.ID) == "" {
			return errors.New("rate limit id is required")
		}
		if strings.TrimSpace(rule.Name) == "" {
			return errors.New("rate limit name is required")
		}
		switch rule.Action {
		case "count", "block":
		default:
			return errors.New("rate limit action must be count or block")
		}
		if rule.Limit <= 0 || rule.WindowSeconds <= 0 {
			return errors.New("rate limit values must be positive")
		}
		switch rule.KeyType {
		case "ip", "host", "path", "header", "api_key_placeholder":
		default:
			return errors.New("rate limit key_type is invalid")
		}
		if rule.KeyType == "header" && strings.TrimSpace(rule.KeyHeader) == "" {
			return errors.New("rate limit key_header is required for header key_type")
		}
		if hasPolicyCondition(rule.Match) {
			if err := validatePolicyCondition(rule.Match, decoded.IPSets); err != nil {
				return err
			}
		}
	}
	return nil
}

type policySnapshot struct {
	Mode        string                        `json:"mode"`
	Rules       []map[string]string           `json:"rules"`
	IPBlocks    []string                      `json:"ip_blocklist"`
	IPSets      map[string][]string           `json:"ip_sets"`
	CustomRules []policyCustomRuleSnapshot    `json:"custom_rules"`
	RateLimits  []policyRateLimitRuleSnapshot `json:"rate_limits"`
}

type policyCustomRuleSnapshot struct {
	ID     string                  `json:"id"`
	Name   string                  `json:"name"`
	Action string                  `json:"action"`
	When   policyConditionSnapshot `json:"when"`
}

type policyRateLimitRuleSnapshot struct {
	ID            string                  `json:"id"`
	Name          string                  `json:"name"`
	Match         policyConditionSnapshot `json:"match"`
	KeyType       string                  `json:"key_type"`
	KeyHeader     string                  `json:"key_header"`
	Limit         int                     `json:"limit"`
	WindowSeconds int                     `json:"window_seconds"`
	Action        string                  `json:"action"`
}

type policyConditionSnapshot struct {
	All                []policyConditionSnapshot `json:"all"`
	Any                []policyConditionSnapshot `json:"any"`
	MethodEquals       string                    `json:"method_equals"`
	PathEquals         string                    `json:"path_equals"`
	PathStartsWith     string                    `json:"path_starts_with"`
	HostEquals         string                    `json:"host_equals"`
	HeaderContains     *policyHeaderMatch        `json:"header_contains"`
	HeaderEquals       *policyHeaderMatch        `json:"header_equals"`
	QueryParamContains *policyQueryParamMatch    `json:"query_parameter_contains"`
	ClientIPInIPSet    string                    `json:"client_ip_in_ip_set"`
	ClientIPNotInIPSet string                    `json:"client_ip_not_in_ip_set"`
}

type policyHeaderMatch struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type policyQueryParamMatch struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func validatePolicyCondition(value policyConditionSnapshot, ipSets map[string][]string) error {
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
		return fmt.Errorf("policy condition must contain exactly one operator, got %d", operators)
	}
	for _, child := range value.All {
		if err := validatePolicyCondition(child, ipSets); err != nil {
			return err
		}
	}
	for _, child := range value.Any {
		if err := validatePolicyCondition(child, ipSets); err != nil {
			return err
		}
	}
	if value.HeaderContains != nil && (strings.TrimSpace(value.HeaderContains.Name) == "" || value.HeaderContains.Value == "") {
		return errors.New("header_contains requires name and value")
	}
	if value.HeaderEquals != nil && (strings.TrimSpace(value.HeaderEquals.Name) == "" || value.HeaderEquals.Value == "") {
		return errors.New("header_equals requires name and value")
	}
	if value.QueryParamContains != nil && (strings.TrimSpace(value.QueryParamContains.Name) == "" || value.QueryParamContains.Value == "") {
		return errors.New("query_parameter_contains requires name and value")
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

func hasPolicyCondition(value policyConditionSnapshot) bool {
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

func (s *Server) validateUpdatePolicy(w http.ResponseWriter, r *http.Request, req *models.UpdatePolicyRequest) bool {
	if req.ExpectedUpdatedAt.IsZero() {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "expected_updated_at is required for optimistic locking")
		return false
	}
	if req.Name != nil {
		*req.Name = strings.TrimSpace(*req.Name)
		if *req.Name == "" {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "name cannot be empty")
			return false
		}
	}
	if req.Mode != nil {
		if err := validateMode(*req.Mode); err != nil {
			writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
			return false
		}
	}
	if err := validatePolicySnapshot(req.Snapshot); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", err.Error())
		return false
	}
	return true
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.adminAuth.Authorized(r) {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid bearer token")
			return
		}
		// TODO: add a persistent per-token/admin-IP rate limiter before production.
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerTenantID := strings.TrimSpace(r.Header.Get("X-Bedem-Tenant-ID"))
		queryTenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if headerTenantID != "" && queryTenantID != "" && headerTenantID != queryTenantID {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "tenant_id query parameter must match tenant context")
			return
		}
		tenantID := headerTenantID
		if tenantID == "" {
			// Development convenience only: production clients should use X-Bedem-Tenant-ID.
			tenantID = queryTenantID
		}
		if tenantID == "" {
			writeError(w, r, http.StatusBadRequest, "tenant_required", "tenant context is required")
			return
		}
		ctx := context.WithValue(r.Context(), tenantIDContextKey, tenantID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tenantIDFromContext(ctx context.Context) string {
	tenantID, _ := ctx.Value(tenantIDContextKey).(string)
	return tenantID
}

func (s *Server) requireGatewayAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.gatewayAuth.Authorized(r) {
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid gateway bearer token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleReadError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, db.ErrNotFound) {
		writeError(w, r, http.StatusNotFound, "not_found", "resource not found")
		return
	}
	if errors.Is(err, db.ErrConflict) {
		writeError(w, r, http.StatusConflict, "conflict", "resource was modified; refresh and retry")
		return
	}
	s.internalError(w, r, err)
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("request_failed", "error", err, "request_id", requestIDFromContext(r.Context()))
	writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error")
}
