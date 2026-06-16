package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bedemwaf/bedemwaf/services/control-api/internal/auth"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/db"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/events"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/models"
)

type Server struct {
	repo        db.Repository
	eventStore  events.Store
	adminAuth   auth.StaticBearer
	gatewayAuth auth.StaticBearer
	logger      *slog.Logger
}

func NewServer(repo db.Repository, eventStore events.Store, adminAuth auth.StaticBearer, gatewayAuth auth.StaticBearer, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{repo: repo, eventStore: eventStore, adminAuth: adminAuth, gatewayAuth: gatewayAuth, logger: logger}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.Handle("GET /v1/tenants", s.requireAuth(http.HandlerFunc(s.listTenants)))
	mux.Handle("POST /v1/tenants", s.requireAuth(http.HandlerFunc(s.createTenant)))
	mux.Handle("GET /v1/apps", s.requireAuth(http.HandlerFunc(s.listApps)))
	mux.Handle("POST /v1/apps", s.requireAuth(http.HandlerFunc(s.createApp)))
	mux.Handle("GET /v1/apps/{app_id}", s.requireAuth(http.HandlerFunc(s.getApp)))
	mux.Handle("PATCH /v1/apps/{app_id}", s.requireAuth(http.HandlerFunc(s.patchApp)))
	mux.Handle("GET /v1/apps/{app_id}/policies", s.requireAuth(http.HandlerFunc(s.listPolicies)))
	mux.Handle("POST /v1/apps/{app_id}/policies", s.requireAuth(http.HandlerFunc(s.createPolicy)))
	mux.Handle("GET /v1/apps/{app_id}/active-policy", s.requireAuth(http.HandlerFunc(s.getActivePolicy)))
	mux.Handle("GET /v1/policies/{policy_id}", s.requireAuth(http.HandlerFunc(s.getPolicy)))
	mux.Handle("PATCH /v1/policies/{policy_id}", s.requireAuth(http.HandlerFunc(s.patchPolicy)))
	mux.Handle("POST /v1/policies/{policy_id}/publish", s.requireAuth(http.HandlerFunc(s.publishPolicy)))
	mux.Handle("GET /v1/gateway/apps/{hostname}/policy", s.requireGatewayAuth(http.HandlerFunc(s.getGatewayPolicy)))
	mux.Handle("GET /v1/events", s.requireAuth(http.HandlerFunc(s.listEvents)))
	mux.Handle("GET /v1/events/{event_id}", s.requireAuth(http.HandlerFunc(s.getEvent)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found", "route not found")
	})
	return requestIDMiddleware(loggingMiddleware(s.logger, devCORSMiddleware(secureHeaders(mux))))
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
	apps, err := s.repo.ListApps(r.Context())
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
	app, err := s.repo.GetApp(r.Context(), r.PathValue("app_id"))
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
	app, err := s.repo.UpdateApp(r.Context(), r.PathValue("app_id"), req, parsedOrigin)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, app)
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := s.repo.ListPoliciesByApp(r.Context(), r.PathValue("app_id"))
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
	policy, err := s.repo.CreatePolicy(r.Context(), r.PathValue("app_id"), req)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, policy)
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.repo.GetPolicy(r.Context(), r.PathValue("policy_id"))
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
	policy, err := s.repo.UpdatePolicy(r.Context(), r.PathValue("policy_id"), req)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) publishPolicy(w http.ResponseWriter, r *http.Request) {
	policyID := r.PathValue("policy_id")
	policy, err := s.repo.GetPolicy(r.Context(), policyID)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	if err := validatePolicySnapshot(policy.Snapshot); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	published, err := s.repo.PublishPolicy(r.Context(), policyID)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, published)
}

func (s *Server) getActivePolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := s.repo.GetActivePolicyByApp(r.Context(), r.PathValue("app_id"))
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) getGatewayPolicy(w http.ResponseWriter, r *http.Request) {
	hostname := strings.TrimSpace(strings.ToLower(r.PathValue("hostname")))
	if hostname == "" {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "hostname is required")
		return
	}
	policy, err := s.repo.GetGatewayPolicyByHostname(r.Context(), hostname)
	if err != nil {
		s.handleReadError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	filters, ok := parseEventFilters(w, r)
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

func parseEventFilters(w http.ResponseWriter, r *http.Request) (events.SearchFilters, bool) {
	values := r.URL.Query()
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
		TenantID:      values.Get("tenant_id"),
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
	event, err := s.eventStore.GetByRequestID(r.Context(), r.PathValue("event_id"))
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
	var decoded struct {
		Mode        string              `json:"mode"`
		Rules       []map[string]string `json:"rules"`
		IPBlocks    []string            `json:"ip_blocklist"`
		IPSets      map[string][]string `json:"ip_sets"`
		CustomRules []struct {
			Action string `json:"action"`
		} `json:"custom_rules"`
		RateLimits []struct {
			Action        string `json:"action"`
			Limit         int    `json:"limit"`
			WindowSeconds int    `json:"window_seconds"`
		} `json:"rate_limits"`
	}
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
		if rule.Action != "" {
			if err := validateAction(rule.Action); err != nil {
				return err
			}
		}
	}
	for _, rule := range decoded.RateLimits {
		if rule.Action != "" {
			if err := validateAction(rule.Action); err != nil {
				return err
			}
		}
		if rule.Limit <= 0 || rule.WindowSeconds <= 0 {
			return errors.New("rate limit values must be positive")
		}
	}
	return nil
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
		next.ServeHTTP(w, r)
	})
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
