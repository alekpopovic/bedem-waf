package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bedemwaf/bedemwaf/services/control-api/internal/auth"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/db"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/events"
	"github.com/bedemwaf/bedemwaf/services/control-api/internal/models"
)

func TestHealthDoesNotRequireAuth(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestV1RequiresBearerToken(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertErrorShape(t, rec.Body.Bytes(), "unauthorized")
}

func TestV1RejectsInvalidBearerToken(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/tenants", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertErrorShape(t, rec.Body.Bytes(), "unauthorized")
}

func TestGatewayRoutesRejectAdminToken(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/gateway/apps/example.local/policy", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	assertErrorShape(t, rec.Body.Bytes(), "unauthorized")
}

func TestCORSAllowsConfiguredOriginsOnly(t *testing.T) {
	server := testServer(t)
	server.ConfigureSecurity(SecurityConfig{CORSAllowedOrigins: []string{"https://dashboard.example.local", "*"}})
	handler := server.Routes()

	allowedReq := httptest.NewRequest(http.MethodOptions, "/v1/tenants", nil)
	allowedReq.Header.Set("Origin", "https://dashboard.example.local")
	allowedRec := httptest.NewRecorder()
	handler.ServeHTTP(allowedRec, allowedReq)

	if got := allowedRec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.example.local" {
		t.Fatalf("allowed origin header = %q, want configured origin", got)
	}

	blockedReq := httptest.NewRequest(http.MethodOptions, "/v1/tenants", nil)
	blockedReq.Header.Set("Origin", "https://evil.example")
	blockedRec := httptest.NewRecorder()
	handler.ServeHTTP(blockedRec, blockedReq)

	if got := blockedRec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("blocked origin header = %q, want empty", got)
	}
}

func TestRequestBodyLimitReturnsJSONError(t *testing.T) {
	server := testServer(t)
	server.ConfigureSecurity(SecurityConfig{RequestBodyLimitBytes: 16})
	handler := server.Routes()
	req := authedRequest(http.MethodPost, "/v1/tenants", bytes.NewBufferString(`{"name":"Demo Tenant","slug":"body-too-large"}`))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertErrorShape(t, rec.Body.Bytes(), "invalid_json")
}

func TestCreateTenant(t *testing.T) {
	handler := testServer(t).Routes()
	body := bytes.NewBufferString(`{"name":"Demo Tenant","slug":"demo"}`)
	req := authedRequest(http.MethodPost, "/v1/tenants", body)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var got models.Tenant
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.Slug != "demo" || got.ID == "" {
		t.Fatalf("tenant = %+v, want created tenant", got)
	}
}

func TestCreateAppValidatesHostnameAndOrigin(t *testing.T) {
	handler := testServer(t).Routes()
	body := bytes.NewBufferString(`{
		"tenant_id":"tenant-1",
		"name":"Bad App",
		"slug":"bad-app",
		"hostnames":["https://example.local/path"],
		"origin_url":"ftp://origin.local"
	}`)
	req := authedRequest(http.MethodPost, "/v1/apps", body)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertErrorShape(t, rec.Body.Bytes(), "invalid_request")
}

func TestCreatePolicyValidatesModeActionAndCIDRInSnapshot(t *testing.T) {
	handler := testServer(t).Routes()
	body := bytes.NewBufferString(`{
		"name":"Bad Policy",
		"mode":"block",
		"snapshot":{
			"ip_blocklist":["not-cidr"],
			"rules":[{"action":"explode"}]
		}
	}`)
	req := authedRequest(http.MethodPost, "/v1/apps/app-1/policies", body)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertErrorShape(t, rec.Body.Bytes(), "invalid_request")
}

func TestReadyzUsesRepositoryPing(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestPublishFlowCreatesImmutableVersionAndActiveGatewayPolicy(t *testing.T) {
	repo := newFakeRepo()
	handler := NewServer(repo, &fakeEventStore{}, auth.NewStaticBearer("test-admin-key"), auth.NewStaticBearer("test-gateway-key"), nil).Routes()
	createBody := bytes.NewBufferString(`{
		"name":"Default Policy",
		"mode":"count",
		"snapshot":{
			"mode":"count",
			"ip_sets":{"office":["198.51.100.0/24"]},
			"custom_rules":[{"id":"rule-admin","action":"block"}],
			"rate_limits":[{"id":"rl-login","action":"block","limit":20,"window_seconds":60}],
			"waf":{"enabled":true,"engine":"coraza"}
		}
	}`)
	createReq := authedRequest(http.MethodPost, "/v1/apps/app-1/policies", createBody)
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201: %s", createRec.Code, createRec.Body.String())
	}

	publishReq := authedRequest(http.MethodPost, "/v1/policies/policy-created/publish", bytes.NewBuffer(nil))
	publishRec := httptest.NewRecorder()
	handler.ServeHTTP(publishRec, publishReq)
	if publishRec.Code != http.StatusCreated {
		t.Fatalf("publish status = %d, want 201: %s", publishRec.Code, publishRec.Body.String())
	}
	if len(repo.versions) != 1 {
		t.Fatalf("versions = %d, want 1", len(repo.versions))
	}
	firstVersionSnapshot := string(repo.versions[0].CustomRules)

	policy := repo.policies["policy-created"]
	updateBody := bytes.NewBufferString(`{
		"expected_updated_at": "` + policy.UpdatedAt.Format(time.RFC3339Nano) + `",
		"snapshot": {
			"mode":"block",
			"custom_rules":[{"id":"rule-after-publish","action":"block"}],
			"waf":{"enabled":true}
		}
	}`)
	updateReq := authedRequest(http.MethodPatch, "/v1/policies/policy-created", updateBody)
	updateRec := httptest.NewRecorder()
	handler.ServeHTTP(updateRec, updateReq)
	if updateRec.Code != http.StatusOK {
		t.Fatalf("update status = %d, want 200: %s", updateRec.Code, updateRec.Body.String())
	}
	if string(repo.versions[0].CustomRules) != firstVersionSnapshot {
		t.Fatal("published version changed after draft update; want immutable snapshot")
	}

	gatewayReq := httptest.NewRequest(http.MethodGet, "/v1/gateway/apps/example.local/policy", nil)
	gatewayReq.Header.Set("Authorization", "Bearer test-gateway-key")
	gatewayRec := httptest.NewRecorder()
	handler.ServeHTTP(gatewayRec, gatewayReq)
	if gatewayRec.Code != http.StatusOK {
		t.Fatalf("gateway status = %d, want 200: %s", gatewayRec.Code, gatewayRec.Body.String())
	}
	var gatewayPolicy models.GatewayPolicy
	if err := json.Unmarshal(gatewayRec.Body.Bytes(), &gatewayPolicy); err != nil {
		t.Fatalf("decode gateway policy: %v", err)
	}
	if gatewayPolicy.PolicyVersionID == "" || gatewayPolicy.Origin.URL == "" || string(gatewayPolicy.CustomRules) != firstVersionSnapshot {
		t.Fatalf("gateway policy = %+v, want active immutable version", gatewayPolicy)
	}
}

func TestGatewayPolicyRequiresGatewayToken(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/gateway/apps/example.local/policy", nil)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEventsAPIRequiresAuth(t *testing.T) {
	handler := testServer(t).Routes()
	req := httptest.NewRequest(http.MethodGet, "/v1/events", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestEventsAPIFiltersAndLimit(t *testing.T) {
	eventStore := &fakeEventStore{}
	handler := NewServer(newFakeRepo(), eventStore, auth.NewStaticBearer("test-admin-key"), auth.NewStaticBearer("test-gateway-key"), nil).Routes()
	req := authedRequest(http.MethodGet, "/v1/events?tenant_id=tenant-1&app_id=app-1&host=example.local&action=block&client_ip=198.51.100.10&matched_rule_id=rule-1&limit=25&from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z", bytes.NewBuffer(nil))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	got := eventStore.lastFilters
	if got.TenantID != "tenant-1" || got.AppID != "app-1" || got.Host != "example.local" || got.Action != "block" || got.ClientIP != "198.51.100.10" || got.MatchedRuleID != "rule-1" || got.Limit != 25 {
		t.Fatalf("filters = %+v, want query filters", got)
	}
}

func TestEventsAPIDateRangeValidation(t *testing.T) {
	handler := testServer(t).Routes()
	req := authedRequest(http.MethodGet, "/v1/events?from=2026-06-16T11:00:00Z&to=2026-06-16T10:00:00Z", bytes.NewBuffer(nil))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestManagedRuleSetEndpoints(t *testing.T) {
	handler := testServer(t).Routes()

	listReq := authedRequest(http.MethodGet, "/v1/managed-rule-sets", bytes.NewBuffer(nil))
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list sets status = %d, want 200: %s", listRec.Code, listRec.Body.String())
	}

	versionsReq := authedRequest(http.MethodGet, "/v1/managed-rule-sets/mrs-1/versions", bytes.NewBuffer(nil))
	versionsRec := httptest.NewRecorder()
	handler.ServeHTTP(versionsRec, versionsReq)
	if versionsRec.Code != http.StatusOK {
		t.Fatalf("list versions status = %d, want 200: %s", versionsRec.Code, versionsRec.Body.String())
	}

	activateReq := authedRequest(http.MethodPost, "/v1/managed-rule-sets/mrs-1/versions/mrv-1/activate", bytes.NewBuffer(nil))
	activateRec := httptest.NewRecorder()
	handler.ServeHTTP(activateRec, activateReq)
	if activateRec.Code != http.StatusAccepted {
		t.Fatalf("activate status = %d, want 202: %s", activateRec.Code, activateRec.Body.String())
	}
}

func testServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(newFakeRepo(), &fakeEventStore{}, auth.NewStaticBearer("test-admin-key"), auth.NewStaticBearer("test-gateway-key"), nil)
}

func authedRequest(method, path string, body *bytes.Buffer) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Authorization", "Bearer test-admin-key")
	req.Header.Set("Content-Type", "application/json")
	return req
}

func assertErrorShape(t *testing.T, data []byte, code string) {
	t.Helper()
	var got struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode error response: %v\n%s", err, string(data))
	}
	if got.Error.Code != code || got.Error.Message == "" || got.Error.RequestID == "" {
		t.Fatalf("error response = %+v, want code %q with message and request_id", got.Error, code)
	}
}

type fakeRepo struct {
	tenants  []models.Tenant
	apps     []models.App
	policies map[string]models.Policy
	versions []models.GatewayPolicy
	ruleSets []models.ManagedRuleSet
}

func newFakeRepo() *fakeRepo {
	now := time.Now().UTC()
	return &fakeRepo{
		tenants: []models.Tenant{{ID: "tenant-1", Name: "Demo", Slug: "demo", Status: "active", CreatedAt: now, UpdatedAt: now}},
		apps: []models.App{{
			ID: "app-1", TenantID: "tenant-1", Name: "Demo App", Slug: "demo-app",
			Hostnames: []string{"example.local"}, Status: "active", CreatedAt: now, UpdatedAt: now,
			Origins: []models.Origin{{Name: "primary", Scheme: "http", Host: "origin.local", Port: 9000, URL: "http://origin.local:9000"}},
		}},
		policies: make(map[string]models.Policy),
		ruleSets: []models.ManagedRuleSet{{
			ID:        "mrs-1",
			Name:      "OWASP CRS Local",
			Provider:  "owasp",
			Source:    "local",
			LocalPath: "/rules/owasp-crs",
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
}

func (f *fakeRepo) Ping(context.Context) error { return nil }
func (f *fakeRepo) Close()                     {}

func (f *fakeRepo) ListTenants(context.Context) ([]models.Tenant, error) {
	return f.tenants, nil
}

func (f *fakeRepo) CreateTenant(_ context.Context, req models.CreateTenantRequest) (models.Tenant, error) {
	now := time.Now().UTC()
	tenant := models.Tenant{ID: "tenant-created", Name: req.Name, Slug: req.Slug, Status: "active", Metadata: req.Metadata, CreatedAt: now, UpdatedAt: now}
	f.tenants = append(f.tenants, tenant)
	return tenant, nil
}

func (f *fakeRepo) ListApps(context.Context) ([]models.App, error) {
	return f.apps, nil
}

func (f *fakeRepo) CreateApp(_ context.Context, req models.CreateAppRequest, originURL *url.URL) (models.App, error) {
	now := time.Now().UTC()
	app := models.App{
		ID: "app-created", TenantID: req.TenantID, Name: req.Name, Slug: req.Slug,
		Hostnames: req.Hostnames, Status: "active", CreatedAt: now, UpdatedAt: now,
		Origins: []models.Origin{{Name: "primary", Scheme: originURL.Scheme, Host: originURL.Hostname(), URL: originURL.String()}},
	}
	f.apps = append(f.apps, app)
	return app, nil
}

func (f *fakeRepo) GetApp(_ context.Context, id string) (models.App, error) {
	for _, app := range f.apps {
		if app.ID == id {
			return app, nil
		}
	}
	return models.App{}, db.ErrNotFound
}

func (f *fakeRepo) UpdateApp(ctx context.Context, id string, req models.UpdateAppRequest, originURL *url.URL) (models.App, error) {
	app, err := f.GetApp(ctx, id)
	if err != nil {
		return models.App{}, err
	}
	if req.Name != nil {
		app.Name = *req.Name
	}
	if len(req.Hostnames) > 0 {
		app.Hostnames = req.Hostnames
	}
	if originURL != nil {
		app.Origins = []models.Origin{{Name: "primary", Scheme: originURL.Scheme, Host: originURL.Hostname(), URL: originURL.String()}}
	}
	return app, nil
}

func (f *fakeRepo) ListPoliciesByApp(context.Context, string) ([]models.Policy, error) {
	policies := make([]models.Policy, 0, len(f.policies))
	for _, policy := range f.policies {
		policies = append(policies, policy)
	}
	return policies, nil
}

func (f *fakeRepo) CreatePolicy(_ context.Context, appID string, req models.CreatePolicyRequest) (models.Policy, error) {
	now := time.Now().UTC()
	policy := models.Policy{ID: "policy-created", TenantID: "tenant-1", AppID: appID, Name: req.Name, Mode: req.Mode, Enabled: true, Snapshot: req.Snapshot, CreatedAt: now, UpdatedAt: now}
	f.policies[policy.ID] = policy
	return policy, nil
}

func (f *fakeRepo) GetPolicy(_ context.Context, id string) (models.Policy, error) {
	if policy, ok := f.policies[id]; ok {
		return policy, nil
	}
	now := time.Now().UTC()
	policy := models.Policy{ID: "policy-1", TenantID: "tenant-1", AppID: "app-1", Name: "Default", Mode: "count", Enabled: true, Snapshot: []byte(`{}`), CreatedAt: now, UpdatedAt: now}
	f.policies[policy.ID] = policy
	return policy, nil
}

func (f *fakeRepo) UpdatePolicy(_ context.Context, id string, req models.UpdatePolicyRequest) (models.Policy, error) {
	policy, ok := f.policies[id]
	if !ok {
		return models.Policy{}, db.ErrNotFound
	}
	if !policy.UpdatedAt.Equal(req.ExpectedUpdatedAt) {
		return models.Policy{}, db.ErrConflict
	}
	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Mode != nil {
		policy.Mode = *req.Mode
	}
	if req.Enabled != nil {
		policy.Enabled = *req.Enabled
	}
	if len(req.Snapshot) > 0 {
		policy.Snapshot = req.Snapshot
	}
	policy.UpdatedAt = policy.UpdatedAt.Add(time.Second)
	f.policies[id] = policy
	return policy, nil
}

func (f *fakeRepo) PublishPolicy(_ context.Context, id string) (models.PublishPolicyResponse, error) {
	policy, ok := f.policies[id]
	if !ok {
		return models.PublishPolicyResponse{}, db.ErrNotFound
	}
	compiled := fakeCompilePolicy(policy, f.apps[0].Origins[0])
	compiled.PolicyVersionID = "version-" + string(rune('1'+len(f.versions)))
	compiled.PublishedAt = time.Now().UTC()
	f.versions = append(f.versions, compiled)
	policy.ActiveVersionID = compiled.PolicyVersionID
	f.policies[id] = policy
	return models.PublishPolicyResponse{PolicyID: id, PolicyVersionID: compiled.PolicyVersionID, Version: len(f.versions), PublishedAt: compiled.PublishedAt}, nil
}

func (f *fakeRepo) GetActivePolicyByApp(_ context.Context, appID string) (models.GatewayPolicy, error) {
	for i := len(f.versions) - 1; i >= 0; i-- {
		if f.versions[i].AppID == appID {
			return f.versions[i], nil
		}
	}
	return models.GatewayPolicy{}, db.ErrNotFound
}

func (f *fakeRepo) GetGatewayPolicyByHostname(_ context.Context, hostname string) (models.GatewayPolicy, error) {
	for _, app := range f.apps {
		for _, got := range app.Hostnames {
			if got == hostname {
				return f.GetActivePolicyByApp(context.Background(), app.ID)
			}
		}
	}
	return models.GatewayPolicy{}, db.ErrNotFound
}

func (f *fakeRepo) ListManagedRuleSets(context.Context) ([]models.ManagedRuleSet, error) {
	return f.ruleSets, nil
}

func (f *fakeRepo) ListManagedRuleVersions(_ context.Context, ruleSetID string) ([]models.ManagedRuleVersion, error) {
	if ruleSetID != "mrs-1" {
		return nil, nil
	}
	return []models.ManagedRuleVersion{{
		ID:               "mrv-1",
		ManagedRuleSetID: "mrs-1",
		Version:          "4.0.0-local",
		SourceURI:        "local",
		LocalPath:        "/rules/owasp-crs",
		ChecksumSHA256:   "abc123",
		RulesetSnapshot:  []byte(`{"files":["REQUEST-901.conf"]}`),
		CreatedAt:        time.Now().UTC(),
	}}, nil
}

func (f *fakeRepo) ActivateManagedRuleVersion(_ context.Context, ruleSetID string, versionID string) (models.ActivateManagedRuleVersionResponse, error) {
	if ruleSetID != "mrs-1" || versionID != "mrv-1" {
		return models.ActivateManagedRuleVersionResponse{}, db.ErrNotFound
	}
	return models.ActivateManagedRuleVersionResponse{
		ManagedRuleSetID:     ruleSetID,
		ManagedRuleVersionID: versionID,
		Status:               "manual_policy_publish_required",
		Message:              "publish a policy to use this version",
	}, nil
}

func (f *fakeRepo) ListEvents(context.Context, int) ([]models.EventRef, error) {
	return []models.EventRef{}, nil
}

func (f *fakeRepo) GetEvent(context.Context, string) (models.EventRef, error) {
	return models.EventRef{}, db.ErrNotFound
}

func fakeCompilePolicy(policy models.Policy, origin models.Origin) models.GatewayPolicy {
	var draft struct {
		Mode        string          `json:"mode"`
		IPSets      json.RawMessage `json:"ip_sets"`
		CustomRules json.RawMessage `json:"custom_rules"`
		RateLimits  json.RawMessage `json:"rate_limits"`
		WAF         json.RawMessage `json:"waf"`
	}
	_ = json.Unmarshal(policy.Snapshot, &draft)
	mode := policy.Mode
	if draft.Mode != "" {
		mode = draft.Mode
	}
	return models.GatewayPolicy{
		TenantID:    policy.TenantID,
		AppID:       policy.AppID,
		PolicyID:    policy.ID,
		Mode:        mode,
		Origin:      origin,
		IPSets:      defaultJSON(draft.IPSets, `{}`),
		CustomRules: defaultJSON(draft.CustomRules, `[]`),
		RateLimits:  defaultJSON(draft.RateLimits, `[]`),
		WAF:         defaultJSON(draft.WAF, `{}`),
	}
}

func defaultJSON(value json.RawMessage, fallback string) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(fallback)
	}
	return value
}

type fakeEventStore struct {
	lastFilters events.SearchFilters
}

func (f *fakeEventStore) Search(_ context.Context, filters events.SearchFilters) ([]events.Event, error) {
	f.lastFilters = filters
	return []events.Event{{RequestID: "req-1", TenantID: filters.TenantID}}, nil
}

func (f *fakeEventStore) GetByRequestID(_ context.Context, requestID string) (events.Event, error) {
	if requestID == "missing" {
		return events.Event{}, events.ErrNotFound
	}
	return events.Event{RequestID: requestID}, nil
}
