package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bedemwaf/bedemwaf/services/control-api/internal/models"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Repository interface {
	Ping(context.Context) error
	ListTenants(context.Context) ([]models.Tenant, error)
	CreateTenant(context.Context, models.CreateTenantRequest) (models.Tenant, error)
	ListApps(context.Context) ([]models.App, error)
	CreateApp(context.Context, models.CreateAppRequest, *url.URL) (models.App, error)
	GetApp(context.Context, string) (models.App, error)
	UpdateApp(context.Context, string, models.UpdateAppRequest, *url.URL) (models.App, error)
	ListPoliciesByApp(context.Context, string) ([]models.Policy, error)
	CreatePolicy(context.Context, string, models.CreatePolicyRequest) (models.Policy, error)
	GetPolicy(context.Context, string) (models.Policy, error)
	UpdatePolicy(context.Context, string, models.UpdatePolicyRequest) (models.Policy, error)
	PublishPolicy(context.Context, string) (models.PublishPolicyResponse, error)
	GetActivePolicyByApp(context.Context, string) (models.GatewayPolicy, error)
	GetGatewayPolicyByHostname(context.Context, string) (models.GatewayPolicy, error)
	ListManagedRuleSets(context.Context) ([]models.ManagedRuleSet, error)
	ListManagedRuleVersions(context.Context, string) ([]models.ManagedRuleVersion, error)
	ActivateManagedRuleVersion(context.Context, string, string) (models.ActivateManagedRuleVersionResponse, error)
	ListEvents(context.Context, int) ([]models.EventRef, error)
	GetEvent(context.Context, string) (models.EventRef, error)
	Close()
}

type PostgresRepository struct {
	pool *pgxpool.Pool
}

func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func OpenPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	if databaseURL == "" {
		return nil, errors.New("database URL is required")
	}
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

func (r *PostgresRepository) Close() {
	if r.pool != nil {
		r.pool.Close()
	}
}

func (r *PostgresRepository) Ping(ctx context.Context) error {
	return r.pool.Ping(ctx)
}

func (r *PostgresRepository) ListTenants(ctx context.Context) ([]models.Tenant, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, name, slug, status, metadata, created_at, updated_at
		FROM tenants
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tenants []models.Tenant
	for rows.Next() {
		var tenant models.Tenant
		if err := rows.Scan(&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Status, &tenant.Metadata, &tenant.CreatedAt, &tenant.UpdatedAt); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

func (r *PostgresRepository) CreateTenant(ctx context.Context, req models.CreateTenantRequest) (models.Tenant, error) {
	metadata := req.Metadata
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}
	var tenant models.Tenant
	err := r.pool.QueryRow(ctx, `
		INSERT INTO tenants (name, slug, metadata)
		VALUES ($1, $2, $3)
		RETURNING id::text, name, slug, status, metadata, created_at, updated_at`,
		req.Name, req.Slug, metadata,
	).Scan(&tenant.ID, &tenant.Name, &tenant.Slug, &tenant.Status, &tenant.Metadata, &tenant.CreatedAt, &tenant.UpdatedAt)
	return tenant, err
}

func (r *PostgresRepository) ListApps(ctx context.Context) ([]models.App, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, tenant_id::text, name, slug, hostnames, status, metadata, created_at, updated_at
		FROM apps
		WHERE deleted_at IS NULL
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []models.App
	for rows.Next() {
		var app models.App
		if err := rows.Scan(&app.ID, &app.TenantID, &app.Name, &app.Slug, &app.Hostnames, &app.Status, &app.Metadata, &app.CreatedAt, &app.UpdatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}
	return apps, rows.Err()
}

func (r *PostgresRepository) CreateApp(ctx context.Context, req models.CreateAppRequest, originURL *url.URL) (models.App, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return models.App{}, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	metadata := req.Metadata
	if len(metadata) == 0 {
		metadata = []byte(`{}`)
	}
	var app models.App
	err = tx.QueryRow(ctx, `
		INSERT INTO apps (tenant_id, name, slug, hostnames, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text, tenant_id::text, name, slug, hostnames, status, metadata, created_at, updated_at`,
		req.TenantID, req.Name, req.Slug, req.Hostnames, metadata,
	).Scan(&app.ID, &app.TenantID, &app.Name, &app.Slug, &app.Hostnames, &app.Status, &app.Metadata, &app.CreatedAt, &app.UpdatedAt)
	if err != nil {
		return models.App{}, err
	}
	origin, err := insertOrigin(ctx, tx, app.TenantID, app.ID, originURL)
	if err != nil {
		return models.App{}, err
	}
	app.Origins = []models.Origin{origin}
	if err := tx.Commit(ctx); err != nil {
		return models.App{}, err
	}
	return app, nil
}

func (r *PostgresRepository) GetApp(ctx context.Context, id string) (models.App, error) {
	var app models.App
	err := r.pool.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, name, slug, hostnames, status, metadata, created_at, updated_at
		FROM apps
		WHERE id = $1 AND deleted_at IS NULL`, id,
	).Scan(&app.ID, &app.TenantID, &app.Name, &app.Slug, &app.Hostnames, &app.Status, &app.Metadata, &app.CreatedAt, &app.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.App{}, ErrNotFound
	}
	if err != nil {
		return models.App{}, err
	}
	origins, err := r.listOrigins(ctx, app.ID)
	if err != nil {
		return models.App{}, err
	}
	app.Origins = origins
	return app, nil
}

func (r *PostgresRepository) UpdateApp(ctx context.Context, id string, req models.UpdateAppRequest, originURL *url.URL) (models.App, error) {
	current, err := r.GetApp(ctx, id)
	if err != nil {
		return models.App{}, err
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if len(req.Hostnames) > 0 {
		current.Hostnames = req.Hostnames
	}
	if req.Status != nil {
		current.Status = *req.Status
	}
	metadata := current.Metadata
	if len(req.Metadata) > 0 {
		metadata = req.Metadata
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return models.App{}, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()
	err = tx.QueryRow(ctx, `
		UPDATE apps
		SET name = $2, hostnames = $3, status = $4, metadata = $5, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id::text, tenant_id::text, name, slug, hostnames, status, metadata, created_at, updated_at`,
		id, current.Name, current.Hostnames, current.Status, metadata,
	).Scan(&current.ID, &current.TenantID, &current.Name, &current.Slug, &current.Hostnames, &current.Status, &current.Metadata, &current.CreatedAt, &current.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.App{}, ErrNotFound
	}
	if err != nil {
		return models.App{}, err
	}
	if originURL != nil {
		if _, err := tx.Exec(ctx, `UPDATE origins SET deleted_at = now(), updated_at = now() WHERE app_id = $1 AND deleted_at IS NULL`, id); err != nil {
			return models.App{}, err
		}
		origin, err := insertOrigin(ctx, tx, current.TenantID, current.ID, originURL)
		if err != nil {
			return models.App{}, err
		}
		current.Origins = []models.Origin{origin}
	}
	if err := tx.Commit(ctx); err != nil {
		return models.App{}, err
	}
	if originURL == nil {
		current.Origins, err = r.listOrigins(ctx, current.ID)
		if err != nil {
			return models.App{}, err
		}
	}
	return current, nil
}

func (r *PostgresRepository) ListPoliciesByApp(ctx context.Context, appID string) ([]models.Policy, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, tenant_id::text, app_id::text, name, mode, enabled,
		       COALESCE(active_version_id::text, ''), created_at, updated_at
		FROM policies
		WHERE app_id = $1 AND deleted_at IS NULL
		ORDER BY created_at DESC`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []models.Policy
	for rows.Next() {
		var policy models.Policy
		if err := rows.Scan(&policy.ID, &policy.TenantID, &policy.AppID, &policy.Name, &policy.Mode, &policy.Enabled, &policy.ActiveVersionID, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, rows.Err()
}

func (r *PostgresRepository) CreatePolicy(ctx context.Context, appID string, req models.CreatePolicyRequest) (models.Policy, error) {
	app, err := r.GetApp(ctx, appID)
	if err != nil {
		return models.Policy{}, err
	}
	snapshot := req.Snapshot
	if len(snapshot) == 0 {
		snapshot = []byte(`{}`)
	}
	metadata, err := metadataWithSnapshot(nil, snapshot)
	if err != nil {
		return models.Policy{}, err
	}
	var policy models.Policy
	err = r.pool.QueryRow(ctx, `
		INSERT INTO policies (tenant_id, app_id, name, mode, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id::text, tenant_id::text, app_id::text, name, mode, enabled,
		          COALESCE(active_version_id::text, ''), created_at, updated_at`,
		app.TenantID, appID, req.Name, req.Mode, metadata,
	).Scan(&policy.ID, &policy.TenantID, &policy.AppID, &policy.Name, &policy.Mode, &policy.Enabled, &policy.ActiveVersionID, &policy.CreatedAt, &policy.UpdatedAt)
	policy.Snapshot = snapshot
	return policy, err
}

func (r *PostgresRepository) GetPolicy(ctx context.Context, id string) (models.Policy, error) {
	var policy models.Policy
	err := r.pool.QueryRow(ctx, `
		SELECT p.id::text, p.tenant_id::text, p.app_id::text, p.name, p.mode, p.enabled,
		       COALESCE(p.active_version_id::text, ''), COALESCE(p.metadata->'snapshot', '{}'::jsonb),
		       p.created_at, p.updated_at
		FROM policies p
		WHERE p.id = $1 AND p.deleted_at IS NULL`, id,
	).Scan(&policy.ID, &policy.TenantID, &policy.AppID, &policy.Name, &policy.Mode, &policy.Enabled, &policy.ActiveVersionID, &policy.Snapshot, &policy.CreatedAt, &policy.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Policy{}, ErrNotFound
	}
	return policy, err
}

func (r *PostgresRepository) UpdatePolicy(ctx context.Context, id string, req models.UpdatePolicyRequest) (models.Policy, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return models.Policy{}, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	current, err := getPolicyForUpdate(ctx, tx, id)
	if err != nil {
		return models.Policy{}, err
	}
	if !current.UpdatedAt.Equal(req.ExpectedUpdatedAt) {
		return models.Policy{}, ErrConflict
	}
	if req.Name != nil {
		current.Name = *req.Name
	}
	if req.Mode != nil {
		current.Mode = *req.Mode
	}
	if req.Enabled != nil {
		current.Enabled = *req.Enabled
	}
	if len(req.Snapshot) > 0 {
		current.Snapshot = req.Snapshot
	}
	metadata, err := metadataWithSnapshot(nil, current.Snapshot)
	if err != nil {
		return models.Policy{}, err
	}
	var updated models.Policy
	err = tx.QueryRow(ctx, `
		UPDATE policies
		SET name = $2, mode = $3, enabled = $4, metadata = $5, updated_at = now()
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING id::text, tenant_id::text, app_id::text, name, mode, enabled,
		          COALESCE(active_version_id::text, ''), COALESCE(metadata->'snapshot', '{}'::jsonb),
		          created_at, updated_at`,
		id, current.Name, current.Mode, current.Enabled, metadata,
	).Scan(&updated.ID, &updated.TenantID, &updated.AppID, &updated.Name, &updated.Mode, &updated.Enabled, &updated.ActiveVersionID, &updated.Snapshot, &updated.CreatedAt, &updated.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Policy{}, ErrNotFound
	}
	if err != nil {
		return models.Policy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.Policy{}, err
	}
	return updated, nil
}

func (r *PostgresRepository) PublishPolicy(ctx context.Context, id string) (models.PublishPolicyResponse, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return models.PublishPolicyResponse{}, err
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	policy, err := getPolicyForUpdate(ctx, tx, id)
	if err != nil {
		return models.PublishPolicyResponse{}, err
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE policy_id = $1`, id).Scan(&version); err != nil {
		return models.PublishPolicyResponse{}, err
	}
	var versionID string
	var publishedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text, now()`).Scan(&versionID, &publishedAt); err != nil {
		return models.PublishPolicyResponse{}, err
	}
	compiled, err := compileGatewayPolicy(ctx, tx, policy, versionID)
	if err != nil {
		return models.PublishPolicyResponse{}, err
	}
	compiled.PublishedAt = publishedAt
	snapshot, err := json.Marshal(compiled)
	if err != nil {
		return models.PublishPolicyResponse{}, err
	}
	sum := sha256.Sum256(snapshot)
	err = tx.QueryRow(ctx, `
		INSERT INTO policy_versions (id, tenant_id, app_id, policy_id, version, mode, snapshot, snapshot_sha256, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id::text, created_at`,
		versionID, policy.TenantID, policy.AppID, policy.ID, version, policy.Mode, snapshot, hex.EncodeToString(sum[:]), publishedAt,
	).Scan(&versionID, &publishedAt)
	if err != nil {
		return models.PublishPolicyResponse{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE policies SET active_version_id = $2, updated_at = now() WHERE id = $1`, policy.ID, versionID); err != nil {
		return models.PublishPolicyResponse{}, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO policy_deployments (tenant_id, app_id, policy_id, policy_version_id, gateway_node_id, status, deployed_at, last_seen_at)
		VALUES ($1, $2, $3, $4, 'default', 'active', now(), now())
		ON CONFLICT (policy_id, gateway_node_id)
		DO UPDATE SET policy_version_id = EXCLUDED.policy_version_id,
		              status = 'active',
		              deployed_at = now(),
		              updated_at = now()`,
		policy.TenantID, policy.AppID, policy.ID, versionID); err != nil {
		return models.PublishPolicyResponse{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return models.PublishPolicyResponse{}, err
	}
	return models.PublishPolicyResponse{PolicyID: policy.ID, PolicyVersionID: versionID, Version: version, PublishedAt: publishedAt}, nil
}

func (r *PostgresRepository) GetActivePolicyByApp(ctx context.Context, appID string) (models.GatewayPolicy, error) {
	var snapshot []byte
	err := r.pool.QueryRow(ctx, `
		SELECT v.snapshot
		FROM policy_deployments d
		JOIN policies p ON p.id = d.policy_id
		JOIN policy_versions v ON v.id = d.policy_version_id
		WHERE d.app_id = $1
		  AND d.gateway_node_id = 'default'
		  AND d.status = 'active'
		  AND p.deleted_at IS NULL
		  AND p.enabled = true
		ORDER BY d.deployed_at DESC
		LIMIT 1`, appID,
	).Scan(&snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.GatewayPolicy{}, ErrNotFound
	}
	if err != nil {
		return models.GatewayPolicy{}, err
	}
	return decodeGatewayPolicy(snapshot)
}

func (r *PostgresRepository) GetGatewayPolicyByHostname(ctx context.Context, hostname string) (models.GatewayPolicy, error) {
	var snapshot []byte
	err := r.pool.QueryRow(ctx, `
		SELECT v.snapshot
		FROM apps a
		JOIN policy_deployments d ON d.app_id = a.id
		JOIN policies p ON p.id = d.policy_id
		JOIN policy_versions v ON v.id = d.policy_version_id
		WHERE EXISTS (
			SELECT 1 FROM unnest(a.hostnames) AS hostname
			WHERE lower(hostname) = lower($1)
		)
		  AND d.gateway_node_id = 'default'
		  AND d.status = 'active'
		  AND a.deleted_at IS NULL
		  AND a.status = 'active'
		  AND p.deleted_at IS NULL
		  AND p.enabled = true
		ORDER BY d.deployed_at DESC
		LIMIT 1`, hostname,
	).Scan(&snapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.GatewayPolicy{}, ErrNotFound
	}
	if err != nil {
		return models.GatewayPolicy{}, err
	}
	return decodeGatewayPolicy(snapshot)
}

func (r *PostgresRepository) ListManagedRuleSets(ctx context.Context) ([]models.ManagedRuleSet, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, name, provider, source, COALESCE(description, ''),
		       COALESCE(local_path, ''), enabled, metadata, created_at, updated_at
		FROM managed_rule_sets
		WHERE deleted_at IS NULL
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sets []models.ManagedRuleSet
	for rows.Next() {
		var set models.ManagedRuleSet
		if err := rows.Scan(&set.ID, &set.Name, &set.Provider, &set.Source, &set.Description, &set.LocalPath, &set.Enabled, &set.Metadata, &set.CreatedAt, &set.UpdatedAt); err != nil {
			return nil, err
		}
		sets = append(sets, set)
	}
	return sets, rows.Err()
}

func (r *PostgresRepository) ListManagedRuleVersions(ctx context.Context, ruleSetID string) ([]models.ManagedRuleVersion, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, managed_rule_set_id::text, version, COALESCE(source_uri, ''),
		       COALESCE(local_path, ''), COALESCE(checksum_sha256, ''),
		       ruleset_snapshot, released_at, created_at
		FROM managed_rule_versions
		WHERE managed_rule_set_id = $1
		ORDER BY created_at DESC`, ruleSetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []models.ManagedRuleVersion
	for rows.Next() {
		var version models.ManagedRuleVersion
		if err := rows.Scan(&version.ID, &version.ManagedRuleSetID, &version.Version, &version.SourceURI, &version.LocalPath, &version.ChecksumSHA256, &version.RulesetSnapshot, &version.ReleasedAt, &version.CreatedAt); err != nil {
			return nil, err
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func (r *PostgresRepository) ActivateManagedRuleVersion(ctx context.Context, ruleSetID string, versionID string) (models.ActivateManagedRuleVersionResponse, error) {
	var exists bool
	if err := r.pool.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM managed_rule_versions
			WHERE id = $1 AND managed_rule_set_id = $2
		)`, versionID, ruleSetID).Scan(&exists); err != nil {
		return models.ActivateManagedRuleVersionResponse{}, err
	}
	if !exists {
		return models.ActivateManagedRuleVersionResponse{}, ErrNotFound
	}
	return models.ActivateManagedRuleVersionResponse{
		ManagedRuleSetID:     ruleSetID,
		ManagedRuleVersionID: versionID,
		Status:               "manual_policy_publish_required",
		Message:              "managed rule versions are not activated automatically; publish a policy referencing this version",
	}, nil
}

func (r *PostgresRepository) ListEvents(ctx context.Context, limit int) ([]models.EventRef, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, tenant_id::text, COALESCE(app_id::text, ''), COALESCE(policy_id::text, ''),
		       event_id, request_id, COALESCE(source_ip::text, ''), COALESCE(host, ''),
		       COALESCE(path, ''), action, occurred_at, metadata
		FROM audit_event_refs
		ORDER BY occurred_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []models.EventRef
	for rows.Next() {
		var event models.EventRef
		if err := rows.Scan(&event.ID, &event.TenantID, &event.AppID, &event.PolicyID, &event.EventID, &event.RequestID, &event.SourceIP, &event.Host, &event.Path, &event.Action, &event.OccurredAt, &event.Metadata); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

func (r *PostgresRepository) GetEvent(ctx context.Context, eventID string) (models.EventRef, error) {
	var event models.EventRef
	err := r.pool.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, COALESCE(app_id::text, ''), COALESCE(policy_id::text, ''),
		       event_id, request_id, COALESCE(source_ip::text, ''), COALESCE(host, ''),
		       COALESCE(path, ''), action, occurred_at, metadata
		FROM audit_event_refs
		WHERE event_id = $1`, eventID,
	).Scan(&event.ID, &event.TenantID, &event.AppID, &event.PolicyID, &event.EventID, &event.RequestID, &event.SourceIP, &event.Host, &event.Path, &event.Action, &event.OccurredAt, &event.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.EventRef{}, ErrNotFound
	}
	return event, err
}

func (r *PostgresRepository) listOrigins(ctx context.Context, appID string) ([]models.Origin, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id::text, name, scheme, host, port
		FROM origins
		WHERE app_id = $1 AND deleted_at IS NULL
		ORDER BY created_at`, appID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var origins []models.Origin
	for rows.Next() {
		var origin models.Origin
		if err := rows.Scan(&origin.ID, &origin.Name, &origin.Scheme, &origin.Host, &origin.Port); err != nil {
			return nil, err
		}
		origin.URL = origin.Scheme + "://" + origin.Host
		if origin.Port > 0 {
			origin.URL += ":" + strconv.Itoa(origin.Port)
		}
		origins = append(origins, origin)
	}
	return origins, rows.Err()
}

func insertOrigin(ctx context.Context, tx pgx.Tx, tenantID, appID string, originURL *url.URL) (models.Origin, error) {
	port := originURL.Port()
	if port == "" {
		if originURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil {
		return models.Origin{}, err
	}
	host := strings.ToLower(originURL.Hostname())
	var origin models.Origin
	err = tx.QueryRow(ctx, `
		INSERT INTO origins (tenant_id, app_id, name, scheme, host, port)
		VALUES ($1, $2, 'primary', $3, $4, $5)
		RETURNING id::text, name, scheme, host, port`,
		tenantID, appID, originURL.Scheme, host, portNumber,
	).Scan(&origin.ID, &origin.Name, &origin.Scheme, &origin.Host, &origin.Port)
	if err != nil {
		return models.Origin{}, err
	}
	origin.URL = origin.Scheme + "://" + origin.Host + ":" + strconv.Itoa(origin.Port)
	return origin, nil
}

func getPolicyForUpdate(ctx context.Context, tx pgx.Tx, id string) (models.Policy, error) {
	var policy models.Policy
	err := tx.QueryRow(ctx, `
		SELECT id::text, tenant_id::text, app_id::text, name, mode, enabled,
		       COALESCE(active_version_id::text, ''), COALESCE(metadata->'snapshot', '{}'::jsonb), created_at, updated_at
		FROM policies
		WHERE id = $1 AND deleted_at IS NULL
		FOR UPDATE`, id,
	).Scan(&policy.ID, &policy.TenantID, &policy.AppID, &policy.Name, &policy.Mode, &policy.Enabled, &policy.ActiveVersionID, &policy.Snapshot, &policy.CreatedAt, &policy.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Policy{}, ErrNotFound
	}
	return policy, err
}

func compileGatewayPolicy(ctx context.Context, tx pgx.Tx, policy models.Policy, versionID string) (models.GatewayPolicy, error) {
	origin, err := getPrimaryOrigin(ctx, tx, policy.AppID)
	if err != nil {
		return models.GatewayPolicy{}, err
	}
	draft, err := decodeDraft(policy.Snapshot)
	if err != nil {
		return models.GatewayPolicy{}, err
	}
	mode := policy.Mode
	if draft.Mode != "" {
		mode = draft.Mode
	}
	return models.GatewayPolicy{
		TenantID:        policy.TenantID,
		AppID:           policy.AppID,
		PolicyID:        policy.ID,
		PolicyVersionID: versionID,
		Mode:            mode,
		Origin:          origin,
		IPSets:          defaultRaw(draft.IPSets, `{}`),
		CustomRules:     defaultRaw(draft.CustomRules, `[]`),
		RateLimits:      defaultRaw(draft.RateLimits, `[]`),
		WAF:             defaultRaw(draft.WAF, `{}`),
	}, nil
}

func getPrimaryOrigin(ctx context.Context, tx pgx.Tx, appID string) (models.Origin, error) {
	var origin models.Origin
	err := tx.QueryRow(ctx, `
		SELECT id::text, name, scheme, host, port
		FROM origins
		WHERE app_id = $1 AND deleted_at IS NULL AND enabled = true
		ORDER BY name = 'primary' DESC, created_at
		LIMIT 1`, appID,
	).Scan(&origin.ID, &origin.Name, &origin.Scheme, &origin.Host, &origin.Port)
	if errors.Is(err, pgx.ErrNoRows) {
		return models.Origin{}, ErrNotFound
	}
	if err != nil {
		return models.Origin{}, err
	}
	origin.URL = origin.Scheme + "://" + origin.Host + ":" + strconv.Itoa(origin.Port)
	return origin, nil
}

type policyDraft struct {
	Mode        string          `json:"mode"`
	IPSets      json.RawMessage `json:"ip_sets"`
	CustomRules json.RawMessage `json:"custom_rules"`
	RateLimits  json.RawMessage `json:"rate_limits"`
	WAF         json.RawMessage `json:"waf"`
}

func decodeDraft(snapshot json.RawMessage) (policyDraft, error) {
	if len(snapshot) == 0 {
		return policyDraft{}, nil
	}
	var draft policyDraft
	if err := json.Unmarshal(snapshot, &draft); err != nil {
		return policyDraft{}, err
	}
	return draft, nil
}

func metadataWithSnapshot(existing json.RawMessage, snapshot json.RawMessage) ([]byte, error) {
	var metadata map[string]json.RawMessage
	if len(existing) > 0 {
		if err := json.Unmarshal(existing, &metadata); err != nil {
			return nil, err
		}
	} else {
		metadata = make(map[string]json.RawMessage)
	}
	metadata["snapshot"] = defaultRaw(snapshot, `{}`)
	return json.Marshal(metadata)
}

func decodeGatewayPolicy(snapshot []byte) (models.GatewayPolicy, error) {
	var policy models.GatewayPolicy
	if err := json.Unmarshal(snapshot, &policy); err != nil {
		return models.GatewayPolicy{}, err
	}
	return policy, nil
}

func defaultRaw(value json.RawMessage, fallback string) json.RawMessage {
	if len(value) == 0 || string(value) == "null" {
		return json.RawMessage(fallback)
	}
	return value
}
