CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin'
        CHECK (role IN ('owner', 'admin', 'viewer')),
    password_hash TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (tenant_id, email)
);

CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (tenant_id, key_prefix),
    UNIQUE (key_hash)
);

CREATE TABLE apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    slug TEXT NOT NULL,
    hostnames TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (tenant_id, slug)
);

CREATE TABLE origins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    scheme TEXT NOT NULL DEFAULT 'http'
        CHECK (scheme IN ('http', 'https')),
    host TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    health_check_path TEXT NOT NULL DEFAULT '/healthz',
    tls_server_name TEXT,
    connect_timeout_ms INTEGER NOT NULL DEFAULT 3000 CHECK (connect_timeout_ms > 0),
    read_timeout_ms INTEGER NOT NULL DEFAULT 30000 CHECK (read_timeout_ms > 0),
    enabled BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (app_id, name)
);

CREATE TABLE managed_rule_sets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    provider TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'local'
        CHECK (source IN ('local', 'manual', 'remote_placeholder')),
    description TEXT,
    local_path TEXT,
    enabled BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

CREATE TABLE managed_rule_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    managed_rule_set_id UUID NOT NULL REFERENCES managed_rule_sets(id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    source_uri TEXT,
    local_path TEXT,
    checksum_sha256 TEXT,
    ruleset_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
    released_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (managed_rule_set_id, version)
);

CREATE TABLE policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'count'
        CHECK (mode IN ('count', 'block')),
    default_origin_id UUID REFERENCES origins(id) ON DELETE SET NULL,
    active_version_id UUID,
    enabled BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (app_id, name)
);

CREATE TABLE rule_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    managed_rule_version_id UUID REFERENCES managed_rule_versions(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    source TEXT NOT NULL
        CHECK (source IN ('custom', 'managed')),
    priority INTEGER NOT NULL DEFAULT 1000 CHECK (priority >= 0),
    enabled BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    CHECK (
        (source = 'custom' AND tenant_id IS NOT NULL AND managed_rule_version_id IS NULL)
        OR
        (source = 'managed' AND managed_rule_version_id IS NOT NULL)
    )
);

CREATE TABLE rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE RESTRICT,
    rule_group_id UUID NOT NULL REFERENCES rule_groups(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    priority INTEGER NOT NULL DEFAULT 1000 CHECK (priority >= 0),
    enabled BOOLEAN NOT NULL DEFAULT true,
    action TEXT NOT NULL DEFAULT 'count'
        CHECK (action IN ('allow', 'count', 'block', 'challenge', 'rate_limit')),
    expression JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (rule_group_id, name)
);

CREATE TABLE ip_sets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID REFERENCES apps(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    action TEXT NOT NULL DEFAULT 'count'
        CHECK (action IN ('allow', 'count', 'block', 'challenge', 'rate_limit')),
    enabled BOOLEAN NOT NULL DEFAULT true,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (tenant_id, name)
);

CREATE TABLE ip_set_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    ip_set_id UUID NOT NULL REFERENCES ip_sets(id) ON DELETE CASCADE,
    cidr CIDR NOT NULL,
    description TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (ip_set_id, cidr)
);

CREATE TABLE rate_limit_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    policy_id UUID REFERENCES policies(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 1000 CHECK (priority >= 0),
    enabled BOOLEAN NOT NULL DEFAULT true,
    key_type TEXT NOT NULL
        CHECK (key_type IN ('source_ip', 'host', 'path', 'method', 'header', 'custom')),
    limit_count INTEGER NOT NULL CHECK (limit_count > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    action TEXT NOT NULL DEFAULT 'count'
        CHECK (action IN ('allow', 'count', 'block', 'challenge', 'rate_limit')),
    match_expression JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ,
    UNIQUE (app_id, name)
);

CREATE TABLE policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    version INTEGER NOT NULL CHECK (version > 0),
    mode TEXT NOT NULL
        CHECK (mode IN ('count', 'block')),
    snapshot JSONB NOT NULL,
    snapshot_sha256 TEXT,
    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, version)
);

ALTER TABLE policies
    ADD CONSTRAINT policies_active_version_fk
    FOREIGN KEY (active_version_id) REFERENCES policy_versions(id) ON DELETE SET NULL;

CREATE TABLE policy_deployments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    policy_id UUID NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    policy_version_id UUID NOT NULL REFERENCES policy_versions(id) ON DELETE RESTRICT,
    gateway_node_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'failed', 'stale', 'retired')),
    deployed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (policy_id, gateway_node_id)
);

CREATE TABLE audit_event_refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
    app_id UUID REFERENCES apps(id) ON DELETE SET NULL,
    policy_id UUID REFERENCES policies(id) ON DELETE SET NULL,
    policy_version_id UUID REFERENCES policy_versions(id) ON DELETE SET NULL,
    event_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    source_ip INET,
    host TEXT,
    path TEXT,
    action TEXT NOT NULL
        CHECK (action IN ('allow', 'count', 'block', 'challenge', 'rate_limit')),
    occurred_at TIMESTAMPTZ NOT NULL,
    clickhouse_table TEXT NOT NULL DEFAULT 'waf_audit_events',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_id)
);

CREATE INDEX idx_users_tenant_id ON users (tenant_id);
CREATE INDEX idx_api_keys_tenant_id ON api_keys (tenant_id);
CREATE INDEX idx_apps_tenant_id ON apps (tenant_id);
CREATE INDEX idx_apps_hostnames_gin ON apps USING GIN (hostnames);
CREATE INDEX idx_origins_tenant_id ON origins (tenant_id);
CREATE INDEX idx_origins_app_id ON origins (app_id);
CREATE INDEX idx_policies_tenant_id ON policies (tenant_id);
CREATE INDEX idx_policies_app_id ON policies (app_id);
CREATE INDEX idx_policies_active_version_id ON policies (active_version_id);
CREATE INDEX idx_rule_groups_tenant_id ON rule_groups (tenant_id);
CREATE INDEX idx_rule_groups_policy_id ON rule_groups (policy_id);
CREATE INDEX idx_rules_tenant_id ON rules (tenant_id);
CREATE INDEX idx_rules_rule_group_id_priority ON rules (rule_group_id, priority);
CREATE INDEX idx_ip_sets_tenant_id ON ip_sets (tenant_id);
CREATE INDEX idx_ip_sets_app_id ON ip_sets (app_id);
CREATE INDEX idx_ip_set_entries_tenant_id ON ip_set_entries (tenant_id);
CREATE INDEX idx_ip_set_entries_ip_set_id ON ip_set_entries (ip_set_id);
CREATE INDEX idx_rate_limit_rules_tenant_id ON rate_limit_rules (tenant_id);
CREATE INDEX idx_rate_limit_rules_app_id ON rate_limit_rules (app_id);
CREATE INDEX idx_rate_limit_rules_policy_id ON rate_limit_rules (policy_id);
CREATE INDEX idx_policy_versions_tenant_id ON policy_versions (tenant_id);
CREATE INDEX idx_policy_versions_app_id ON policy_versions (app_id);
CREATE INDEX idx_policy_versions_policy_id_version ON policy_versions (policy_id, version DESC);
CREATE INDEX idx_managed_rule_versions_set_id ON managed_rule_versions (managed_rule_set_id);
CREATE INDEX idx_policy_deployments_tenant_id ON policy_deployments (tenant_id);
CREATE INDEX idx_policy_deployments_app_id ON policy_deployments (app_id);
CREATE INDEX idx_policy_deployments_policy_version_id ON policy_deployments (policy_version_id);
CREATE INDEX idx_policy_deployments_gateway_node_id ON policy_deployments (gateway_node_id);
CREATE INDEX idx_audit_event_refs_tenant_occurred ON audit_event_refs (tenant_id, occurred_at DESC);
CREATE INDEX idx_audit_event_refs_app_occurred ON audit_event_refs (app_id, occurred_at DESC);
CREATE INDEX idx_audit_event_refs_policy_version_id ON audit_event_refs (policy_version_id);
CREATE INDEX idx_audit_event_refs_request_id ON audit_event_refs (request_id);
CREATE INDEX idx_audit_event_refs_event_id ON audit_event_refs (event_id);
CREATE INDEX idx_audit_event_refs_host ON audit_event_refs (host);
