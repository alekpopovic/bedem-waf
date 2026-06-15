# Database Schema

The BedemWAF control-plane database stores durable configuration in Postgres.
High-volume WAF events belong in ClickHouse; Postgres keeps only lightweight
event references for lookup and correlation.

The initial migration is:

- `services/control-api/internal/db/migrations/000001_init.up.sql`
- `services/control-api/internal/db/migrations/000001_init.down.sql`

## Design Choices

- All primary keys are UUIDs generated with `gen_random_uuid()`.
- Tenant-owned resources carry `tenant_id`.
- Most mutable resources include `created_at`, `updated_at`, and `deleted_at`.
- Immutable records, such as policy versions, do not use `updated_at`.
- JSONB is used for snapshots, expressions, and metadata that will evolve during
  MVP development.
- Actions are constrained to `allow`, `count`, `block`, `challenge`, and
  `rate_limit`.
- Policy modes are constrained to `count` and `block`.
- CIDR values are stored with Postgres `CIDR`.

## Tables

### tenants

Top-level administrative boundary. Every customer or internal team maps to one
tenant.

Important columns:

- `id`: UUID primary key.
- `name`: Display name.
- `slug`: Stable unique identifier for URLs and operator workflows.
- `status`: `active` or `suspended`.
- `metadata`: JSONB extension point.
- `deleted_at`: Soft-delete marker.

### users

Human control-plane users scoped to a tenant.

Important columns:

- `tenant_id`: Owning tenant.
- `email`: Unique per tenant.
- `role`: `owner`, `admin`, or `viewer`.
- `password_hash`: Optional until authentication is fully implemented.

### api_keys

Automation credentials for control API access and future gateway-to-control-plane
authentication.

Important columns:

- `key_prefix`: Non-secret display prefix for lookup and support.
- `key_hash`: Hashed API key secret; plaintext keys must never be stored.
- `scopes`: Text array for permissions such as `events:read`.
- `expires_at` and `last_used_at`: Lifecycle and audit metadata.

### apps

A protected HTTP application. Apps belong to tenants and are resolved by
hostnames at the gateway.

Important columns:

- `tenant_id`: Owning tenant.
- `slug`: Unique per tenant.
- `hostnames`: Text array of hostnames handled by the app.
- `status`: `active` or `disabled`.

Indexes:

- `tenant_id` for tenant-scoped API queries.
- GIN index on `hostnames` for gateway and API hostname lookup.

### origins

The NGINX upstream target for allowed traffic.

Important columns:

- `app_id`: App this origin belongs to.
- `scheme`, `host`, `port`: Upstream connection target.
- `health_check_path`: Future health checking endpoint.
- `tls_server_name`: SNI override for HTTPS origins.
- Timeout fields for proxy transport configuration.

### managed_rule_sets

Catalog entry for managed rule families, such as OWASP CRS-compatible rules.

Important columns:

- `name`: Unique rule set name.
- `provider`: Source or maintainer.
- `description` and `metadata`: Operator-facing details.

### managed_rule_versions

Immutable version of a managed rule set.

Important columns:

- `managed_rule_set_id`: Parent rule set.
- `version`: Provider version string.
- `source_uri`: Where the rules were obtained.
- `checksum_sha256`: Integrity metadata.
- `ruleset_snapshot`: JSONB description of the bundled rules.
- `released_at`: Upstream release timestamp when known.

### policies

Mutable policy head for an app. Policies define active mode and point to
immutable versions.

Important columns:

- `app_id`: App protected by this policy.
- `mode`: `count` or `block`.
- `default_origin_id`: Origin used by default for allowed requests.
- `active_version_id`: Currently selected immutable policy version.
- `enabled`: Allows policy deactivation without deleting history.

### policy_versions

Immutable deployable policy snapshots.

Important columns:

- `policy_id`: Parent mutable policy.
- `version`: Monotonic integer version per policy.
- `mode`: Copied mode at snapshot time.
- `snapshot`: Complete JSONB policy snapshot consumed by gateways.
- `snapshot_sha256`: Optional integrity hash.
- `created_by_user_id`: User who created the version.

Implementation note: gateway deployments should reference policy versions, not
the mutable policy row alone.

### rule_groups

Groups rules for a policy. Rule groups can be custom or managed.

Important columns:

- `policy_id`: Optional policy attachment.
- `source`: `custom` or `managed`.
- `managed_rule_version_id`: Required for managed groups.
- `priority`: Evaluation order.
- `enabled`: Allows disabling a group without deletion.

Constraint behavior:

- Custom groups require `tenant_id` and must not point at a managed rule version.
- Managed groups must point at `managed_rule_versions`.

### rules

Individual rules inside rule groups.

Important columns:

- `rule_group_id`: Parent group.
- `priority`: Evaluation order inside the group.
- `enabled`: Per-rule toggle.
- `action`: `allow`, `count`, `block`, `challenge`, or `rate_limit`.
- `expression`: JSONB match expression.
- `metadata`: JSONB for severity, tags, provider IDs, and notes.

### ip_sets

Named collections of IP ranges.

Important columns:

- `tenant_id`: Owning tenant.
- `app_id`: Optional app-specific scope.
- `action`: Action applied when an entry matches.
- `enabled`: Set-level toggle.

### ip_set_entries

Individual CIDR entries within an IP set.

Important columns:

- `ip_set_id`: Parent IP set.
- `cidr`: Postgres `CIDR` value.
- `description`: Operator note for why the range exists.

Constraint behavior:

- A CIDR can only appear once per IP set.

### rate_limit_rules

Redis-backed rate limit definitions for apps and policies.

Important columns:

- `app_id`: App being protected.
- `policy_id`: Optional policy attachment.
- `key_type`: `source_ip`, `host`, `path`, `method`, `header`, or `custom`.
- `limit_count`: Maximum requests for the window.
- `window_seconds`: Window length.
- `action`: Usually `count`, `block`, or `rate_limit`.
- `match_expression`: JSONB predicate for when the rate limit applies.

### policy_deployments

Tracks which immutable policy version is active on gateway nodes.

Important columns:

- `policy_version_id`: Version deployed to a gateway node.
- `gateway_node_id`: Stable gateway instance identifier.
- `status`: `pending`, `active`, `failed`, `stale`, or `retired`.
- `deployed_at`: Deployment timestamp.
- `last_seen_at`: Last gateway heartbeat/report timestamp.

Use this table to identify stale gateways and rollout drift.

### audit_event_refs

Lightweight references to ClickHouse audit events.

Important columns:

- `event_id`: Event identifier stored in ClickHouse.
- `request_id`: Gateway request ID.
- `source_ip`, `host`, `path`: Common search dimensions.
- `action`: Final action recorded by the gateway.
- `occurred_at`: Event timestamp.
- `clickhouse_table`: Destination table name.

Indexes support tenant/time, app/time, request ID, event ID, host, and policy
version lookup.

## Index Strategy

The migration adds indexes for:

- Tenant-scoped queries via `tenant_id`.
- App-scoped queries via `app_id`.
- Hostname lookup using `apps.hostnames` GIN.
- Policy version lookup with `(policy_id, version DESC)`.
- Gateway deployment lookup by policy version and gateway node.
- Event lookup by tenant/time, app/time, request ID, event ID, host, and policy
  version.

## MVP vs Later Phase

MVP:

- Store tenants, apps, origins, policies, rules, IP sets, rate limits, API keys,
  immutable policy versions, and gateway deployment state.
- Generate gateway policy snapshots from Postgres rows.
- Store full audit event payloads in ClickHouse and references in Postgres.

Later phase:

- Add row-level security if needed.
- Add policy approval workflows.
- Add richer RBAC.
- Add normalized many-to-many policy attachments if rule groups and IP sets need
  broader reuse.
- Add automatic `updated_at` triggers.
