# Policy Model

BedemWAF models configuration as tenant-owned resources. A request is mapped to
an app by hostname, the app points to an active policy, and the policy references
origins, rule groups, custom rules, IP sets, and rate limits.

## Entity Relationship Diagram

```text
Tenant
  |
  +--> User
  +--> API Key
  +--> App
        |
        +--> Hostname
        +--> Origin
        +--> Policy
              |
              +--> Rule Group
              |     |
              |     +--> Managed Rule
              |     +--> Custom Rule
              |
              +--> IP Set
              +--> Rate Limit
```

```mermaid
erDiagram
    TENANT ||--o{ USER : owns
    TENANT ||--o{ API_KEY : owns
    TENANT ||--o{ APP : owns
    APP ||--o{ HOSTNAME : routes
    APP ||--o{ ORIGIN : forwards_to
    APP ||--o{ POLICY : protects
    POLICY ||--o{ RULE_GROUP : includes
    POLICY ||--o{ CUSTOM_RULE : includes
    POLICY ||--o{ IP_SET : includes
    POLICY ||--o{ RATE_LIMIT : includes
    RULE_GROUP ||--o{ MANAGED_RULE : contains
```

## Tenant

A tenant is the top-level administrative boundary. All mutable resources belong
to exactly one tenant.

Suggested fields:

- `id`
- `name`
- `status`: `active`, `suspended`, or `deleted`
- `created_at`
- `updated_at`

Implementation notes:

- Every control API query must include tenant scoping.
- Cross-tenant access should be impossible at the database and service layer.
- Event search must filter by tenant before applying user-provided filters.

## App

An app represents a protected HTTP property, usually one or more hostnames that
route through BedemWAF.

Suggested fields:

- `id`
- `tenant_id`
- `name`
- `hostnames`
- `default_origin_id`
- `active_policy_id`
- `created_at`
- `updated_at`

Rules:

- Hostnames must be unique across active apps unless explicit multi-tenant
  routing rules are added later.
- Unknown hosts must not proxy to a fallback origin.
- Apps should start with a default `count` mode policy.

## Origin

An origin is the upstream NGINX endpoint for allowed traffic.

Suggested fields:

- `id`
- `tenant_id`
- `app_id`
- `name`
- `scheme`: `http` or `https`
- `host`
- `port`
- `health_check_path`
- `tls_server_name`
- `connect_timeout_ms`
- `read_timeout_ms`

Implementation notes:

- MVP supports one default origin per app.
- Later phases can add weighted origins, failover, active health checks, and
  per-path routing.
- Operators should configure NGINX or network controls so only BedemWAF gateways
  can reach the origin.

## Policy

A policy is the ordered decision configuration for an app.

Suggested fields:

- `id`
- `tenant_id`
- `app_id`
- `name`
- `mode`: `count` or `block`
- `rule_group_ids`
- `custom_rule_ids`
- `ip_set_ids`
- `rate_limit_ids`
- `enabled`
- `revision`
- `created_at`
- `updated_at`

Mode behavior:

- `count`: record matching rules and intended action, then allow the request.
- `block`: enforce blocking matches unless an allow rule explicitly overrides
  them.

MVP requirements:

- New policies default to `count`.
- A policy revision should be included in gateway snapshots and audit events.
- Disabled policies should never be selected as active policies.

Later-phase requirements:

- Draft policies
- Staged rollout
- Rollback to prior revisions
- Per-rule override actions

## Rule Group

A rule group is an ordered set of managed or custom defensive rules.

Suggested fields:

- `id`
- `tenant_id`
- `name`
- `source`: `managed`, `custom`, or `imported`
- `version`
- `enabled`
- `rule_ids`

MVP:

- Support managed OWASP CRS-compatible rule groups executed by Coraza.
- Store metadata in Postgres and load rule files from trusted local paths or
  bundled images.

Later phase:

- Signed managed rule updates
- Tenant-level rule exclusions
- Per-app anomaly score thresholds

## Custom Rule

A custom rule is a simple defensive predicate controlled by the operator.

Suggested fields:

- `id`
- `tenant_id`
- `name`
- `description`
- `enabled`
- `priority`
- `match_target`: `path`, `method`, `header`, `query`, or `source_ip`
- `operator`: `equals`, `prefix`, `contains`, `regex`, or `cidr_contains`
- `value`
- `action`: `allow`, `count`, or `block`

Implementation notes:

- Regex rules must have timeouts or use a safe regex engine.
- Custom rules must not support exploit generation or active scanning behavior.
- MVP should keep custom rules simple and deterministic.

## IP Set

An IP set is a named collection of CIDR ranges.

Suggested fields:

- `id`
- `tenant_id`
- `name`
- `description`
- `cidrs`
- `action`: `allow`, `count`, or `block`
- `enabled`

Evaluation rules:

- Exact IP/CIDR membership should be evaluated before WAF inspection.
- If both allow and block sets match, MVP should prefer explicit block unless a
  policy-level override is added later.
- IP set matches must be recorded in audit events.

## Rate Limit

A rate limit defines a threshold over a window.

Suggested fields:

- `id`
- `tenant_id`
- `app_id`
- `name`
- `key`: `source_ip`, `host`, `path`, or future composite key
- `limit`
- `window_seconds`
- `action`: `count` or `block`
- `fail_mode`: `open` or `closed`
- `enabled`

MVP implementation:

- Use Redis counters with expiration equal to the configured window.
- Include tenant and app IDs in the Redis key.
- Default `fail_mode` is `open` to avoid outage during Redis incidents.
- Log rate-limit backend failures as audit or health events.

## API Key

API keys authenticate automation against the control API.

Suggested fields:

- `id`
- `tenant_id`
- `name`
- `key_hash`
- `scopes`
- `last_used_at`
- `expires_at`
- `created_at`

Implementation notes:

- Store only hashed keys.
- Show the plaintext key only once at creation.
- Scope keys to specific actions such as `events:read` or `policies:write`.

## Evaluation Order

```text
Resolve app by Host
  |
  v
Load active policy revision
  |
  v
IP sets
  |
  v
Rate limits
  |
  v
Managed WAF rule groups
  |
  v
Custom rules
  |
  v
Apply count/block mode
```

## Published Gateway Policy JSON

Control API policy drafts are mutable. Publishing validates the draft, compiles
it with the app origin, writes an immutable `policy_versions.snapshot`, and
atomically advances the active pointer in `policy_deployments`.

The gateway policy endpoint:

```text
GET /v1/gateway/apps/{hostname}/policy
Authorization: Bearer <BEDEMWAF_GATEWAY_API_KEY>
```

returns JSON shaped for gateway consumption:

```json
{
  "tenant_id": "7d6c9c9c-5d8f-4b1e-8b6c-2b7c4b6c7f01",
  "app_id": "9a6c4f2e-7c4a-4f52-93a5-3148a6f9e011",
  "policy_id": "e06edfe2-4dc6-46c8-b66d-1e2e962c2b7e",
  "policy_version_id": "b7e5c513-43cc-4c69-b6db-4f30ad23f328",
  "mode": "count",
  "origin": {
    "id": "1fd8fc48-7b4e-45cc-81ca-d8c0fd234e71",
    "name": "primary",
    "scheme": "http",
    "host": "nginx-origin",
    "port": 9000,
    "url": "http://nginx-origin:9000"
  },
  "ip_sets": {
    "office_ips": ["198.51.100.0/24"],
    "blocked_sources": ["203.0.113.10/32"]
  },
  "custom_rules": [
    {
      "id": "rule-admin-office-only",
      "name": "Admin only from office IPs",
      "priority": 100,
      "enabled": true,
      "action": "block",
      "status_code": 403,
      "when": {
        "all": [
          {"path_starts_with": "/admin"},
          {"client_ip_not_in_ip_set": "office_ips"}
        ]
      }
    }
  ],
  "rate_limits": [
    {
      "id": "rl-login-ip",
      "name": "Login IP limit",
      "enabled": true,
      "priority": 100,
      "match": {"path_starts_with": "/login"},
      "key_type": "ip",
      "limit": 20,
      "window_seconds": 60,
      "action": "block",
      "status_code": 429
    }
  ],
  "waf": {
    "enabled": true,
    "engine": "coraza",
    "rule_engine": "DetectionOnly",
    "request_body_limit_bytes": 1048576,
    "directives_file": "./rules/coraza.conf"
  },
  "published_at": "2026-06-16T12:00:00Z"
}
```

Gateway implementations should treat this response as read-only runtime
configuration and cache it with a short TTL. If the policy endpoint is
unavailable, gateways should continue using the last known good policy and emit
an audit or health warning.

## MVP vs Later Phase

MVP:

- Tenants, apps, origins, policies
- Managed rule group metadata
- Basic custom rules
- IP sets
- Redis-backed rate limits
- API keys with hashed storage

Later phase:

- Fine-grained RBAC
- Policy drafts and approvals
- Rule exclusions and overrides
- Multi-origin routing
- Signed policy snapshots
- Managed rule update channels
