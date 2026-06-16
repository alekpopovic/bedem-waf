# Tenant Model

BedemWAF is tenant-scoped by default. A tenant owns apps, origins, policy
drafts, published policy versions, custom rule groups, custom rules, IP sets,
rate limit rules, deployment pointers, and audit event references.

Managed rule set definitions can be global because they are reviewed platform
content. A tenant only uses a managed rule version after an admin explicitly
publishes a tenant policy that references it.

## Control API Context

The MVP uses a static admin bearer token and an explicit tenant context:

```http
Authorization: Bearer <BEDEMWAF_ADMIN_API_KEY>
X-Bedem-Tenant-ID: <tenant-id>
```

Tenant-scoped admin endpoints require `X-Bedem-Tenant-ID`. For local
development only, the Control API also accepts `?tenant_id=<tenant-id>` when the
header is not present. If both are present they must match.

Tenant context is required for:

- Apps and origins
- Policies and policy publishing
- Active policy lookup by app
- Policy simulation summaries
- Event search and event detail lookup

Tenant context is not required for:

- Health checks
- Creating/listing tenants in the MVP admin API
- Managed rule set catalog endpoints
- Gateway policy fetch by hostname

## Ownership Rules

The Control API passes tenant ID into repository methods and database queries.
Reads and writes include tenant predicates, so a cross-tenant lookup returns a
normal `404 not_found` instead of revealing that the resource exists elsewhere.

Examples:

- Tenant A listing apps only receives apps where `apps.tenant_id = tenant_a`.
- Tenant A fetching Tenant B's app ID receives `404 not_found`.
- Tenant A updating Tenant B's policy receives `404 not_found`.
- Event search always filters by the resolved tenant context.
- Event detail lookup requires both tenant context and request ID.

## Gateway Policy Lookup

Gateways use a separate gateway bearer token and fetch policy by hostname:

```http
GET /v1/gateway/apps/{hostname}/policy
Authorization: Bearer <BEDEMWAF_GATEWAY_API_KEY>
```

The lookup is host-based because the gateway only has the request Host header
at the edge. The returned policy snapshot includes `tenant_id`, `app_id`,
`policy_id`, and `policy_version_id`, and audit events emitted by the gateway
must preserve those identifiers.

## Database Expectations

Tenant-owned tables must include `tenant_id` and indexes that support
tenant-scoped queries. The initial schema includes tenant indexes for apps,
origins, policies, rule groups, rules, IP sets, IP set entries, rate limit
rules, policy versions, policy deployments, and audit event references.

Future RBAC should build on this boundary instead of replacing it:

- API keys should carry tenant and scope claims.
- Dashboard sessions should bind to tenant membership.
- Cross-tenant admin operations should require explicit platform-admin scope.
- Background workers should process one tenant scope at a time where practical.
