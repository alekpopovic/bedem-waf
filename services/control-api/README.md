# BedemWAF Control API

The Control API is the REST management plane for BedemWAF. It manages tenants,
apps, origins, policy drafts, policy publishes, and audit event references.

This is an MVP skeleton with production-oriented boundaries:

- `net/http` router and middleware
- structured JSON logging
- request IDs
- static admin bearer token authentication
- Postgres connection pool through `pgxpool`
- repository interfaces for testability
- consistent JSON error responses
- static OpenAPI spec at `../../docs/openapi.yaml`

## Configuration

Environment variables:

```bash
export BEDEMWAF_CONTROL_API_ADDR=":8081"
export BEDEMWAF_DATABASE_URL="postgres://bedemwaf:bedemwaf_dev_password@localhost:5432/bedemwaf?sslmode=disable"
export BEDEMWAF_ADMIN_API_KEY="local-dev-admin-key-change-me"
export BEDEMWAF_GATEWAY_API_KEY="local-dev-gateway-key-change-me"
```

`BEDEMWAF_ADMIN_API_KEY` protects administrative routes. `BEDEMWAF_GATEWAY_API_KEY`
protects gateway policy fetch routes. Do not commit real production tokens.

## Run

From this directory:

```bash
go run ./cmd/control-api
```

From the repository root with local infrastructure:

```bash
./scripts/dev-up.sh
BEDEMWAF_ADMIN_API_KEY="local-dev-admin-key-change-me" \
BEDEMWAF_GATEWAY_API_KEY="local-dev-gateway-key-change-me" \
BEDEMWAF_DATABASE_URL="postgres://bedemwaf:bedemwaf_dev_password@localhost:5432/bedemwaf?sslmode=disable" \
go run ./services/control-api/cmd/control-api
```

## Health

Health endpoints do not require authentication:

```bash
curl -s http://localhost:8081/healthz
curl -s http://localhost:8081/readyz
```

## Authenticated Requests

All `/v1` routes require:

```http
Authorization: Bearer <BEDEMWAF_ADMIN_API_KEY>
```

Set a shell helper:

```bash
API=http://localhost:8081
TOKEN=local-dev-admin-key-change-me
GATEWAY_TOKEN=local-dev-gateway-key-change-me
AUTH="Authorization: Bearer $TOKEN"
GATEWAY_AUTH="Authorization: Bearer $GATEWAY_TOKEN"
```

Create a tenant:

```bash
TENANT_ID=$(curl -s -X POST "$API/v1/tenants" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"name":"Demo Tenant","slug":"demo"}' | jq -r .id)
```

List tenants:

```bash
curl -s "$API/v1/tenants" -H "$AUTH"
```

Create an app and primary origin:

```bash
APP_ID=$(curl -s -X POST "$API/v1/apps" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id":"'"$TENANT_ID"'",
    "name":"Demo App",
    "slug":"demo-app",
    "hostnames":["app.example.local"],
    "origin_url":"http://localhost:9000"
  }' | jq -r .id)
```

Create a policy draft:

```bash
POLICY_ID=$(curl -s -X POST "$API/v1/apps/$APP_ID/policies" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "name":"Default policy",
    "mode":"count",
    "snapshot":{
      "mode":"count",
      "ip_sets":{"office_ips":["198.51.100.0/24"]},
      "custom_rules":[{
        "id":"rule-admin-office-only",
        "name":"Admin only from office IPs",
        "priority":100,
        "enabled":true,
        "action":"block",
        "status_code":403,
        "when":{"path_starts_with":"/admin"}
      }],
      "rate_limits":[{
        "id":"rl-login",
        "name":"Login IP limit",
        "enabled":true,
        "priority":100,
        "key_type":"ip",
        "limit":20,
        "window_seconds":60,
        "action":"block",
        "status_code":429
      }],
      "waf":{"enabled":true,"engine":"coraza","rule_engine":"DetectionOnly"}
    }
  }' | jq -r .id)
```

Update a policy draft with optimistic locking:

```bash
UPDATED_AT=$(curl -s "$API/v1/policies/$POLICY_ID" -H "$AUTH" | jq -r .updated_at)
curl -s -X PATCH "$API/v1/policies/$POLICY_ID" \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "expected_updated_at":"'"$UPDATED_AT"'",
    "mode":"block",
    "snapshot":{"mode":"block","waf":{"enabled":true,"engine":"coraza"}}
  }'
```

Publish a policy to create an immutable version and advance the active
deployment pointer:

```bash
curl -s -X POST "$API/v1/policies/$POLICY_ID/publish" -H "$AUTH"
```

Fetch the active compiled policy as an admin:

```bash
curl -s "$API/v1/apps/$APP_ID/active-policy" -H "$AUTH"
```

Fetch the gateway-ready policy by hostname using the gateway key:

```bash
curl -s "$API/v1/gateway/apps/app.example.local/policy" -H "$GATEWAY_AUTH"
```

List managed rule sets and local versions:

```bash
curl -s "$API/v1/managed-rule-sets" -H "$AUTH"
curl -s "$API/v1/managed-rule-sets/<id>/versions" -H "$AUTH"
curl -s -X POST "$API/v1/managed-rule-sets/<id>/versions/<version_id>/activate" -H "$AUTH"
```

Search event references:

```bash
curl -s "$API/v1/events?limit=50" -H "$AUTH"
curl -s "$API/v1/events/<request_id>" -H "$AUTH"
```

## Error Shape

All API errors use:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "hostnames must contain at least one hostname",
    "request_id": "..."
  }
}
```

## MVP Notes

- Authentication uses static API keys for MVP: one admin key and one separate
  gateway key.
- Policy snapshots are stored as JSON in policy metadata until publish creates an
  immutable `policy_versions` row.
- Publishing compiles gateway-ready JSON and atomically advances the active
  deployment pointer in `policy_deployments`.
- Event endpoints read `audit_event_refs`; full ClickHouse event search is later
  phase work.
- The API validates hostnames, origin URLs, modes, rule actions in policy
  snapshots, and CIDR values in policy snapshots.
