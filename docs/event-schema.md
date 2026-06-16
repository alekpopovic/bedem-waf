# Event Schema

BedemWAF audit events are structured security telemetry emitted by the gateway
after each request decision. Events are designed for defensive investigation,
analytics, and future ClickHouse storage without logging sensitive request
bodies or credential-bearing headers.

Gateway audit emission is asynchronous. Request handling enqueues an event into
a bounded dispatcher and continues; sink writes happen outside the request path.
If the queue is full, the event is dropped, `events_dropped_total` is incremented,
and a warning is logged.

## Pipeline

```text
Request decision
      |
      v
+--------------------+
| audit.Event        |
| flat JSON schema   |
+--------------------+
      |
      v
+---------------------------+
| Async bounded dispatcher  |
| non-blocking enqueue      |
+---------------------------+
      |
      +------------------> JSON stdout sink
      |
      +------------------> ClickHouse sink placeholder
```

## Event Fields

The gateway emits one JSON object per line.

| Field | Type | Description |
| --- | --- | --- |
| `timestamp` | string | UTC RFC3339 timestamp for event creation. |
| `request_id` | string | Gateway-generated request correlation ID. |
| `tenant_id` | string | Tenant that owns the matched app. |
| `app_id` | string | Matched protected app ID. |
| `policy_id` | string | Policy identifier placeholder for control-plane integration. |
| `policy_version` | string | Active immutable policy version placeholder. |
| `host` | string | Normalized request host used for app lookup. |
| `client_ip` | string | Client IP selected by gateway trusted-proxy rules. |
| `country` | string | GeoIP country placeholder. MVP uses `ZZ` when unknown. |
| `method` | string | HTTP method. |
| `path` | string | URL path without query string. |
| `query_redacted` | string | Query string after sensitive parameter redaction. |
| `user_agent` | string | User-Agent header value. |
| `action` | string | Rule decision intent: `allow`, `count`, `block`, or `rate_limit`. |
| `mode` | string | Policy mode: `count` or `block`. |
| `enforced` | boolean | True when BedemWAF actually denied the request. |
| `would_block` | boolean | True when the rule decision would deny the request in block mode. |
| `status` | number | Response status returned to the client. |
| `reason` | string | Decision reason, for example `ip_blocklist`, `custom_rule`, `waf_match`, or `rate_limit`. |
| `matched_rule_id` | string | Rule or synthetic rule ID that caused the decision. |
| `matched_rule_name` | string | Human-readable rule name when available. |
| `rule_group` | string | Rule source, such as `custom`, `coraza`, or `rate_limit`. |
| `tags` | string array | Small classification labels for filtering. |
| `anomaly_score` | number | Placeholder for CRS-style anomaly scoring. |
| `rate_limit` | object | Rate-limit result when a rate-limit rule was evaluated. |
| `latency_ms` | number | Gateway request latency in milliseconds. |
| `origin_status` | number | Upstream origin status for proxied requests. |
| `origin_latency_ms` | number | Time to receive the origin response headers or proxy error. |

## Rate Limit Object

```json
{
  "limit": 100,
  "remaining": 0,
  "reset_at": "2026-06-16T12:01:00Z",
  "rule_id": "rl-global-ip",
  "action": "block"
}
```

## Example Allow Event

```json
{
  "timestamp": "2026-06-16T12:00:00Z",
  "request_id": "8f4f2e1b1c0a4d8c9a4d6c5b2a1e0f11",
  "tenant_id": "tenant-local",
  "app_id": "app-local",
  "host": "example.local",
  "client_ip": "198.51.100.10",
  "country": "ZZ",
  "method": "GET",
  "path": "/api/items",
  "query_redacted": "page=1",
  "user_agent": "ExampleClient/1.0",
  "action": "allow",
  "mode": "count",
  "enforced": false,
  "would_block": false,
  "status": 200,
  "latency_ms": 14,
  "origin_status": 200,
  "origin_latency_ms": 8
}
```

## Example Count Event

```json
{
  "timestamp": "2026-06-16T12:02:00Z",
  "request_id": "b4b3cb73580845e5aafef4f2e732aa11",
  "tenant_id": "tenant-local",
  "app_id": "app-local",
  "host": "example.local",
  "client_ip": "203.0.113.10",
  "country": "ZZ",
  "method": "GET",
  "path": "/admin",
  "query_redacted": "token=%5BREDACTED%5D",
  "user_agent": "ExampleClient/1.0",
  "action": "block",
  "mode": "count",
  "enforced": false,
  "would_block": true,
  "status": 200,
  "reason": "custom_rule",
  "matched_rule_id": "rule-admin-office-only",
  "matched_rule_name": "Admin only from office IPs",
  "rule_group": "custom",
  "tags": ["custom_rule"],
  "latency_ms": 11,
  "origin_status": 200,
  "origin_latency_ms": 6
}
```

## Example Rate-Limit Block Event

```json
{
  "timestamp": "2026-06-16T12:03:00Z",
  "request_id": "1043f921ea9b45f7b5f1d16fd924f4d5",
  "tenant_id": "tenant-local",
  "app_id": "app-local",
  "host": "example.local",
  "client_ip": "198.51.100.25",
  "country": "ZZ",
  "method": "POST",
  "path": "/login",
  "query_redacted": "",
  "user_agent": "ExampleClient/1.0",
  "action": "rate_limit",
  "mode": "block",
  "enforced": true,
  "would_block": true,
  "status": 429,
  "reason": "rate_limit",
  "matched_rule_id": "rate_limit:rl-login",
  "matched_rule_name": "Login IP limit",
  "rule_group": "rate_limit",
  "tags": ["rate_limit"],
  "rate_limit": {
    "limit": 20,
    "remaining": 0,
    "reset_at": "2026-06-16T12:04:00Z",
    "rule_id": "rl-login",
    "action": "block"
  },
  "latency_ms": 2
}
```

## Redaction Rules

BedemWAF must not log full sensitive request bodies by default.

Headers:

- `Authorization` is never logged.
- `Cookie` is never logged.
- Header redaction helpers are centralized in the gateway audit package for
  future sinks that need header metadata.

Query parameters with these names are replaced with `[REDACTED]`:

- `password`
- `pass`
- `token`
- `access_token`
- `refresh_token`
- `secret`
- `api_key`
- `key`
- `code`

Example:

```text
before: username=demo&password=hunter2&token=abc&page=1
after:  page=1&password=%5BREDACTED%5D&token=%5BREDACTED%5D&username=demo
```

## Audit Metrics

The gateway exports Prometheus metrics for audit dispatcher backpressure and
request decisions:

- `bedem_audit_events_dropped_total`
- `bedem_requests_total`
- `bedem_blocked_requests_total`

## MVP Scope

- JSON stdout sink is implemented.
- Async bounded dispatcher is implemented.
- ClickHouse sink can write JSONEachRow audit events when configured.
- Events are emitted as one JSON object per line.
- Full request body logging is disabled by default.

## Later Phase

- ClickHouse batch writer with retry/backoff.
- Event schema version field and compatibility policy.
- Configurable sampling for high-volume count events.
- GeoIP enrichment.
- Origin ID and active policy version from the control plane.
- More detailed audit delivery success/failure metrics.
