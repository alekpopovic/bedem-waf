# Architecture

BedemWAF is a self-hosted managed WAF platform for HTTP applications that are
served behind NGINX origins.

```text
Internet
   |
   v
BedemWAF Gateway
   |
   v
NGINX Origin
   |
   v
Application
```

## Design Goals

- Provide a managed WAF experience without requiring a hosted edge provider
- Keep the enforcement path small, observable, and safe by default
- Support count mode before block mode for lower-risk policy rollout
- Avoid storing full sensitive request bodies by default
- Keep data plane services isolated from control plane services
- Make local development reproducible with Docker Compose

## Component Responsibilities

### Gateway

Language: Go

Responsibilities:

- Accept inbound HTTP traffic
- Resolve the target origin from app and routing configuration
- Proxy traffic to NGINX origins
- Inspect requests and responses where configured
- Use Coraza with OWASP CRS-compatible rules
- Enforce policy decisions in count or block mode
- Apply rate limiting using Redis-backed counters
- Emit structured audit events asynchronously

Security notes:

- Request body handling must use explicit size limits
- Sensitive headers and fields must be redacted before event storage
- Policy failures should default to safe, observable behavior
- Origin lock-down documentation must describe how to restrict origin ingress to
  BedemWAF gateway addresses

TODO:

- Define gateway configuration format
- Add Coraza integration spike
- Define audit event schema
- Define rate-limit key strategy

### Control API

Language: Go

Responsibilities:

- Expose REST APIs for management operations
- Store tenant, app, origin, policy, rule group, IP set, rate limit, and user
  configuration in Postgres
- Expose event query APIs backed by ClickHouse
- Provide OpenAPI documentation
- Validate all user input
- Return production-ready error responses

TODO:

- Choose Go HTTP router and validation libraries
- Define initial REST resource model
- Add database migration tooling
- Add OpenAPI generation workflow

### Dashboard

Language: TypeScript

Framework: Next.js

Responsibilities:

- Manage apps, origins, policies, rule groups, IP sets, and rate limits
- Display WAF events and analytics
- Support safe policy rollout workflows
- Use secure browser headers and avoid leaking secrets to the client

TODO:

- Scaffold Next.js application
- Define API client generation strategy from OpenAPI
- Add authentication and session model
- Add dashboard information architecture

### Worker

Language: Go

Responsibilities:

- Process asynchronous jobs
- Enrich audit events
- Run rule update jobs
- Run retention cleanup
- Support future scheduled maintenance work

TODO:

- Choose job queue approach
- Define rule update source and verification process
- Define retention policies for Postgres and ClickHouse data

## Data Stores

### Postgres

Source of truth for control-plane configuration:

- Tenants
- Users and access control
- Applications
- Origins
- Policies
- Rule groups
- IP sets
- Rate-limit definitions

### Redis

Low-latency operational state:

- Rate-limit counters
- Short-lived coordination locks
- Async queue metadata if selected by future worker design

### ClickHouse

High-volume analytics and event storage:

- WAF audit events
- Policy match events
- Rate-limit events
- Aggregated analytics

## Audit Events

Audit events should be structured, redacted, and safe to store by default.

Minimum fields to consider:

- Tenant ID
- App ID
- Request ID
- Timestamp
- Source IP
- HTTP method
- Host
- Path
- Matched policy and rule identifiers
- Action: `count`, `block`, or `allow`
- Response status
- Redaction metadata

TODO:

- Define final event schema
- Define redaction rules
- Define body sampling policy, disabled by default

## Control Flow

1. An operator configures tenants, apps, origins, and policies through the
   dashboard or control API.
2. The control API stores configuration in Postgres.
3. The gateway loads or receives configuration snapshots.
4. Incoming traffic reaches the gateway.
5. The gateway applies WAF inspection, IP logic, and rate limits.
6. In count mode, matches are logged but requests continue.
7. In block mode, matching requests receive a defensive block response.
8. The gateway forwards allowed requests to the NGINX origin.
9. Audit events are emitted asynchronously for enrichment and analytics.

## Non-Goals

- L3/L4 DDoS mitigation
- CDN caching or global edge routing
- Offensive scanning
- Exploit tooling
- Default storage of full sensitive request bodies

## Future Work

- Prometheus metrics
- Grafana dashboards
- mTLS or signed configuration distribution
- Multi-gateway deployment examples
- Kubernetes manifests or Helm charts
- Origin lock-down examples for common cloud environments
