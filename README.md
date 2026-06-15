# BedemWAF

BedemWAF is a self-hosted managed web application firewall platform for teams
that want AWS WAF-style policy management while keeping enforcement in their own
infrastructure. It is designed to sit directly in front of NGINX origins and
make defensive traffic decisions before requests reach the application.

```text
Internet -> BedemWAF Gateway -> NGINX Origin -> Application
```

The product has two halves:

- A Go data plane gateway that reverse proxies traffic, inspects requests with
  Coraza and OWASP CRS-compatible rules, applies rate limits, and emits
  redacted audit events.
- A managed control plane made of a Go REST API, background worker, and Next.js
  dashboard for configuring tenants, applications, origins, policies, rule
  groups, IP sets, rate limits, and event analytics.

BedemWAF is defensive software only. It is not a CDN, exploit framework,
scanner, or L3/L4 DDoS protection system.

## MVP Scope

The MVP focuses on safe policy rollout, clear operations, and auditable
decisions.

Included:

- Reverse proxy gateway for HTTP traffic in front of NGINX origins
- WAF inspection with Coraza and OWASP CRS-compatible rules
- Count mode before block mode
- REST control plane for tenants, apps, origins, policies, rule groups, IP sets,
  rate limits, and events
- Asynchronous audit event delivery and enrichment
- Admin dashboard for configuration and analytics
- Local development stack with Postgres, Redis, and ClickHouse

Not included:

- L3/L4 DDoS protection
- CDN behavior
- Offensive scanning or exploit tooling
- Storage of full sensitive request bodies by default

## Repository Layout

```text
.
├── dashboard/              # Next.js admin UI
├── deployments/            # Local Docker Compose and service config examples
├── docs/                   # Architecture and operations documentation
├── services/
│   ├── control-api/        # Go REST API and OpenAPI docs
│   ├── gateway/            # Go reverse proxy, WAF, and enforcement data plane
│   └── worker/             # Go async jobs and retention processing
├── scripts/                # Local developer helper scripts
└── README.md
```

## Services

### Gateway

The gateway is the data plane. It will proxy requests to configured NGINX
origins, inspect traffic with Coraza, enforce WAF/rate-limit decisions, and emit
redacted structured audit events asynchronously.

### Control API

The control API is the management plane. It will expose REST endpoints for
tenants, apps, origins, policies, rule groups, IP sets, rate limits, and security
events. Postgres is the source of truth for configuration.

### Dashboard

The dashboard is a Next.js admin UI for managing applications, policies, rules,
events, and analytics.

### Worker

The worker runs asynchronous jobs such as rule updates, event enrichment,
retention cleanup, and future background maintenance tasks.

## Security Principles

- Defensive use only
- Safe defaults
- Count mode before block mode
- Structured audit logging with redaction
- No secrets committed to git
- Validate all user input
- Secure headers on dashboard and API surfaces
- Production-ready error handling
- Document origin lock-down so origins only trust BedemWAF gateway traffic

## Local Development

Copy the example environment file before starting local dependencies:

```bash
cp .env.example .env
./scripts/dev-up.sh
```

The local Compose stack lives in `deployments/` and currently starts Postgres,
Redis, and ClickHouse. Gateway, control API, and worker service entries are
included as placeholders and will be wired to Dockerfiles once each service has
real runtime behavior.

Run the minimal Go services directly:

```bash
go run ./services/gateway/cmd/gateway
go run ./services/control-api/cmd/control-api
go run ./services/worker/cmd/worker
```

## Current Implementation Status

- Monorepo structure is in place
- Documentation is specific to the intended BedemWAF model
- Go services have minimal compiling entrypoints
- Docker Compose validates from `deployments/`
- Business logic is intentionally left as TODOs for reviewable follow-up work

Next implementation steps:

- Add gateway configuration loading and reverse proxy skeleton
- Add Coraza integration and CRS rule loading
- Add policy decision model and unit tests
- Add control API router, validation, migrations, and OpenAPI generation
- Add database migrations
- Scaffold the Next.js dashboard
- Add event ingestion and ClickHouse schema

## Documentation

- [Architecture](docs/architecture.md)
- [Data Plane](docs/data-plane.md)
- [Control Plane](docs/control-plane.md)
- [Request Flow](docs/request-flow.md)
- [Deployment Model](docs/deployment-model.md)
- [Threat Model](docs/threat-model.md)
- [Local Development](docs/local-development.md)
- [Policy Model](docs/policy-model.md)
- [Event Schema](docs/event-schema.md)
