# BedemWAF

[![CI](https://github.com/alekpopovic/BedemWAF/actions/workflows/ci.yml/badge.svg)](https://github.com/alekpopovic/BedemWAF/actions/workflows/ci.yml)
[![Docker](https://github.com/alekpopovic/BedemWAF/actions/workflows/docker.yml/badge.svg)](https://github.com/alekpopovic/BedemWAF/actions/workflows/docker.yml)
[![Docs](https://github.com/alekpopovic/BedemWAF/actions/workflows/pages.yml/badge.svg)](https://github.com/alekpopovic/BedemWAF/actions/workflows/pages.yml)

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

The local Compose stack lives in `deployments/` and starts Postgres, Redis,
ClickHouse, Control API, Gateway, Worker, Dashboard, NGINX origin, and a tiny
demo application.

Local URLs:

- Dashboard: http://localhost:3000
- Gateway: http://localhost:8080
- Control API: http://localhost:8081
- Demo origin through NGINX: http://localhost:9000
- Demo app hostname through gateway: `demo.local`

Seed the demo tenant, app, policy, and published gateway policy:

```bash
./scripts/seed-demo.sh
```

Try the request paths:

```bash
# Allowed
curl -i -H 'Host: demo.local' http://localhost:8080/

# Blocked by custom rule
curl -i -H 'Host: demo.local' http://localhost:8080/admin

# Rate limited after 3 requests within 60 seconds
curl -i -H 'Host: demo.local' http://localhost:8080/login

# Echo through Gateway -> NGINX origin -> demo app
curl -i -X POST -H 'Host: demo.local' -H 'Content-Type: application/json' \
  -d '{"hello":"bedemwaf"}' http://localhost:8080/api/echo
```

Follow logs or stop the stack:

```bash
./scripts/dev-logs.sh
./scripts/dev-down.sh
```

## Local Quality Checks

CI uses the same checks that are available locally.

Run all current Go tests:

```bash
./scripts/test.sh
```

Run Go formatting and vet checks. If dashboard dependencies are installed, this
also runs the dashboard lint script:

```bash
./scripts/lint.sh
```

Run dashboard checks:

```bash
cd dashboard
npm ci
npm run typecheck
npm run lint
npm run build
```

Validate the local Docker Compose file:

```bash
cd deployments
docker compose --env-file ../.env.example config
```

## Current Implementation Status

- Monorepo structure is in place
- Documentation is specific to the intended BedemWAF model
- Go services have compiling entrypoints
- Docker Compose validates and runs the local stack from `deployments/`
- Gateway, Control API, Dashboard, event storage, and demo policy publishing are
  wired for local development

Next implementation steps:

- Add production deployment manifests
- Add proper dashboard session authentication
- Add worker retention and enrichment jobs
- Add managed CRS update workflows

## Documentation

- [Architecture](docs/architecture.md)
- [Data Plane](docs/data-plane.md)
- [Control Plane](docs/control-plane.md)
- [Request Flow](docs/request-flow.md)
- [Deployment Model](docs/deployment-model.md)
- [Threat Model](docs/threat-model.md)
- [Local Development](docs/local-development.md)
- [Policy Model](docs/policy-model.md)
- [Database Schema](docs/database-schema.md)
- [Event Schema](docs/event-schema.md)
- [OpenAPI](docs/openapi.yaml)
- [Managed Rules](docs/managed-rules.md)
- [Security Hardening](docs/security-hardening.md)
- [Production Checklist](docs/production-checklist.md)

## Docs Site

The GitHub Pages docs site is generated from `README.md` and `docs/*.md`.

```bash
python3 scripts/build-docs-site.py
```

The generated site is written to `_site/`. The GitHub Actions workflow in
`.github/workflows/pages.yml` builds and publishes the site on pushes to `main`.
