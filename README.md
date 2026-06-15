# BedemWAF

BedemWAF is a self-hosted managed web application firewall platform designed to
sit in front of NGINX origins.

```text
Internet -> BedemWAF Gateway -> NGINX Origin -> Application
```

The goal is to provide AWS WAF-like policy management for teams that want to run
their own edge enforcement layer: OWASP CRS-compatible inspection, count/block
rollout, IP sets, rate limits, structured audit events, and dashboard visibility.

## MVP Scope

BedemWAF is defensive software. The MVP focuses on safe policy enforcement and
operational visibility.

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
├── docs/                   # Architecture and operations documentation
├── infra/                  # Local and deployment infrastructure
├── services/
│   ├── control-api/        # Go REST API and OpenAPI docs
│   ├── gateway/            # Go reverse proxy, WAF, and enforcement data plane
│   └── worker/             # Go async jobs and retention processing
├── docker-compose.yml      # Local development dependencies
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

The initial `docker-compose.yml` starts datastore dependencies only. Application
service containers will be added when each service has its first runnable entry
point.

```bash
docker compose up -d
```

TODO:

- Add Go modules for `services/gateway`, `services/control-api`, and
  `services/worker`
- Add a Next.js app under `dashboard`
- Add database migrations
- Add OpenAPI generation for the control API
- Add local seed data and example NGINX origin configuration

## Documentation

- [Architecture](docs/architecture.md)
