# BedemWAF Project Context

BedemWAF is a defensive WAF management platform.

Runtime architecture:

```text
Internet -> BedemWAF Gateway -> NGINX Origin -> Application
```

## Repository Shape

- `services/gateway`: Go data plane.
- `services/control-api`: Go REST API and Postgres migrations.
- `services/worker`: Go async jobs.
- `dashboard`: Next.js admin UI scaffold.
- `deployments`: Docker Compose and local infrastructure examples.
- `docs`: technical documentation and diagrams.
- `scripts`: developer commands.

## Current Implementation State

Gateway:

- Has YAML config loading.
- Matches apps by Host header.
- Evaluates CIDR IP blocklist.
- Supports count/block mode behavior.
- Has optional Redis-backed rate limiting.
- Has a placeholder WAF engine interface.
- Proxies allowed requests to configured origins.
- Emits structured JSON audit logs.

Control API:

- Has initial placeholder Go service.
- Has first Postgres migration for tenants, apps, policies, rule groups, rules,
  IP sets, rate limits, managed rule sets, deployments, and audit references.

Dashboard:

- Next.js package scaffold only.

Worker:

- Placeholder Go service only.

## Boundaries

- Do not add offensive scanning or exploit features.
- Do not log request bodies by default.
- Keep WAF integrations defensive and rule-evaluation focused.
- Prefer small, service-local changes over cross-repo rewrites.
- Keep generated output out of git unless explicitly requested.

## Preferred Implementation Style

- Go packages should stay under each service's `internal/` directory.
- New Go code should be covered by focused tests when it affects decisions,
  routing, validation, persistence, or security behavior.
- Structured logs should use `log/slog` or service-local structured encoders.
- Docs should stay practical and implementation-oriented.
