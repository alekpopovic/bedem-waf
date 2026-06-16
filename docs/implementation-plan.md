# Implementation Plan

This plan breaks BedemWAF into small pull requests that are easy to review,
test, and roll back. Each PR should avoid broad rewrites and should leave the
main branch in a runnable state.

## PR 1: Repo Skeleton And Docs

Goal: Establish the monorepo layout, service boundaries, and initial technical
documentation.

Files touched: `README.md`, `docs/architecture.md`, `docs/threat-model.md`,
`docs/local-development.md`, `docs/policy-model.md`, `docs/event-schema.md`,
`services/gateway/README.md`, `services/control-api/README.md`,
`services/worker/README.md`, `dashboard/README.md`, `.gitignore`,
`.env.example`.

Acceptance criteria: Repository structure matches the planned service layout;
documentation clearly states defensive scope, non-goals, and safe defaults; no
secrets are committed.

Tests: Docs-only PR, so no runtime tests required. Run markdown/link review
manually.

Dependencies: None.

Rollback notes: Revert the skeleton commit. No data migration or runtime state
exists yet.

## PR 2: Docker Compose Local Infra

Goal: Add local development infrastructure for Postgres, Redis, ClickHouse,
NGINX origin, demo app, and service placeholders.

Files touched: `deployments/docker-compose.yml`, `deployments/postgres/init.sql`,
`deployments/clickhouse/init.sql`, `deployments/nginx-origin/nginx.conf`,
`deployments/demo-app/*`, `scripts/dev-up.sh`, `scripts/dev-down.sh`,
`scripts/dev-logs.sh`, `.env.example`, `docs/local-development.md`.

Acceptance criteria: `docker compose --env-file ../.env.example config` is
valid from `deployments/`; healthchecks are present where practical; internal
databases are not exposed publicly by default.

Tests: Compose config validation and a manual `./scripts/dev-up.sh` smoke test.

Dependencies: PR 1.

Rollback notes: Revert compose and scripts. Remove local volumes with
`docker compose down -v` if needed.

## PR 3: Gateway Reverse Proxy MVP

Goal: Implement a minimal Go gateway that listens on a configurable address,
matches Host, and proxies allowed requests to an origin.

Files touched: `services/gateway/cmd/gateway/main.go`,
`services/gateway/internal/config`, `services/gateway/internal/proxy`,
`services/gateway/internal/policy`, `services/gateway/go.mod`,
`services/gateway/config.example.yaml`, `services/gateway/README.md`.

Acceptance criteria: Gateway starts from YAML config; unknown hosts return JSON
404; matching hosts proxy to configured origin; request bodies are restored when
read by middleware.

Tests: Go unit tests for host matching, no matching app, origin target
construction, and proxying to `httptest` upstream.

Dependencies: PR 1, optionally PR 2 for local smoke testing.

Rollback notes: Disable the gateway container or revert the service code. No
persistent schema changes.

## PR 4: Policy Model And Local YAML Config

Goal: Define local policy configuration for apps, origins, modes, IP sets, and
basic allow/block decisions.

Files touched: `services/gateway/internal/config`,
`services/gateway/internal/policy`, `services/gateway/internal/decision`,
`services/gateway/config.example.yaml`, `docs/policy-model.md`,
`docs/request-flow.md`.

Acceptance criteria: Local YAML supports tenant ID, app ID, hostnames, origin,
mode, default action, IP allowlist, and IP blocklist; invalid config fails at
startup with clear errors.

Tests: Go unit tests for CIDR parsing, IP blocklist behavior, count vs block
mode semantics, invalid modes, and invalid origin URLs.

Dependencies: PR 3.

Rollback notes: Revert policy parsing changes and run gateway with the previous
static proxy config.

## PR 5: Custom Rules Engine

Goal: Add deterministic, safe custom rules without arbitrary code execution.

Files touched: `services/gateway/internal/policy/rules*.go`,
`services/gateway/internal/config`, `services/gateway/internal/proxy`,
`services/gateway/config.example.yaml`, `services/gateway/README.md`,
`docs/policy-model.md`.

Acceptance criteria: Rules sort by priority ascending; first terminal block wins;
count action records would-block without blocking; allow short-circuits only
with `terminal_allow`; schema validation rejects unsupported operators.

Tests: Unit tests for method, path, host, header, query parameter, IP set,
`all`, `any`, disabled rules, priority order, count behavior, and invalid rule
validation.

Dependencies: PR 4.

Rollback notes: Remove custom rules from policy config and redeploy. Existing
IP allow/block behavior remains.

## PR 6: Redis Rate Limiting

Goal: Add production-oriented fixed-window Redis rate limiting behind an
interface that can later support sliding windows or token buckets.

Files touched: `services/gateway/internal/ratelimit`,
`services/gateway/internal/policy`, `services/gateway/internal/proxy`,
`services/gateway/internal/config`, `services/gateway/config.example.yaml`,
`deployments/docker-compose.yml`, `services/gateway/README.md`.

Acceptance criteria: Redis limiter uses an atomic Lua script; keys hash
high-cardinality values; Redis disabled mode is a no-op limiter; fail-open or
fail-closed behavior is configurable with fail-open default for MVP.

Tests: Unit tests for below limit, over limit, count action, disabled rules,
separate IP counters, fail-open behavior, and key hashing.

Dependencies: PR 4, PR 5 for match expressions.

Rollback notes: Disable Redis rate limits in policy or set Redis disabled in
gateway config. Existing custom rules continue to work.

## PR 7: Audit Event Pipeline

Goal: Emit redacted structured audit events asynchronously without slowing
request processing.

Files touched: `services/gateway/internal/audit`,
`services/gateway/internal/audit/redaction`, `services/gateway/internal/proxy`,
`docs/event-schema.md`, `docs/request-flow.md`.

Acceptance criteria: Gateway emits one JSON event per line through stdout sink;
dispatcher has a bounded queue; full request bodies, Authorization, and Cookie
headers are never logged; sensitive query parameters are redacted.

Tests: Unit tests for query redaction, sensitive header redaction, dispatcher
drain on shutdown, queue full behavior, and JSON schema snapshot stability.

Dependencies: PR 3 through PR 6.

Rollback notes: Switch gateway to stdout-only synchronous debug logging or
disable nonessential sinks. Event schema changes are additive only.

## PR 8: Coraza WAF Integration

Goal: Integrate Coraza behind the gateway WAF engine interface with safe request
body handling and sample OWASP CRS-compatible rule configuration.

Files touched: `services/gateway/internal/waf`,
`services/gateway/internal/waf/coraza`, `services/gateway/internal/proxy`,
`services/gateway/internal/config`, `services/gateway/rules/coraza.conf`,
`services/gateway/rules/README.md`, `services/gateway/README.md`.

Acceptance criteria: Gateway still works with `waf.enabled=false`; Coraza
interruption maps to block; DetectionOnly/count mode logs would-block and
allows; request body is read only up to configured limit and restored before
proxying; full bodies are not logged.

Tests: Unit tests with a harmless local SecRule for `X-Bedem-Test: block-me`,
count-mode allow, block-mode 403, body restoration to test upstream, and body
limit behavior.

Dependencies: PR 4, PR 7.

Rollback notes: Set `waf.enabled=false` in policy/config and redeploy gateway.
Custom rules and rate limits remain active.

## PR 9: Control API Skeleton

Goal: Add the Go REST API foundation with auth, routing, request IDs, health
checks, validation, and static OpenAPI docs.

Files touched: `services/control-api/cmd/control-api/main.go`,
`services/control-api/internal/config`, `services/control-api/internal/httpapi`,
`services/control-api/internal/auth`, `services/control-api/internal/models`,
`services/control-api/go.mod`, `docs/openapi.yaml`,
`services/control-api/README.md`.

Acceptance criteria: Health endpoints are public; `/v1` routes require
`Authorization: Bearer <BEDEMWAF_ADMIN_API_KEY>`; JSON errors are consistent;
basic tenants/apps/policies/events routes exist even if repository methods are
initial placeholders.

Tests: Handler tests for health, auth required, request ID propagation, JSON
error shape, and validation failures.

Dependencies: PR 1, PR 2.

Rollback notes: Remove the control-api service from Compose or revert the API
skeleton. Gateway can continue local YAML mode.

## PR 10: Postgres Migrations

Goal: Add the initial control-plane schema for tenant-scoped configuration and
policy versioning.

Files touched: `services/control-api/internal/db/migrations/000001_init.up.sql`,
`services/control-api/internal/db/migrations/000001_init.down.sql`,
`services/control-api/internal/db`, `docs/database-schema.md`,
`deployments/docker-compose.yml`.

Acceptance criteria: Up/down migrations are valid SQL; UUID primary keys are
used; relevant tenant/app/host/version/event indexes exist; immutable policy
version snapshots and deployment pointers are represented.

Tests: Migration smoke test against local Postgres or SQL validation in CI when
available; repository unit tests can use fakes until integration DB tests land.

Dependencies: PR 9.

Rollback notes: Apply down migration in non-production environments. In
production, use a forward migration for schema corrections.

## PR 11: Policy Publish Flow

Goal: Implement draft policy create/update and immutable publish flow with an
active deployment pointer.

Files touched: `services/control-api/internal/db`,
`services/control-api/internal/httpapi`, `services/control-api/internal/models`,
`docs/policy-model.md`, `docs/openapi.yaml`,
`services/control-api/README.md`.

Acceptance criteria: Users can create/update policy drafts, publish immutable
versions, atomically update active deployment, fetch active policy by app, and
fetch gateway-ready policy by hostname using the gateway API key.

Tests: API/repository tests for create, update optimistic locking, publish,
immutability, active policy lookup, gateway auth, and invalid policy rejection.

Dependencies: PR 9, PR 10.

Rollback notes: Roll back by republishing the previous policy version. Avoid
deleting published versions.

## PR 12: Gateway Remote Policy Cache

Goal: Let the gateway fetch active policies from Control API by Host and cache
them with stale fallback behavior.

Files touched: `services/gateway/internal/policyclient`,
`services/gateway/internal/policy`, `services/gateway/internal/proxy`,
`services/gateway/internal/config`, `services/gateway/README.md`,
`deployments/gateway/config.compose.yaml`.

Acceptance criteria: Local YAML mode still works; remote mode fetches
`GET /v1/gateway/apps/{hostname}/policy`; cache TTL and fail behavior are
configurable; stale policies are used on fetch failure when available; no stale
policy follows configured fail-open/fail-closed behavior.

Tests: Unit tests for cache hit, cache miss, expiry refresh, stale fallback,
fail-open, fail-closed, invalid policy rejection, Host normalization, and
forward-compatible additive response fields.

Dependencies: PR 11.

Rollback notes: Switch `control_api.enabled=false` and use local YAML policy
until Control API or network issues are fixed.

## PR 13: ClickHouse Event Storage

Goal: Store high-volume gateway audit events in ClickHouse and expose event
search through Control API.

Files touched: `deployments/clickhouse/init.sql`,
`services/gateway/internal/audit`, `services/control-api/internal/events`,
`services/control-api/internal/httpapi`, `services/worker/internal/events`,
`docs/events.md`, `docs/openapi.yaml`.

Acceptance criteria: ClickHouse table `waf_events` is initialized by Compose;
gateway can write to stdout and optionally ClickHouse; Control API supports
filtered event search and event lookup by request ID; raw request bodies are not
stored or exposed.

Tests: Query builder tests for filters, parameterization, limit enforcement,
date range validation, and API auth required.

Dependencies: PR 7, PR 9, PR 11.

Rollback notes: Disable ClickHouse sink and continue stdout events. Historical
events may be unavailable during rollback.

## PR 14: Dashboard MVP

Goal: Build a Next.js admin UI for login, dashboard summary, apps, policy JSON
editor, event search, event detail, and API key placeholder settings.

Files touched: `dashboard/package.json`, `dashboard/next.config.js`,
`dashboard/src/**`, `dashboard/README.md`, `deployments/docker-compose.yml`,
`.env.example`.

Acceptance criteria: TypeScript strict mode is enabled; UI works against the
documented Control API; loading and error states exist; no hardcoded secrets;
development API key storage warning is visible.

Tests: `npm run typecheck`, `npm run build`, and component/client unit tests if
configured. Manual smoke test with local stack.

Dependencies: PR 9, PR 11, PR 13 for event pages.

Rollback notes: Remove dashboard from Compose or point users back to curl/API
flows. Control API remains the source of truth.

## PR 15: Safe Rollout Count/Block Analytics

Goal: Make count-mode tuning visible by distinguishing would-block decisions
from enforced blocks and adding simulation summary analytics.

Files touched: `services/gateway/internal/decision`,
`services/gateway/internal/audit`, `services/control-api/internal/events`,
`services/control-api/internal/httpapi`, `dashboard/src/**`,
`docs/safe-rollout.md`, `docs/event-schema.md`, `docs/openapi.yaml`.

Acceptance criteria: Count mode never blocks because of WAF/custom/rate rules;
events include `enforced` and `would_block`; API exposes
`GET /v1/policies/{policy_id}/simulation-summary`; dashboard shows rules that
would have blocked.

Tests: Gateway tests for count/block WAF, custom rules, and rate limits; Control
API tests for simulation query validation; dashboard typecheck/build.

Dependencies: PR 5, PR 6, PR 8, PR 13, PR 14.

Rollback notes: Keep policies in count mode and hide analytics UI if the
summary endpoint has issues. Existing audit events remain compatible.

## PR 16: Observability

Goal: Add Prometheus metrics endpoints, structured request logging, and optional
Prometheus/Grafana local profile.

Files touched: `services/gateway/internal/metrics`,
`services/control-api/internal/metrics`, `services/worker/internal/metrics`,
`services/*/cmd/*/main.go`, `deployments/docker-compose.yml`,
`deployments/prometheus/prometheus.yml`, `deployments/grafana/**`,
`docs/observability.md`, `README.md`.

Acceptance criteria: `/metrics` endpoints work for gateway, control-api, and
worker; metrics do not expose secrets; optional observability profile starts
Prometheus and Grafana; README documents how to enable it.

Tests: Handler tests for metrics endpoints and existing service tests. Compose
config validation with and without observability profile.

Dependencies: PR 3, PR 9, PR 13.

Rollback notes: Disable metrics endpoints or omit the observability profile.
Core request handling is unaffected.

## PR 17: Security Hardening

Goal: Add obvious production-oriented safeguards across gateway, Control API,
dashboard, Docker, and docs.

Files touched: `services/gateway/internal/config`,
`services/gateway/internal/proxy`, `services/control-api/internal/httpapi`,
`dashboard/next.config.js`, `dashboard/src/**`, `deployments/docker-compose.yml`,
`docs/security-hardening.md`, `docs/production-checklist.md`.

Acceptance criteria: Gateway has request body limit, server timeouts, max header
bytes, trusted proxy CIDR parsing, Host validation, and panic recovery; Control
API has request size limit, safe CORS defaults, secure JSON errors, and auth
tests; dashboard has security headers and dev-mode auth warning; containers
avoid root/read-write where practical.

Tests: Unit tests for trusted proxy IP extraction, Host validation, panic
recovery, Control API auth, request size limit, and CORS defaults.

Dependencies: PR 3, PR 9, PR 14.

Rollback notes: Roll back individual hardening toggles if they block local
development, but preserve no-body-logging and auth protections.

## PR 18: Demo Flow

Goal: Provide a complete local product walkthrough that developers can run with
one command and use for screenshots/internal validation.

Files touched: `scripts/demo-reset.sh`, `scripts/demo-seed.sh`,
`scripts/demo-requests.sh`, `scripts/seed-demo.sh`, `docs/demo.md`,
`README.md`, `.gitignore`, `deployments/docker-compose.yml`,
`deployments/demo-app/main.go`.

Acceptance criteria: `./scripts/demo-reset.sh` starts and seeds the local stack;
`./scripts/demo-requests.sh` demonstrates allowed traffic, count-mode
would-blocks, block-mode 403s, rate-limit 429s, event search, and dashboard
entry points; only harmless test markers are used.

Tests: Shell syntax checks, Compose config validation, full local smoke test
with Docker, and existing `./scripts/test.sh`/`./scripts/lint.sh`.

Dependencies: PR 2, PR 11, PR 12, PR 13, PR 14, PR 15.

Rollback notes: Revert demo scripts/docs only. Core services remain deployable.

## PR 19: CI/CD

Goal: Add GitHub Actions workflows aligned with local scripts.

Files touched: `.github/workflows/ci.yml`, `.github/workflows/docker.yml`,
`README.md`, optionally `scripts/test.sh` and `scripts/lint.sh`.

Acceptance criteria: CI runs gateway, control-api, and worker Go tests;
dashboard install/typecheck/build; lint commands if configured; Docker Compose
config validation; workflows require no real secrets and failures are clear.

Tests: Validate workflow YAML locally if tooling is available; push branch and
confirm GitHub Actions results.

Dependencies: PR 3, PR 9, PR 14, PR 18.

Rollback notes: Disable or revert failing workflow jobs without changing runtime
code. Keep local scripts as source of truth.

## PR 20: Production Checklist

Goal: Publish a concrete production readiness checklist and close obvious docs
gaps without claiming BedemWAF is production-ready before it is.

Files touched: `docs/production-checklist.md`,
`docs/security-hardening.md`, `docs/deployment-model.md`,
`docs/observability.md`, `README.md`.

Acceptance criteria: Checklist covers network, secrets, data, availability,
security, observability, and upgrade/rollback; gaps are labeled as TODOs; origin
locking, TLS, backups, monitoring, access control, managed rule review, and
policy rollback are documented.

Tests: Docs-only PR, so no runtime tests required. Run docs site build and
manual checklist review.

Dependencies: PR 16, PR 17.

Rollback notes: Revert docs updates if they become inaccurate. No runtime state
changes.
