# BedemWAF Testing Strategy

BedemWAF is a defensive security product, so tests must prove safe defaults and predictable enforcement before they prove feature breadth. The test suite should stay deterministic, avoid external internet access, and use harmless markers such as `X-Bedem-Test: block-me` or `/blocked-test` instead of exploit payload collections.

## Goals

- Catch regressions in policy enforcement before they can affect protected origins.
- Verify sensitive data is redacted from logs and event storage.
- Keep unit tests fast enough for every local edit and every CI run.
- Provide integration and end-to-end tests that exercise the same local Docker Compose stack engineers use during development.
- Make count mode and block mode behavior explicit in tests.

## Test Pyramid

```text
                  End-to-end tests
             seed policy + live stack checks
                         /\
                        /  \
              Integration tests
      gateway, control-api, redis, postgres,
        clickhouse, dashboard API contract
                      /      \
                     /        \
                Unit tests
 policy, custom rules, rate limits, redaction,
 audit events, API validation, repositories
```

Most tests should be unit tests. Integration tests should cover service boundaries and storage behavior. End-to-end tests should be fewer, slower, and focused on MVP user flows.

## Unit Tests

Unit tests run with:

```sh
./scripts/test.sh
```

Current gateway coverage includes:

- Host normalization and app lookup.
- CIDR IP blocklist evaluation.
- Count mode versus block mode decision enforcement.
- Custom rule operators:
  - method equals
  - path equals
  - path starts with
  - host equals
  - header contains
  - header equals
  - query parameter contains
  - client IP in IP set
  - client IP not in IP set
  - `all` conditions
  - `any` conditions
- Disabled custom rules.
- Custom rule priority ordering.
- Terminal allow short-circuit behavior.
- Non-terminal allow behavior.
- Invalid custom rule validation.
- Unknown IP set validation.
- Rate limit fixed-window behavior with deterministic in-memory stores.
- Rate limit key hashing so sensitive token-like values do not appear in Redis keys.
- Query redaction.
- sensitive header redaction for `Authorization` and `Cookie`.
- Async audit dispatcher draining, bounded queue drops, and JSON schema stability.

Unit tests to add next:

- Control API request validation for all policy fields.
- Policy publish validation and immutable version behavior at repository level.
- ClickHouse event query builder edge cases for every filter.
- Dashboard API client serialization tests.
- Coraza configuration error handling with missing or invalid rule files.

## Integration Tests

Integration tests validate real service seams while still using local deterministic dependencies.

```text
+-------------+       +-------------------+
| test client | ----> | BedemWAF Gateway  |
+-------------+       +-------------------+
                               |
                               v
                       +---------------+
                       | fake upstream |
                       | httptest      |
                       +---------------+
```

Current gateway integration coverage includes:

- Gateway proxies to a real `httptest` upstream.
- The upstream receives the original method, path, and body.
- Gateway injects `X-BedemWAF-Request-ID`.
- Gateway preserves `X-Forwarded-Host`.
- Request bodies are restored before proxying after WAF preview reads.

Integration tests to add next:

- Gateway to Redis using the Compose Redis service.
- Gateway to Control API policy fetch with cache hit, miss, stale fallback, fail-open, and fail-closed behavior.
- Control API to Postgres migrations and CRUD repositories.
- Control API to ClickHouse event search.
- Worker retention cleanup against ClickHouse.

## Security Regression Tests

Security regressions should use harmless inputs that represent enforcement mechanics, not real attack strings.

Required checks:

- Count mode records `count` or would-block decisions but still proxies the request.
- Block mode returns the configured deny status.
- Sensitive query values are redacted:
  - `password`
  - `pass`
  - `token`
  - `access_token`
  - `refresh_token`
  - `secret`
  - `api_key`
  - `key`
  - `code`
- `Authorization` and `Cookie` headers are never logged.
- Full request bodies are not logged by default.
- Oversized bodies are blocked or counted according to policy mode.
- Unknown or invalid `Host` values do not route to a default app.
- Malformed headers are handled by Go's HTTP server and must not bypass policy checks.

Current security regression coverage includes count/block mode, redaction, no body logging by default, oversized body block behavior, and no matching app handling.

## End-To-End Tests

End-to-end tests should run against the local Docker Compose stack:

```text
+--------+      +---------+      +--------------+      +----------+
| client | ---> | gateway | ---> | nginx-origin | ---> | demo-app |
+--------+      +---------+      +--------------+      +----------+
                    |
                    v
             +-------------+
             | control-api |
             +-------------+
              |          |
              v          v
         +----------+  +------------+
         | postgres |  | clickhouse |
         +----------+  +------------+
```

Baseline E2E flow:

1. Start the stack with `./scripts/dev-up.sh`.
2. Seed a demo tenant, app, and policy with `./scripts/seed-demo.sh`.
3. Send an allowed request to `/`.
4. Send a request matching a harmless block rule such as `/admin` or `/blocked-test`.
5. Send a rate-limited sequence to `/login`.
6. Verify audit events are searchable through `GET /v1/events`.

The E2E suite should eventually be wrapped in a script such as `scripts/test-e2e.sh` so CI can opt into it separately from fast unit tests.

## CI Plan

Initial CI should call:

```sh
./scripts/test.sh
```

Later CI stages should add:

- `docker compose --env-file ../.env.example config` from `deployments/`.
- Docker image build checks when runner disk space permits.
- Compose-backed integration tests.
- Dashboard TypeScript build and lint checks.
- Optional E2E smoke tests on pull requests touching gateway, control-api, deployments, or event code.

## MVP Scope

MVP tests focus on:

- Local YAML policy behavior.
- Remote policy fetch and cache unit behavior.
- Gateway reverse proxy behavior.
- Safe custom rules.
- Redis-backed rate limiting logic through deterministic stores.
- Audit event formatting and redaction.
- Control API CRUD and publish flows.
- ClickHouse query validation.

## Later-Phase Scope

Later phases should add:

- OWASP CRS compatibility smoke tests using mounted rule files.
- Multi-node gateway cache consistency checks.
- Policy rollback tests.
- Dashboard browser tests with Playwright.
- Load tests for audit dispatcher backpressure.
- Chaos tests for Redis, ClickHouse, Control API, and origin outages.
- Upgrade tests for database migrations.

## Test Data Rules

- Do not commit real secrets, access tokens, cookies, or customer-like data.
- Do not commit exploit payload collections.
- Prefer clearly fake documentation ranges for IPs, such as `198.51.100.0/24` and `203.0.113.0/24`.
- Prefer harmless rule markers:
  - `X-Bedem-Test: block-me`
  - `/blocked-test`
  - `User-Agent: bad-bot-test`
- Keep timestamps deterministic where possible.

## Running Tests Locally

Fast tests:

```sh
./scripts/test.sh
```

Compose validation:

```sh
cd deployments
docker compose --env-file ../.env.example config
```

Local stack smoke test:

```sh
./scripts/dev-up.sh
./scripts/seed-demo.sh
curl -i -H 'Host: demo.local' http://localhost:8080/
curl -i -H 'Host: demo.local' http://localhost:8080/admin
./scripts/dev-down.sh
```
