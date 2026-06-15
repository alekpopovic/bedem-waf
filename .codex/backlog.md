# Codex Backlog

Safe next tasks for future agents.

## Gateway

- Add config unit tests for YAML defaults and validation errors.
- Add trusted proxy tests for `X-Forwarded-For` handling.
- Add Redis limiter tests with a fake RESP server that does not require network
  binding in restricted sandboxes.
- Add health endpoint support.
- Add WAF engine package with a Coraza adapter behind the existing interface.
- Add request body inspection limits before Coraza integration.

## Control API

- Add migration runner command.
- Add database connection config.
- Add health endpoint.
- Add tenant/app/origin/policy model structs.
- Add OpenAPI skeleton.
- Add validation tests for create/update request payloads.

## Worker

- Add job runner interface.
- Add retention cleanup placeholder.
- Add managed rule update job skeleton with signature/checksum placeholders.

## Dashboard

- Scaffold actual Next.js `src/app` structure.
- Add secure headers in `next.config.js`.
- Add API client layout generated from future OpenAPI schema.

## Docs

- Keep `docs/database-schema.md` in sync with migrations.
- Rebuild docs site when navigation or docs pages change.
- Add origin lock-down examples for common deployment targets.

## Security Checks

- Confirm request bodies are not logged.
- Confirm examples use safe placeholder secrets only.
- Confirm new policy behavior defaults to count mode where possible.
- Confirm unknown hosts do not proxy to origins.
