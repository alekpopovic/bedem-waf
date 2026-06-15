# BedemWAF Codex Agent Guide

This file gives Codex agents project-specific context for working in this
repository.

## Project

BedemWAF is a defensive, self-hosted managed WAF platform for applications behind
NGINX origins.

Core path:

```text
Internet -> BedemWAF Gateway -> NGINX Origin -> Application
```

Primary services:

- `services/gateway`: Go reverse proxy and data-plane enforcement.
- `services/control-api`: Go REST control plane backed by Postgres.
- `services/worker`: Go async jobs for rule updates, enrichment, and retention.
- `dashboard`: Next.js admin UI.
- `deployments`: Local Docker Compose and infrastructure examples.
- `docs`: Product, architecture, security, and implementation documentation.

## Safety Rules

- BedemWAF is defensive software only.
- Do not add exploit tooling, offensive scanning, payload generation, or attack
  replay features.
- Do not log request bodies by default.
- Do not commit real secrets.
- Prefer count mode before block mode.
- Redact sensitive values in audit logs and examples.
- Keep origin lock-down guidance intact when editing deployment docs.

## Common Commands

Run all current service tests:

```bash
./scripts/test.sh
```

Run gateway tests directly:

```bash
cd services/gateway
GOCACHE=/tmp/bedemwaf-go-cache GOPATH=/tmp/bedemwaf-go GOMODCACHE=/tmp/bedemwaf-go/pkg/mod go test ./...
```

Validate local Compose configuration:

```bash
cd deployments
docker compose config --quiet
```

Build the docs site:

```bash
python3 scripts/build-docs-site.py
```

More command recipes live in [`.codex/commands.md`](.codex/commands.md).

## Completion Workflow

After every user prompt that changes files, Codex must prepare the work for the
remote repository:

1. Run relevant validation.
2. Review `git status --short`.
3. Stage the completed change with `git add`.
4. Commit with a concise message.
5. Push the commit to the configured remote.

Exceptions:

- Do not commit or push if validation fails and the failure is not explicitly
  accepted by the user.
- Do not commit or push if the user explicitly asks not to.
- Do not commit secrets, generated caches, local `.env` files, or unrelated
  user changes.
- If push fails because credentials or network access are unavailable, report
  the exact failure and leave the commit local.

## Coding Conventions

- Keep services isolated.
- Use idiomatic Go and small internal packages.
- Add focused unit tests for policy, decision, request handling, validation, and
  migration-sensitive logic.
- Prefer structured logs.
- Avoid new dependencies unless they clearly reduce risk or complexity.
- Keep docs implementation-oriented and specific to BedemWAF.

## Go Notes

- Use `gofmt` on changed Go files.
- The sandbox may not allow writes to the default Go cache. Use `/tmp` cache
  locations in commands when needed:

```bash
GOCACHE=/tmp/bedemwaf-go-cache GOPATH=/tmp/bedemwaf-go GOMODCACHE=/tmp/bedemwaf-go/pkg/mod
```

## Current MVP Direction

- Gateway: YAML config, host lookup, in-memory policy, IP blocklist, optional
  Redis rate limiting, placeholder WAF interface, JSON audit logs, reverse proxy.
- Control API: initial Postgres schema and migrations.
- Dashboard: scaffold only.
- Worker: scaffold only.

Detailed repo context lives in [`.codex/project.md`](.codex/project.md), and
safe follow-up tasks live in [`.codex/backlog.md`](.codex/backlog.md).

## Review Checklist

Before finishing changes:

- Run relevant tests.
- Confirm no real secrets were added.
- Confirm request bodies are not logged.
- Confirm docs and README links still point to real files.
- Note any command that could not be run and why.
