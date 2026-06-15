# Codex Command Recipes

Use these from the repository root unless otherwise noted.

## Finish Every File-Changing Prompt

After validation succeeds, commit and push the completed work:

```bash
git status --short
git add <changed-files>
git commit -m "<concise imperative summary>"
git push
```

Use `git add .` only when all visible changes are part of the completed prompt.
Never stage secrets, local `.env` files, generated caches, or unrelated user
changes.

## Tests

Run all current service tests:

```bash
./scripts/test.sh
```

Run gateway tests directly:

```bash
cd services/gateway
GOCACHE=/tmp/bedemwaf-go-cache GOPATH=/tmp/bedemwaf-go GOMODCACHE=/tmp/bedemwaf-go/pkg/mod go test ./...
```

Run control API tests directly:

```bash
cd services/control-api
GOCACHE=/tmp/bedemwaf-go-cache GOPATH=/tmp/bedemwaf-go GOMODCACHE=/tmp/bedemwaf-go/pkg/mod go test ./...
```

Run worker tests directly:

```bash
cd services/worker
GOCACHE=/tmp/bedemwaf-go-cache GOPATH=/tmp/bedemwaf-go GOMODCACHE=/tmp/bedemwaf-go/pkg/mod go test ./...
```

## Formatting

Format changed Go files:

```bash
gofmt -w <files>
```

## Local Infrastructure

Validate Compose:

```bash
cd deployments
docker compose config --quiet
```

Start dependencies:

```bash
./scripts/dev-up.sh
```

Stop dependencies:

```bash
./scripts/dev-down.sh
```

## Gateway

Run gateway with sample config:

```bash
cd services/gateway
GOCACHE=/tmp/bedemwaf-go-cache GOPATH=/tmp/bedemwaf-go GOMODCACHE=/tmp/bedemwaf-go/pkg/mod go run ./cmd/gateway -config config.example.yaml
```

Start a simple origin for manual gateway testing:

```bash
python3 -m http.server 9000
```

## Docs Site

Build the static docs site:

```bash
python3 scripts/build-docs-site.py
```

The output goes to `_site/` and is ignored by git.
