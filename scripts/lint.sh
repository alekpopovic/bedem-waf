#!/usr/bin/env sh
set -eu

root_dir="$(dirname "$0")/.."

export GOCACHE="${GOCACHE:-/tmp/bedemwaf-go-cache}"
export GOPATH="${GOPATH:-/tmp/bedemwaf-go}"
export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"

check_gofmt() {
  service="$1"
  files="$(cd "$root_dir/$service" && gofmt -l .)"
  if [ -n "$files" ]; then
    printf 'gofmt needed in %s:\n%s\n' "$service" "$files"
    exit 1
  fi
}

printf '==> gofmt checks\n'
check_gofmt services/gateway
check_gofmt services/control-api
check_gofmt services/worker

printf '==> go vet checks\n'
(cd "$root_dir/services/gateway" && go vet ./...)
(cd "$root_dir/services/control-api" && go vet ./...)
(cd "$root_dir/services/worker" && go vet ./...)

if [ -d "$root_dir/dashboard/node_modules" ]; then
  printf '==> dashboard lint\n'
  (cd "$root_dir/dashboard" && npm run lint)
else
  printf '==> dashboard lint skipped; run npm ci in dashboard/ first\n'
fi
