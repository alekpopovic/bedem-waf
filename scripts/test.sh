#!/usr/bin/env sh
set -eu

root_dir="$(dirname "$0")/.."

export GOCACHE="${GOCACHE:-/tmp/bedemwaf-go-cache}"
export GOPATH="${GOPATH:-/tmp/bedemwaf-go}"
export GOMODCACHE="${GOMODCACHE:-$GOPATH/pkg/mod}"

(cd "$root_dir/services/gateway" && go test ./...)
(cd "$root_dir/services/control-api" && go test ./...)
(cd "$root_dir/services/worker" && go test ./...)
