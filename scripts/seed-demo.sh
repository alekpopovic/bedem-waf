#!/usr/bin/env sh
set -eu

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
exec "$root_dir/scripts/demo-seed.sh" "$@"
