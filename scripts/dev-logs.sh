#!/usr/bin/env sh
set -eu

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${ENV_FILE:-$root_dir/.env}"
if [ ! -f "$env_file" ]; then
  env_file="$root_dir/.env.example"
fi

cd "$root_dir/deployments"
docker compose --env-file "$env_file" logs -f "$@"
