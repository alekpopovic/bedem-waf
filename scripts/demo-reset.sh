#!/usr/bin/env sh
set -eu

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${ENV_FILE:-$root_dir/.env}"
if [ ! -f "$env_file" ]; then
  env_file="$root_dir/.env.example"
fi

step() {
  printf '\n==> %s\n' "$1"
}

step "Resetting local Docker Compose stack and volumes"
cd "$root_dir/deployments"
docker compose --env-file "$env_file" down -v --remove-orphans

step "Starting local Docker Compose stack"
BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker compose --env-file "$env_file" up -d --build

step "Seeding BedemWAF demo"
cd "$root_dir"
ENV_FILE="$env_file" "$root_dir/scripts/demo-seed.sh"

cat <<'EOF'

Demo stack is ready.

Open the dashboard, then run:
  ./scripts/demo-requests.sh
EOF
