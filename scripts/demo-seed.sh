#!/usr/bin/env sh
set -eu

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${ENV_FILE:-$root_dir/.env}"
if [ ! -f "$env_file" ]; then
  env_file="$root_dir/.env.example"
fi

set -a
. "$env_file"
set +a

api_url="${CONTROL_API_URL:-http://localhost:${CONTROL_API_PORT:-8081}}"
gateway_url="${GATEWAY_URL:-http://localhost:${GATEWAY_PORT:-8080}}"
dashboard_url="${DASHBOARD_URL:-http://localhost:${DASHBOARD_PORT:-3000}}"
admin_key="${BEDEMWAF_ADMIN_API_KEY:-local_dev_admin_key_change_me}"
demo_host="${DEMO_HOST:-demo.localhost}"
origin_url="${DEMO_ORIGIN_URL:-http://nginx-origin:8080}"
state_file="${DEMO_STATE_FILE:-$root_dir/.demo.env}"
suffix="${DEMO_SUFFIX:-$(date +%s)}"

step() {
  printf '\n==> %s\n' "$1"
}

json_value() {
  key="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)["'"$key"'"])'
}

api_request() {
  method="$1"
  path="$2"
  tenant_header="${3:-}"
  data="${4:-}"
  if [ -n "$data" ]; then
    if [ -n "$tenant_header" ]; then
      curl -fsS -X "$method" "$api_url$path" \
        -H "Authorization: Bearer $admin_key" \
        -H "$tenant_header" \
        -H "Content-Type: application/json" \
        -d "$data"
    else
      curl -fsS -X "$method" "$api_url$path" \
        -H "Authorization: Bearer $admin_key" \
        -H "Content-Type: application/json" \
        -d "$data"
    fi
  else
    if [ -n "$tenant_header" ]; then
      curl -fsS -X "$method" "$api_url$path" \
        -H "Authorization: Bearer $admin_key" \
        -H "$tenant_header"
    else
      curl -fsS -X "$method" "$api_url$path" \
        -H "Authorization: Bearer $admin_key"
    fi
  fi
}

json_payload() {
  python3 - "$@" <<'PY'
import json
import sys

kind = sys.argv[1]
if kind == "app":
    _, _, tenant_id, suffix, host, origin = sys.argv
    print(json.dumps({
        "tenant_id": tenant_id,
        "name": "Demo App",
        "slug": f"demo-app-{suffix}",
        "hostnames": [host],
        "origin_url": origin,
    }))
elif kind == "policy":
    _, _, mode = sys.argv
    print(json.dumps({
        "name": "Demo policy",
        "mode": mode,
        "snapshot": {
            "mode": mode,
            "ip_sets": {
                "office_ips": ["198.51.100.0/24"],
            },
            "custom_rules": [
                {
                    "id": "rule-admin-office-only",
                    "name": "Admin path outside office IPs",
                    "priority": 100,
                    "enabled": True,
                    "action": "block",
                    "status_code": 403,
                    "when": {
                        "all": [
                            {"path_starts_with": "/admin"},
                            {"client_ip_not_in_ip_set": "office_ips"},
                        ],
                    },
                },
                {
                    "id": "rule-header-block-me",
                    "name": "Harmless demo header marker",
                    "priority": 200,
                    "enabled": True,
                    "action": "block",
                    "status_code": 403,
                    "when": {
                        "header_equals": {
                            "name": "X-Bedem-Test",
                            "value": "block-me",
                        },
                    },
                },
            ],
            "rate_limits": [
                {
                    "id": "rl-login-demo",
                    "name": "Demo login IP rate limit",
                    "enabled": True,
                    "priority": 100,
                    "match": {"path_starts_with": "/login"},
                    "key_type": "ip",
                    "limit": 5,
                    "window_seconds": 60,
                    "action": "block",
                    "status_code": 429,
                },
            ],
            "waf": {"enabled": False},
        },
    }))
else:
    raise SystemExit(f"unknown payload kind: {kind}")
PY
}

step "Waiting for Control API at $api_url"
for _ in $(seq 1 90); do
  if curl -fsS "$api_url/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "$api_url/readyz" >/dev/null

step "Creating Demo Tenant"
tenant_json="$(api_request POST /v1/tenants "" '{"name":"Demo Tenant","slug":"demo-'"$suffix"'"}')"
tenant_id="$(printf '%s' "$tenant_json" | json_value id)"
tenant_header="X-Bedem-Tenant-ID: $tenant_id"
printf 'tenant_id=%s\n' "$tenant_id"

step "Creating Demo App for $demo_host"
app_payload="$(json_payload app "$tenant_id" "$suffix" "$demo_host" "$origin_url")"
app_json="$(api_request POST /v1/apps "$tenant_header" "$app_payload")"
app_id="$(printf '%s' "$app_json" | json_value id)"
printf 'app_id=%s\n' "$app_id"

step "Creating count-mode policy"
policy_payload="$(json_payload policy count)"
policy_json="$(api_request POST "/v1/apps/$app_id/policies" "$tenant_header" "$policy_payload")"
policy_id="$(printf '%s' "$policy_json" | json_value id)"
printf 'policy_id=%s\n' "$policy_id"

step "Publishing count-mode policy"
publish_json="$(api_request POST "/v1/policies/$policy_id/publish" "$tenant_header")"
policy_version_id="$(printf '%s' "$publish_json" | json_value policy_version_id)"
printf 'policy_version_id=%s\n' "$policy_version_id"

step "Writing demo state to $state_file"
cat >"$state_file" <<EOF
DEMO_TENANT_ID=$tenant_id
DEMO_APP_ID=$app_id
DEMO_POLICY_ID=$policy_id
DEMO_POLICY_VERSION_ID=$policy_version_id
DEMO_HOST=$demo_host
DEMO_ORIGIN_URL=$origin_url
DEMO_API_URL=$api_url
DEMO_GATEWAY_URL=$gateway_url
DEMO_DASHBOARD_URL=$dashboard_url
DEMO_ADMIN_KEY=$admin_key
EOF

step "Warming gateway policy cache"
curl -sS -H "Host: $demo_host" "$gateway_url/" >/dev/null || true

cat <<EOF

Demo seed complete.

Dashboard:
  $dashboard_url/login

Login values:
  Admin API key: $admin_key
  Tenant ID:     $tenant_id

Next:
  ./scripts/demo-requests.sh
EOF
