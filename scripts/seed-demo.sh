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
admin_key="${BEDEMWAF_ADMIN_API_KEY:-local_dev_admin_key_change_me}"
demo_host="${DEMO_HOST:-demo.local}"
origin_url="${DEMO_ORIGIN_URL:-http://nginx-origin:8080}"
suffix="$(date +%s)"

request() {
  method="$1"
  path="$2"
  data="${3:-}"
  if [ -n "$data" ]; then
    curl -fsS -X "$method" "$api_url$path" \
      -H "Authorization: Bearer $admin_key" \
      -H "Content-Type: application/json" \
      -d "$data"
  else
    curl -fsS -X "$method" "$api_url$path" \
      -H "Authorization: Bearer $admin_key"
  fi
}

json_get() {
  key="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)["'"$key"'"])'
}

echo "Waiting for Control API at $api_url ..."
for _ in $(seq 1 60); do
  if curl -fsS "$api_url/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -fsS "$api_url/readyz" >/dev/null

tenant_json=$(request POST /v1/tenants '{"name":"Demo Tenant","slug":"demo-'"$suffix"'"}')
tenant_id=$(printf '%s' "$tenant_json" | json_get id)
echo "Created tenant: $tenant_id"

app_json=$(request POST /v1/apps '{
  "tenant_id":"'"$tenant_id"'",
  "name":"Demo App",
  "slug":"demo-app-'"$suffix"'",
  "hostnames":["'"$demo_host"'"],
  "origin_url":"'"$origin_url"'"
}')
app_id=$(printf '%s' "$app_json" | json_get id)
echo "Created app: $app_id ($demo_host -> $origin_url)"

policy_json=$(request POST "/v1/apps/$app_id/policies" '{
  "name":"Demo policy",
  "mode":"block",
  "snapshot":{
    "mode":"block",
    "ip_sets":{
      "office_ips":["198.51.100.0/24"]
    },
    "custom_rules":[
      {
        "id":"rule-block-admin",
        "name":"Block admin demo path",
        "priority":100,
        "enabled":true,
        "action":"block",
        "status_code":403,
        "when":{"path_starts_with":"/admin"}
      }
    ],
    "rate_limits":[
      {
        "id":"rl-login-demo",
        "name":"Demo login IP rate limit",
        "enabled":true,
        "priority":100,
        "match":{"path_starts_with":"/login"},
        "key_type":"ip",
        "limit":3,
        "window_seconds":60,
        "action":"block",
        "status_code":429
      }
    ],
    "waf":{
      "enabled":false
    }
  }
}')
policy_id=$(printf '%s' "$policy_json" | json_get id)
echo "Created policy draft: $policy_id"

publish_json=$(request POST "/v1/policies/$policy_id/publish")
policy_version_id=$(printf '%s' "$publish_json" | json_get policy_version_id)
echo "Published policy version: $policy_version_id"

echo "Warming gateway policy cache..."
curl -sS -H "Host: $demo_host" "$gateway_url/" >/dev/null || true

cat <<EOF

Demo is ready.

Allowed request:
  curl -i -H 'Host: $demo_host' $gateway_url/

Blocked request:
  curl -i -H 'Host: $demo_host' $gateway_url/admin

Rate limit request, run 4 times within 60 seconds:
  curl -i -H 'Host: $demo_host' $gateway_url/login

Echo request:
  curl -i -X POST -H 'Host: $demo_host' -H 'Content-Type: application/json' \\
    -d '{"hello":"bedemwaf"}' $gateway_url/api/echo

Dashboard:
  http://localhost:${DASHBOARD_PORT:-3000}

Control API:
  $api_url
EOF
