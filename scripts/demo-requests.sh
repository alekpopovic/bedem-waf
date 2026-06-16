#!/usr/bin/env sh
set -eu

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
env_file="${ENV_FILE:-$root_dir/.env}"
if [ ! -f "$env_file" ]; then
  env_file="$root_dir/.env.example"
fi
state_file="${DEMO_STATE_FILE:-$root_dir/.demo.env}"

set -a
. "$env_file"
if [ -f "$state_file" ]; then
  . "$state_file"
fi
set +a

api_url="${DEMO_API_URL:-${CONTROL_API_URL:-http://localhost:${CONTROL_API_PORT:-8081}}}"
gateway_url="${DEMO_GATEWAY_URL:-${GATEWAY_URL:-http://localhost:${GATEWAY_PORT:-8080}}}"
dashboard_url="${DEMO_DASHBOARD_URL:-${DASHBOARD_URL:-http://localhost:${DASHBOARD_PORT:-3000}}}"
admin_key="${DEMO_ADMIN_KEY:-${BEDEMWAF_ADMIN_API_KEY:-local_dev_admin_key_change_me}}"
tenant_id="${DEMO_TENANT_ID:-}"
app_id="${DEMO_APP_ID:-}"
policy_id="${DEMO_POLICY_ID:-}"
demo_host="${DEMO_HOST:-demo.localhost}"
cache_wait="${DEMO_POLICY_CACHE_WAIT_SECONDS:-11}"

if [ -z "$tenant_id" ] || [ -z "$app_id" ] || [ -z "$policy_id" ]; then
  echo "Missing demo state. Run ./scripts/demo-seed.sh or ./scripts/demo-reset.sh first." >&2
  exit 1
fi

tenant_header="X-Bedem-Tenant-ID: $tenant_id"

step() {
  printf '\n==> %s\n' "$1"
}

status_request() {
  path="$1"
  extra_header="${2:-}"
  if [ -n "$extra_header" ]; then
    curl -sS -o /tmp/bedemwaf-demo-response.txt -w "%{http_code}" \
      -H "Host: $demo_host" \
      -H "$extra_header" \
      "$gateway_url$path"
  else
    curl -sS -o /tmp/bedemwaf-demo-response.txt -w "%{http_code}" \
      -H "Host: $demo_host" \
      "$gateway_url$path"
  fi
}

api_request() {
  method="$1"
  path="$2"
  data="${3:-}"
  if [ -n "$data" ]; then
    curl -fsS -X "$method" "$api_url$path" \
      -H "Authorization: Bearer $admin_key" \
      -H "$tenant_header" \
      -H "Content-Type: application/json" \
      -d "$data"
  else
    curl -fsS -X "$method" "$api_url$path" \
      -H "Authorization: Bearer $admin_key" \
      -H "$tenant_header"
  fi
}

json_field() {
  field="$1"
  python3 -c 'import json,sys; print(json.load(sys.stdin)["'"$field"'"])'
}

policy_update_payload() {
  mode="$1"
  expected_updated_at="$2"
  python3 - "$mode" "$expected_updated_at" <<'PY'
import json
import sys

mode = sys.argv[1]
expected_updated_at = sys.argv[2]
print(json.dumps({
    "expected_updated_at": expected_updated_at,
    "mode": mode,
    "snapshot": {
        "mode": mode,
        "ip_sets": {"office_ips": ["198.51.100.0/24"]},
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
PY
}

print_response() {
  status="$1"
  expected="$2"
  printf 'HTTP status: %s (expected %s)\n' "$status" "$expected"
  sed -n '1,8p' /tmp/bedemwaf-demo-response.txt
  printf '\n'
  if [ "$status" != "$expected" ]; then
    echo "Unexpected HTTP status for demo step." >&2
    exit 1
  fi
}

step "Waiting for Gateway at $gateway_url"
for _ in $(seq 1 60); do
  if curl -fsS -H "Host: $demo_host" "$gateway_url/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fsS -H "Host: $demo_host" "$gateway_url/healthz" >/dev/null

step "1. Allowed request in count mode"
status="$(status_request /)"
print_response "$status" "200"

step "2. /admin matches custom rule in count mode and is allowed"
status="$(status_request /admin)"
print_response "$status" "200"

step "3. X-Bedem-Test: block-me matches custom rule in count mode and is allowed"
status="$(status_request / "X-Bedem-Test: block-me")"
print_response "$status" "200"

step "4. Switching policy to block mode"
policy_json="$(api_request GET "/v1/policies/$policy_id")"
updated_at="$(printf '%s' "$policy_json" | json_field updated_at)"
patch_payload="$(policy_update_payload block "$updated_at")"
api_request PATCH "/v1/policies/$policy_id" "$patch_payload" >/dev/null
publish_json="$(api_request POST "/v1/policies/$policy_id/publish")"
policy_version_id="$(printf '%s' "$publish_json" | json_field policy_version_id)"
printf 'Published block-mode policy version: %s\n' "$policy_version_id"

printf 'Waiting %s seconds for gateway policy cache refresh...\n' "$cache_wait"
sleep "$cache_wait"

step "5. /admin now blocks in block mode"
status="$(status_request /admin)"
print_response "$status" "403"

step "6. X-Bedem-Test: block-me now blocks in block mode"
status="$(status_request / "X-Bedem-Test: block-me")"
print_response "$status" "403"

step "7. Login burst triggers rate limit"
i=1
last_status=""
while [ "$i" -le 7 ]; do
  last_status="$(status_request /login)"
  printf 'login request %s -> HTTP %s\n' "$i" "$last_status"
  i=$((i + 1))
done
printf 'Expected final burst status: 429, got %s\n' "$last_status"
if [ "$last_status" != "429" ]; then
  echo "Login burst did not trigger the expected rate limit." >&2
  exit 1
fi

step "8. Query recent events through Control API"
events_json="$(api_request GET "/v1/events?app_id=$app_id&host=$demo_host&limit=10")"
EVENTS_JSON="$events_json" python3 - <<'PY'
import json
import os
import sys

data = json.loads(os.environ["EVENTS_JSON"])
events = data.get("events", [])
if not events:
    print("No events returned yet. ClickHouse writes may still be catching up.")
    raise SystemExit(0)
for event in events[:10]:
    print(
        f"{event.get('timestamp', '')} "
        f"{event.get('request_id', '')} "
        f"{event.get('action', '')} "
        f"enforced={event.get('enforced')} "
        f"would_block={event.get('would_block')} "
        f"{event.get('host', '')}{event.get('path', '')} "
        f"rule={event.get('matched_rule_id', '')}"
    )
PY

cat <<EOF

Dashboard:
  $dashboard_url/login

Login values:
  Admin API key: $admin_key
  Tenant ID:     $tenant_id

Useful pages:
  $dashboard_url/apps
  $dashboard_url/events
EOF
