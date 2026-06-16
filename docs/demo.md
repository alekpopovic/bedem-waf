# Demo Flow

This demo gives a developer a repeatable BedemWAF product walkthrough:

1. Start the local Docker Compose stack.
2. Seed a tenant, app, origin, and count-mode policy.
3. Send harmless requests that would block in count mode.
4. Publish the same policy in block mode.
5. Confirm blocked and rate-limited responses.
6. Search the resulting audit events through the Control API and dashboard.

The demo uses only harmless markers:

- path `/admin`
- header `X-Bedem-Test: block-me`
- path `/login` for rate limiting

It does not use offensive payload collections.

## One Command Setup

From the repository root:

```bash
./scripts/demo-reset.sh
```

This command:

- stops the local stack
- removes local Compose volumes
- rebuilds and starts the stack
- waits for the Control API
- creates `Demo Tenant`
- creates `Demo App`
- configures hostname `demo.localhost`
- points the origin at `http://nginx-origin:8080`
- creates and publishes a count-mode policy
- writes demo IDs to `.demo.env`

Expected final output:

```text
Demo seed complete.

Dashboard:
  http://localhost:3000/login

Login values:
  Admin API key: local_dev_admin_key_change_me
  Tenant ID:     <generated tenant id>

Next:
  ./scripts/demo-requests.sh
```

## Open The Dashboard

Open:

```text
http://localhost:3000/login
```

Use the values printed by `demo-reset.sh`:

- Admin API key: `local_dev_admin_key_change_me`
- Tenant ID: value from `.demo.env`

Useful pages:

- Apps: http://localhost:3000/apps
- Events: http://localhost:3000/events

## Send Demo Requests

Run:

```bash
./scripts/demo-requests.sh
```

The script performs the full flow.

### 1. Allowed Request

Request:

```bash
curl -i -H 'Host: demo.localhost' http://localhost:8080/
```

Expected:

```text
HTTP status: 200
request reached the demo application
```

### 2. Count Mode Custom Rule

Request:

```bash
curl -i -H 'Host: demo.localhost' http://localhost:8080/admin
```

Expected while policy mode is `count`:

```text
HTTP status: 200
```

The audit event should show:

```json
{
  "action": "block",
  "mode": "count",
  "would_block": true,
  "enforced": false,
  "matched_rule_id": "rule-admin-office-only"
}
```

### 3. Count Mode Header Marker

Request:

```bash
curl -i -H 'Host: demo.localhost' \
  -H 'X-Bedem-Test: block-me' \
  http://localhost:8080/
```

Expected while policy mode is `count`:

```text
HTTP status: 200
```

The audit event should show `matched_rule_id=rule-header-block-me`,
`would_block=true`, and `enforced=false`.

### 4. Switch To Block Mode

`demo-requests.sh` updates the policy draft, publishes a new immutable policy
version, and waits for the gateway policy cache to refresh.

Expected output:

```text
Published block-mode policy version: <policy version id>
Waiting 11 seconds for gateway policy cache refresh...
```

### 5. Block Mode Custom Rule

Request:

```bash
curl -i -H 'Host: demo.localhost' http://localhost:8080/admin
```

Expected after block-mode publish:

```text
HTTP status: 403
{"error":"request blocked","request_id":"..."}
```

The audit event should show:

```json
{
  "action": "block",
  "mode": "block",
  "would_block": true,
  "enforced": true,
  "matched_rule_id": "rule-admin-office-only"
}
```

### 6. Header Marker Block

Request:

```bash
curl -i -H 'Host: demo.localhost' \
  -H 'X-Bedem-Test: block-me' \
  http://localhost:8080/
```

Expected after block-mode publish:

```text
HTTP status: 403
```

### 7. Login Rate Limit

The policy contains a rate limit for `/login`:

- key: client IP
- limit: 5
- window: 60 seconds
- action: block
- status: 429

Run a burst:

```bash
for i in 1 2 3 4 5 6 7; do
  curl -i -H 'Host: demo.localhost' http://localhost:8080/login
done
```

Expected:

```text
first requests: HTTP 200
later request:  HTTP 429
```

`demo-requests.sh` prints each status and expects the final request to be
`429`.

## Query Events

The request script queries recent events:

```bash
curl -s 'http://localhost:8081/v1/events?app_id=<app_id>&host=demo.localhost&limit=10' \
  -H 'Authorization: Bearer local_dev_admin_key_change_me' \
  -H 'X-Bedem-Tenant-ID: <tenant_id>'
```

Expected event summary output:

```text
<timestamp> <request_id> block enforced=false would_block=true demo.localhost/admin rule=rule-admin-office-only
<timestamp> <request_id> block enforced=true would_block=true demo.localhost/admin rule=rule-admin-office-only
<timestamp> <request_id> block enforced=true would_block=true demo.localhost/login rule=rl-login-demo
```

ClickHouse inserts are asynchronous. If the script reports no events yet, wait a
few seconds and run:

```bash
./scripts/demo-requests.sh
```

or search in the dashboard Events page.

## Reset Or Rerun

Reset all local demo state:

```bash
./scripts/demo-reset.sh
```

Seed a new demo without destroying volumes:

```bash
./scripts/demo-seed.sh
```

Run only the request walkthrough:

```bash
./scripts/demo-requests.sh
```

## Files

- `scripts/demo-reset.sh`: reset volumes, start stack, seed demo.
- `scripts/demo-seed.sh`: create tenant, app, count-mode policy, publish.
- `scripts/demo-requests.sh`: exercise count mode, block mode, rate limit, and
  event search.
- `.demo.env`: generated local state file; do not commit it.
