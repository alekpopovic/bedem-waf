# Observability

BedemWAF exposes Prometheus metrics and structured JSON logs for local
development and production monitoring. Metrics are intentionally low-cardinality
and must not include secrets, request bodies, cookies, authorization headers, or
raw API keys.

## Metrics Endpoints

MVP endpoints:

| Service | Endpoint | Notes |
| --- | --- | --- |
| Gateway | `GET /metrics` on the gateway listener | Same port as `/healthz` and proxied traffic. |
| Control API | `GET /metrics` on the API listener | No admin or gateway bearer token required. |
| Worker | `GET /metrics` on `BEDEMWAF_WORKER_METRICS_ADDR` | Defaults to `:9092`. |

Do not expose these endpoints directly to the public internet. In production,
bind metrics to private networks, scrape them from Prometheus, and restrict
access with network policy or service mesh controls.

## Gateway Metrics

The gateway records:

- `bedem_requests_total{app_id,host,action}`: request decisions by app, host,
  and final action.
- `bedem_blocked_requests_total{app_id,reason}`: blocked or error responses by
  app and reason.
- `bedem_request_duration_seconds`: end-to-end gateway request latency.
- `bedem_origin_duration_seconds`: reverse proxy upstream latency.
- `bedem_policy_cache_hits_total`: remote policy cache hits.
- `bedem_policy_cache_misses_total`: remote policy cache misses.
- `bedem_rate_limited_total`: requests that matched a rate limit rule.
- `bedem_audit_events_dropped_total`: audit events dropped because the async
  queue was full.

Labels intentionally avoid client IP, user agent, paths, authorization headers,
and request bodies.

## Control API Metrics

The Control API records:

- `bedem_control_api_requests_total{method,status}`: API request count by HTTP
  method and status.
- `bedem_control_api_request_duration_seconds`: API request latency.
- `bedem_control_api_errors_total{status}`: API error responses by status code.

Control API structured logs include `request_id`, method, path, status, and
latency. They do not log bearer tokens or request bodies.

## Worker Metrics

The worker records:

- `bedem_worker_jobs_total{job}`: background job attempts.
- `bedem_worker_job_errors_total{job}`: background job failures.

The initial job label is `managed_rules_scan`.

## Local Prometheus And Grafana

Start the normal local stack:

```bash
./scripts/dev-up.sh
```

Enable the optional observability profile from `deployments/`:

```bash
docker compose --env-file ../.env.example --profile observability up -d prometheus grafana
```

Local URLs:

- Prometheus: http://localhost:9090
- Grafana: http://localhost:3001

The local Grafana username/password defaults to `admin` / `admin` from
`.env.example`. These are development placeholders only. Replace them anywhere
outside local development.

Prometheus scrape config lives at:

```text
deployments/prometheus/prometheus.yml
```

The placeholder Grafana dashboard lives at:

```text
deployments/grafana/dashboards/bedemwaf-overview.json
```

## Production Notes

- Run Prometheus and Grafana on private management networks.
- Protect `/metrics` endpoints from internet traffic.
- Alert on high `bedem_blocked_requests_total`, sustained
  `bedem_audit_events_dropped_total`, high request latency, policy cache miss
  spikes, and worker job failures.
- Keep labels bounded. Do not add raw path, query, IP, token, cookie, or header
  value labels without a cardinality and privacy review.
- Correlate metrics with audit events through `request_id` in logs and events,
  not through sensitive metric labels.
