# BedemWAF Gateway

The gateway is the HTTP data plane for BedemWAF. The MVP gateway accepts HTTP
requests, identifies the protected app by `Host`, evaluates an in-memory policy,
optionally checks Redis-backed rate limits, inspects requests with Coraza when
enabled, emits structured JSON audit logs, and reverse proxies allowed traffic to
the configured NGINX origin.

## Run Locally

Start a simple origin:

```bash
python3 -m http.server 9000
```

Run the gateway:

```bash
go run ./cmd/gateway -config config.example.yaml
```

Send a request:

```bash
curl -H 'Host: localhost' http://localhost:8080/
```

Validate the sample Coraza rule:

```bash
curl -i -H 'Host: localhost' -H 'X-Bedem-Test: block-me' http://localhost:8080/
```

With the sample config, Coraza runs in `DetectionOnly` and the app policy runs in
`count`, so the request is logged as a would-block event but still reaches the
origin. To enforce a `403`, set `waf.rule_engine` to `On` and change the app
policy mode to `block`.

## Configuration

See [config.example.yaml](config.example.yaml).

Important defaults:

- `server.listen_addr` defaults to `:8080`.
- Client IP comes from `RemoteAddr` by default.
- `X-Forwarded-For` is only trusted when `server.trusted_proxies` is configured
  and the immediate peer IP matches that list.
- Policy mode defaults to `count`.
- Redis rate limiting is disabled unless `redis.enabled` is `true`.
- Coraza runs when `waf.enabled` is `true`.
- `waf.rule_engine` defaults to `DetectionOnly`.
- Request bodies are read only up to `waf.request_body_limit_bytes`, then
  restored before proxying.
- Full request bodies are never logged.

## Audit Logs

Audit events are newline-delimited JSON written to stdout. They include:

- `timestamp`
- `request_id`
- `app_id`
- `host`
- `client_ip`
- `method`
- `path`
- `action`
- `mode`
- `status`
- `reason`
- `matched_rule_id`
- `user_agent`
- `latency_ms`

Request bodies are not logged.

## Coraza Rules

The sample rules live in [rules/coraza.conf](rules/coraza.conf).

To use OWASP CRS-compatible rules, mount CRS into the gateway container and
uncomment the placeholder `Include` lines in `rules/coraza.conf`. See
[rules/README.md](rules/README.md).

## Tests

```bash
go test ./...
```

## TODO

- Add hot policy reload from the control plane.
- Add richer Redis rate-limit keys.
- Add Prometheus metrics.
