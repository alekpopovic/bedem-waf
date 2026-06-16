# Production Readiness Checklist

BedemWAF is not production-ready by default. This checklist is the minimum gate
before putting the gateway in front of real applications. Treat unchecked items
as blockers unless a risk owner explicitly accepts them.

Status markers:

- `[ ]` Required before production.
- `[x]` Implemented or available in the current MVP.
- `TODO:` Known gap that needs implementation, automation, or an operational
  runbook.

## 1. Network

- [ ] Origin accepts traffic only from BedemWAF Gateway IPs, private subnets, or
  a dedicated load balancer security group.
- [ ] Direct public access to NGINX origins is blocked by firewall, cloud
  security group, Kubernetes NetworkPolicy, or equivalent control.
- [ ] Admin Control API is not publicly exposed.
- [ ] Dashboard is behind VPN, SSO, reverse proxy auth, or private network
  access.
- [ ] TLS is configured for all public tenant hostnames.
- [ ] TLS is configured for Dashboard and Control API outside local
  development.
- [ ] HTTP-to-HTTPS redirect is configured where applicable.
- [ ] HSTS is enabled only after all tenant hostnames are confirmed HTTPS-ready.
- [x] Gateway validates and normalizes Host headers before policy lookup.
- [x] Gateway trusts `X-Forwarded-For` only when the direct peer matches a
  configured trusted proxy CIDR.

TODO gaps:

- TODO: Add production deployment examples for origin lock-down in Kubernetes,
  Docker, and common cloud load balancers.
- TODO: Add first-class TLS listener/certificate configuration for gateway
  deployments that terminate TLS directly.

## 2. Secrets

- [ ] Admin API keys are stored in a secret manager or orchestrator secret
  store, not in plaintext deployment manifests.
- [ ] Gateway API keys are stored in a secret manager or orchestrator secret
  store.
- [ ] Dashboard session secrets are generated per environment and stored in a
  secret manager.
- [ ] `.env` files containing real values are excluded from git and deployment
  artifacts.
- [x] Repository includes only placeholder secrets in `.env.example`.
- [ ] Key rotation process is documented and tested.
- [ ] Rotation includes gateway API keys, admin/API automation keys, database
  credentials, dashboard session secrets, and Grafana credentials.
- [ ] API keys have owners, expiration dates, and last-used audit metadata.

TODO gaps:

- TODO: Replace MVP static bearer tokens with scoped, hashed, expiring API keys
  and dashboard session authentication.
- TODO: Implement a documented key rotation runbook and API.
- TODO: Add automated secret scanning in CI if repository hosting does not
  already enforce it.

## 3. Data

- [ ] Postgres backups are scheduled, encrypted, and monitored.
- [ ] Postgres restore is tested in a non-production environment.
- [ ] ClickHouse retention policy is defined per environment and tenant class.
- [ ] ClickHouse disk growth alerts are configured.
- [ ] ClickHouse backups are configured if audit retention requirements require
  recovery after data loss.
- [x] Gateway audit logging redacts sensitive query parameters.
- [x] Gateway redaction helpers remove sensitive headers such as
  `Authorization` and `Cookie`.
- [x] Full request body logging is disabled by default.
- [x] Body preview logging is opt-in and should remain disabled in production
  unless an incident procedure explicitly enables it for a short period.
- [ ] Logs and audit events are classified as security telemetry and protected
  from broad access.

TODO gaps:

- TODO: Implement worker retention cleanup for ClickHouse.
- TODO: Add tenant-level retention settings and enforcement.
- TODO: Add backup and restore runbooks for Postgres and ClickHouse.

## 4. Availability

- [ ] Multiple gateway replicas are deployed across failure domains.
- [ ] Gateway replicas are behind a production load balancer.
- [x] Gateway, Control API, Dashboard, databases, demo services, Prometheus, and
  Grafana have local Compose healthchecks where practical.
- [ ] Production readiness/liveness probes are configured in the target
  orchestrator.
- [ ] Redis is deployed in HA mode, or the deployment explicitly accepts
  fail-open rate limiting during Redis outages.
- [x] Gateway rate limiting supports configurable Redis fail-open/fail-closed
  behavior.
- [x] Gateway remote policy loading supports stale-cache and fail-open/fail-closed
  behavior.
- [ ] Control API failure policy is documented for gateway operators.
- [ ] Gateway policy cache TTL and stale policy behavior are reviewed for each
  environment.
- [ ] Database connection pool limits are sized and monitored.

TODO gaps:

- TODO: Add production deployment manifests with replica counts, probes, resource
  requests, and pod disruption budgets.
- TODO: Add a gateway readiness endpoint that reports policy cache and backend
  dependency health without exposing secrets.
- TODO: Add operational runbook for Control API outage behavior.

## 5. Security

- [ ] New policies and managed rule updates are tuned in count mode before block
  mode.
- [x] Gateway records `would_block` and `enforced` event fields for safe rollout.
- [ ] Admin access audit logs are retained and reviewed.
- [ ] Dashboard authentication is implemented with secure sessions, MFA/SSO
  support, CSRF protection, and secure cookies.
- [ ] Role-based access control is implemented for tenant admins, read-only
  users, and platform operators.
- [ ] Database users follow least privilege: runtime users cannot run schema
  migrations; migration users are not used by services.
- [ ] Dependency scanning is enabled for Go, npm, container images, and GitHub
  Actions.
- [ ] Container images are rebuilt regularly and pinned to trusted registries.
- [ ] Security headers are verified on the dashboard and any reverse proxy.
- [ ] Admin API rate limiting is enforced before exposing the API outside a
  private network.

TODO gaps:

- TODO: Replace dashboard localStorage API-key login with production session
  auth.
- TODO: Implement persistent admin API rate limiting.
- TODO: Implement admin audit logs for tenant/app/policy/API-key changes.
- TODO: Add RBAC and least-privilege service tokens.
- TODO: Review and address current dependency scanning findings before any
  production claim.

## 6. Observability

- [x] Gateway exposes Prometheus metrics at `/metrics`.
- [x] Control API exposes Prometheus metrics at `/metrics`.
- [x] Worker exposes Prometheus metrics on `BEDEMWAF_WORKER_METRICS_ADDR`.
- [x] Local Docker Compose includes an optional Prometheus/Grafana profile.
- [x] Gateway exports `bedem_policy_fetch_errors_total` for policy fetch
  failure alerts.
- [ ] Production Prometheus scrapes gateway, Control API, and worker metrics
  from private networks only.
- [ ] Alert for high block rate by app and reason.
- [ ] Alert for sustained `bedem_audit_events_dropped_total` increases.
- [ ] Alert for policy fetch failures and stale policy fallback.
- [ ] Alert for Redis, Postgres, ClickHouse, Control API, and gateway health
  failures.
- [ ] Alert for elevated gateway and origin latency.
- [ ] Centralized structured logs are available with `request_id` correlation.
- [ ] Metrics labels are reviewed to avoid secrets and high-cardinality values.

TODO gaps:

- TODO: Add production alert rule examples for Prometheus/Alertmanager.
- TODO: Expand the placeholder Grafana dashboard with request, block,
  rate-limit, policy-cache, audit-drop, Control API, and worker panels.

## 7. Upgrade

- [ ] Managed rules review process is documented and assigned to an owner.
- [x] Managed rules updater MVP scans local rule directories and records version
  metadata without automatically activating rules.
- [ ] Managed rules checksums are reviewed before policy publication.
- [ ] Rollback procedure exists for application deployment, gateway deployment,
  and managed rule updates.
- [ ] Policy version rollback is documented and tested.
- [ ] Database migration rollback plan is documented for each release.
- [ ] Upgrade testing includes count-mode simulation before block-mode
  enforcement.
- [ ] Release notes identify changed rule sets, schema changes, and operator
  actions.

TODO gaps:

- TODO: Implement explicit policy version rollback API and dashboard action.
- TODO: Add managed rule review checklist and approval workflow.
- TODO: Add release checklist covering database migrations, gateway rollout,
  dashboard compatibility, and worker jobs.

## Release Sign-Off

Before production traffic is routed through BedemWAF, record:

- Environment name and owner.
- Application/tenant list.
- Gateway version and image digest.
- Control API version and image digest.
- Dashboard version and image digest.
- Worker version and image digest.
- Active policy IDs and policy version IDs.
- Redis fail behavior.
- Control API policy cache fail behavior.
- Backup status and latest restore test date.
- Monitoring dashboard link.
- Alert receiver/on-call owner.
- Known accepted risks.

Do not mark BedemWAF production-ready while TODO gaps remain unresolved unless
the deployment owner documents explicit compensating controls.
