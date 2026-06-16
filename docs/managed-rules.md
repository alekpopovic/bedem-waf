# Managed Rules

BedemWAF managed rules are versioned rule bundles that can be referenced by
policies. The MVP starts with OWASP CRS-compatible files mounted from a local
directory. It intentionally does not download rules from the internet by
default.

## MVP Scope

Included:

- Local managed rule set directory scanning by the worker.
- Version metadata from `ruleset.json`.
- Deterministic SHA-256 checksums over local rule files.
- Postgres records for managed rule sets and versions.
- Control API read endpoints for rule sets and versions.
- Activation endpoint placeholder that returns a manual-publish-required status.

Not included:

- Automatic remote downloads.
- Automatic policy activation.
- Executing rule files as code.
- Trusting downloaded content without operator review.

## Local Directory Layout

The local Docker Compose stack mounts `deployments/rules` into the worker at
`/rules`.

```text
deployments/rules/
  owasp-crs-local/
    ruleset.json
    REQUEST-901-INITIALIZATION.conf
    REQUEST-942-APPLICATION-ATTACK-SQLI.conf
```

`ruleset.json`:

```json
{
  "name": "OWASP CRS Local",
  "provider": "owasp",
  "source": "local",
  "version": "4.0.0-local",
  "description": "Local operator-reviewed CRS mirror",
  "enabled": true
}
```

The worker scans immediate child directories. If the configured root itself has
a `ruleset.json`, the root is treated as a single rule set.

## Worker Flow

```text
Local rules dir
      |
      v
Worker scan job
      |
      v
Parse ruleset.json -> hash rule files -> upsert metadata
      |
      v
Postgres managed_rule_sets / managed_rule_versions
      |
      v
Admin reviews version and publishes policy explicitly
```

The scanner reads metadata, includes `.conf`, `.data`, and `.txt` files in the
checksum, and records:

- rule set name
- provider
- source
- version
- local path
- checksum
- enabled flag
- ruleset snapshot with scanned files

## Control API

Administrative endpoints:

```http
GET /v1/managed-rule-sets
GET /v1/managed-rule-sets/{id}/versions
POST /v1/managed-rule-sets/{id}/versions/{version_id}/activate
```

The activate endpoint is a placeholder in MVP. It verifies that the version
exists and returns `202 Accepted` with `manual_policy_publish_required`. It does
not change gateway behavior.

## Manual Review Workflow

1. Place reviewed OWASP CRS-compatible files under `deployments/rules/<name>/`.
2. Add or update `ruleset.json`.
3. Start or restart the worker.
4. Confirm the rule set appears in `GET /v1/managed-rule-sets`.
5. Confirm the checksum and file list in `GET /v1/managed-rule-sets/{id}/versions`.
6. Review changes out of band.
7. Publish a policy that references the chosen managed rule version.
8. Start in count mode, review audit events, then move to block mode only after
   expected behavior is verified.

## Safety Notes

- No automatic remote downloads in MVP.
- Rule files are treated as data and are not executed by the worker.
- Checksums provide change detection, not trust by themselves.
- Production should require signed release metadata or a trusted artifact
  mirror before remote update automation is added.
- Managed rule versions should be activated through policy publishing, not by
  background jobs.
