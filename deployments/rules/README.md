# Local Managed Rules Directory

This directory is mounted into the worker at `/rules` by the local Docker
Compose stack.

MVP managed rules are local-only. BedemWAF does not download rules from the
internet automatically. To test an OWASP CRS-compatible rule set locally, place a
subdirectory here with a `ruleset.json` file and rule files.

Example layout:

```text
deployments/rules/
  owasp-crs-local/
    ruleset.json
    REQUEST-901-INITIALIZATION.conf
    REQUEST-942-APPLICATION-ATTACK-SQLI.conf
```

Example `ruleset.json`:

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

The worker scans the directory, computes a deterministic SHA-256 checksum over
rule file names and contents, and records metadata in Postgres. It does not
activate rules automatically. An administrator must explicitly publish a policy
that references the managed rule version.
