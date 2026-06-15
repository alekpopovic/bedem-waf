# Gateway WAF Rules

This directory contains the sample Coraza configuration for the BedemWAF gateway.

## Files

- `coraza.conf`: Minimal defensive Coraza configuration for MVP local testing.

## OWASP CRS

BedemWAF is designed to load OWASP CRS-compatible rule files through Coraza, but
CRS files are not vendored in this repository.

For Docker-based deployments, mount CRS files into the gateway container and
include them from `coraza.conf`.

Example mount layout:

```text
/etc/bedemwaf/crs/crs-setup.conf
/etc/bedemwaf/crs/rules/*.conf
```

Then configure:

```text
Include /etc/bedemwaf/crs/crs-setup.conf
Include /etc/bedemwaf/crs/rules/*.conf
```

## Safe Defaults

- Request body access is enabled.
- Response body access is disabled for MVP.
- `DetectionOnly` is the default sample mode.
- Full request bodies are never written to BedemWAF audit logs by default.
- The included smoke-test rule only checks `X-Bedem-Test: block-me`.
