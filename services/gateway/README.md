# BedemWAF Gateway

The gateway is the HTTP data plane for BedemWAF.

Planned responsibilities:

- Reverse proxy traffic to configured NGINX origins
- Inspect requests with Coraza and OWASP CRS-compatible rules
- Support count and block policy modes
- Apply IP set and rate-limit decisions
- Emit structured, redacted audit events asynchronously

TODO:

- Initialize Go module
- Add configuration loading
- Add reverse proxy skeleton
- Add Coraza integration
- Add unit tests for policy decision logic
