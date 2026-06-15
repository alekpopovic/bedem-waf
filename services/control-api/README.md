# BedemWAF Control API

The control API is the REST management plane for BedemWAF.

Planned responsibilities:

- Manage tenants, apps, origins, policies, rule groups, IP sets, and rate limits
- Store configuration in Postgres
- Query WAF events from ClickHouse
- Provide OpenAPI documentation
- Validate all user input and return production-ready errors

TODO:

- Initialize Go module
- Choose router, validation, and migration tooling
- Define initial REST resources
- Add OpenAPI generation
- Add unit tests for validation and authorization boundaries
