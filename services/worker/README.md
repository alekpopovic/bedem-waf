# BedemWAF Worker

The worker handles asynchronous BedemWAF jobs.

Planned responsibilities:

- Process audit event enrichment jobs
- Run rule update workflows
- Run retention cleanup
- Support future scheduled maintenance tasks

TODO:

- Initialize Go module
- Choose queue and scheduling approach
- Define event enrichment pipeline
- Define retention policy jobs
- Add unit tests for job handlers
