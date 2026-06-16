CREATE DATABASE IF NOT EXISTS bedemwaf;

CREATE TABLE IF NOT EXISTS bedemwaf.waf_events
(
    timestamp DateTime64(3, 'UTC'),
    request_id String,
    tenant_id String,
    app_id String,
    policy_id String,
    policy_version_id String,
    host String,
    client_ip String,
    method LowCardinality(String),
    path String,
    action LowCardinality(String),
    mode LowCardinality(String),
    enforced Bool,
    would_block Bool,
    status UInt16,
    reason String,
    matched_rule_id String,
    matched_rule_name String,
    rule_group String,
    tags Array(String),
    anomaly_score Int32,
    user_agent String,
    latency_ms UInt32,
    origin_status UInt16,
    origin_latency_ms UInt32
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, app_id, timestamp, request_id)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;
