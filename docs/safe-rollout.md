# Safe Policy Rollout

BedemWAF policies are designed to move from observation to enforcement. New
policies and managed rule updates should start in count mode, generate audit
events, and only move to block mode after review.

## Modes

```text
count mode:
  evaluate rules
  emit would_block=true for disruptive matches
  enforced=false
  proxy request to origin

block mode:
  evaluate rules
  emit would_block=true for disruptive matches
  enforced=true
  return block/rate-limit response
```

Policy modes:

- `count`: record what would have happened, but do not block WAF, custom rule,
  or rate-limit matches.
- `block`: enforce disruptive rule actions.

Rule actions:

- `allow`: allow matching traffic. A terminal allow rule can short-circuit later
  block rules.
- `count`: record a match without blocking.
- `block`: disruptive action that is observed in count mode and enforced in
  block mode.

Rate-limit actions:

- `count`: record over-limit traffic without blocking.
- `block`: return the configured rate-limit status in block mode.

## Audit Event Semantics

Events separate rule intent from enforcement:

- `action`: rule decision intent, such as `allow`, `count`, `block`, or
  `rate_limit`.
- `mode`: active policy mode, `count` or `block`.
- `would_block`: `true` when the rule decision is disruptive.
- `enforced`: `true` when BedemWAF actually denied the request.

Example count-mode block match:

```json
{
  "action": "block",
  "mode": "count",
  "would_block": true,
  "enforced": false,
  "matched_rule_id": "rule-admin"
}
```

Example block-mode block match:

```json
{
  "action": "block",
  "mode": "block",
  "would_block": true,
  "enforced": true,
  "matched_rule_id": "rule-admin"
}
```

## Simulation Summary

The Control API exposes a policy simulation summary:

```http
GET /v1/policies/{policy_id}/simulation-summary?from=2026-06-16T10:00:00Z&to=2026-06-16T11:00:00Z
```

The response groups `would_block=true` events by rule:

```json
{
  "policy_id": "policy-1",
  "rules": [
    {
      "rule_id": "rule-admin",
      "rule_name": "Admin block",
      "would_block_count": 42,
      "unique_ips": 12,
      "top_paths": ["/admin", "/admin/users"],
      "sample_request_ids": ["req-1", "req-2"]
    }
  ]
}
```

## Recommended Workflow

1. Create or update a policy with `mode: "count"`.
2. Publish the policy.
3. Let representative traffic run through the gateway.
4. Review audit events and simulation summaries.
5. Tune custom rules, IP sets, WAF rules, and rate limits.
6. Publish again in count mode after tuning.
7. Switch to `mode: "block"` only when expected matches are understood.
8. Monitor `enforced=true` events after rollout.

## Safety Notes

- Do not switch new managed rule versions directly to block mode.
- Keep request bodies out of logs.
- Use sample request IDs from simulation summaries for investigation.
- Treat high-cardinality or noisy rules as count-only until reviewed.
