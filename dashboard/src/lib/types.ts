export type Tenant = {
  id: string;
  name: string;
  slug: string;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Origin = {
  id?: string;
  name: string;
  scheme: string;
  host: string;
  port: number;
  url?: string;
};

export type App = {
  id: string;
  tenant_id: string;
  name: string;
  slug: string;
  hostnames: string[];
  status: string;
  origins?: Origin[];
  created_at: string;
  updated_at: string;
};

export type Policy = {
  id: string;
  tenant_id: string;
  app_id: string;
  name: string;
  mode: "count" | "block";
  enabled: boolean;
  active_version_id?: string;
  snapshot?: unknown;
  created_at: string;
  updated_at: string;
};

export type GatewayPolicy = {
  tenant_id: string;
  app_id: string;
  policy_id: string;
  policy_version_id: string;
  mode: "count" | "block";
  origin: Origin;
  ip_sets: Record<string, string[]>;
  custom_rules: unknown[];
  rate_limits: unknown[];
  waf: Record<string, unknown>;
  published_at?: string;
};

export type WafEvent = {
  timestamp: string;
  request_id: string;
  tenant_id: string;
  app_id: string;
  policy_id: string;
  policy_version_id: string;
  host: string;
  client_ip: string;
  method: string;
  path: string;
  action: string;
  mode: string;
  enforced: boolean;
  would_block: boolean;
  status: number;
  reason: string;
  matched_rule_id: string;
  matched_rule_name: string;
  rule_group: string;
  tags: string[];
  anomaly_score: number;
  user_agent: string;
  latency_ms: number;
  origin_status: number;
  origin_latency_ms: number;
};

export type RuleSimulationSummary = {
  rule_id: string;
  rule_name: string;
  would_block_count: number;
  unique_ips: number;
  top_paths: string[];
  sample_request_ids: string[];
};

export type PolicySimulationSummary = {
  policy_id: string;
  from?: string;
  to?: string;
  rules: RuleSimulationSummary[];
};

export type CreateAppInput = {
  tenant_id: string;
  name: string;
  slug: string;
  hostnames: string[];
  origin_url: string;
};

export type CreatePolicyInput = {
  name: string;
  mode: "count" | "block";
  snapshot: unknown;
};

export type UpdatePolicyInput = {
  expected_updated_at: string;
  name?: string;
  mode?: "count" | "block";
  enabled?: boolean;
  snapshot?: unknown;
};
