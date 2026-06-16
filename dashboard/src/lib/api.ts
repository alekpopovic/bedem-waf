import type {
  App,
  CreateAppInput,
  CreatePolicyInput,
  GatewayPolicy,
  PolicySimulationSummary,
  Policy,
  Tenant,
  UpdatePolicyInput,
  WafEvent,
} from "./types";

const API_KEY_STORAGE = "bedemwaf.admin_api_key";

export function getControlApiUrl(): string {
  return process.env.NEXT_PUBLIC_CONTROL_API_URL ?? "http://localhost:8081";
}

export function getStoredApiKey(): string {
  if (typeof window === "undefined") {
    return "";
  }
  return window.localStorage.getItem(API_KEY_STORAGE) ?? "";
}

export function setStoredApiKey(value: string): void {
  window.localStorage.setItem(API_KEY_STORAGE, value);
}

export function clearStoredApiKey(): void {
  window.localStorage.removeItem(API_KEY_STORAGE);
}

export type EventFilters = {
  tenant_id?: string;
  app_id?: string;
  host?: string;
  action?: string;
  client_ip?: string;
  matched_rule_id?: string;
  from?: string;
  to?: string;
  limit?: number;
};

type ApiErrorBody = {
  error?: {
    code?: string;
    message?: string;
    request_id?: string;
  };
};

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId?: string;

  constructor(status: number, code: string, message: string, requestId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

export class ControlApiClient {
  private readonly baseUrl: string;
  private readonly apiKey: string;

  constructor(apiKey: string, baseUrl = getControlApiUrl()) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl.replace(/\/$/, "");
  }

  async listTenants(): Promise<Tenant[]> {
    const body = await this.request<{ tenants: Tenant[] }>("/v1/tenants");
    return body.tenants;
  }

  async listApps(): Promise<App[]> {
    const body = await this.request<{ apps: App[] }>("/v1/apps");
    return body.apps;
  }

  async createApp(input: CreateAppInput): Promise<App> {
    return this.request<App>("/v1/apps", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async getApp(id: string): Promise<App> {
    return this.request<App>(`/v1/apps/${encodeURIComponent(id)}`);
  }

  async listPolicies(appId: string): Promise<Policy[]> {
    const body = await this.request<{ policies: Policy[] }>(`/v1/apps/${encodeURIComponent(appId)}/policies`);
    return body.policies;
  }

  async createPolicy(appId: string, input: CreatePolicyInput): Promise<Policy> {
    return this.request<Policy>(`/v1/apps/${encodeURIComponent(appId)}/policies`, {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async getPolicy(policyId: string): Promise<Policy> {
    return this.request<Policy>(`/v1/policies/${encodeURIComponent(policyId)}`);
  }

  async updatePolicy(policyId: string, input: UpdatePolicyInput): Promise<Policy> {
    return this.request<Policy>(`/v1/policies/${encodeURIComponent(policyId)}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    });
  }

  async publishPolicy(policyId: string): Promise<{ policy_version_id: string; version: number; published_at: string }> {
    return this.request(`/v1/policies/${encodeURIComponent(policyId)}/publish`, {
      method: "POST",
    });
  }

  async getPolicySimulationSummary(policyId: string, filters: Pick<EventFilters, "from" | "to"> = {}): Promise<PolicySimulationSummary> {
    const params = new URLSearchParams();
    if (filters.from) {
      params.set("from", filters.from);
    }
    if (filters.to) {
      params.set("to", filters.to);
    }
    const suffix = params.toString() ? `?${params.toString()}` : "";
    return this.request<PolicySimulationSummary>(`/v1/policies/${encodeURIComponent(policyId)}/simulation-summary${suffix}`);
  }

  async getActivePolicy(appId: string): Promise<GatewayPolicy> {
    return this.request<GatewayPolicy>(`/v1/apps/${encodeURIComponent(appId)}/active-policy`);
  }

  async searchEvents(filters: EventFilters = {}): Promise<WafEvent[]> {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== "") {
        params.set(key, String(value));
      }
    }
    const suffix = params.toString() ? `?${params.toString()}` : "";
    const body = await this.request<{ events: WafEvent[] }>(`/v1/events${suffix}`);
    return body.events;
  }

  async getEvent(requestId: string): Promise<WafEvent> {
    return this.request<WafEvent>(`/v1/events/${encodeURIComponent(requestId)}`);
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      ...init,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        ...init.headers,
      },
    });

    if (!response.ok) {
      let errorBody: ApiErrorBody = {};
      try {
        errorBody = (await response.json()) as ApiErrorBody;
      } catch {
        // Keep generic error below.
      }
      throw new ApiError(
        response.status,
        errorBody.error?.code ?? "request_failed",
        errorBody.error?.message ?? `Request failed with status ${response.status}`,
        errorBody.error?.request_id,
      );
    }

    return (await response.json()) as T;
  }
}
