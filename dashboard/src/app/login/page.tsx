"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";
import { getControlApiUrl, setStoredApiKey, setStoredTenantId } from "../../lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [apiKey, setApiKey] = useState("");
  const [tenantId, setTenantId] = useState("tenant-1");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!apiKey.trim() || !tenantId.trim()) {
      return;
    }
    setStoredApiKey(apiKey.trim());
    setStoredTenantId(tenantId.trim());
    router.replace("/dashboard");
  }

  return (
    <main className="login-page">
      <section className="card login-card">
        <div className="page-header">
          <div>
            <h1 className="page-title">BedemWAF</h1>
            <p className="page-description">Admin dashboard sign in</p>
          </div>
        </div>
        <div className="notice">
          Development mode only: the admin API key is stored in browser localStorage. TODO: replace this with proper
          session authentication and CSRF protection before production use.
        </div>
        <form className="form" onSubmit={submit} style={{ marginTop: 18 }}>
          <div className="field">
            <label htmlFor="api-key">Admin API key</label>
            <input
              id="api-key"
              autoComplete="off"
              placeholder="BEDEMWAF_ADMIN_API_KEY"
              type="password"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
            />
          </div>
          <div className="field">
            <label>Control API</label>
            <input readOnly value={getControlApiUrl()} />
          </div>
          <div className="field">
            <label htmlFor="tenant-id">Tenant ID</label>
            <input id="tenant-id" placeholder="tenant UUID or demo tenant id" value={tenantId} onChange={(event) => setTenantId(event.target.value)} />
          </div>
          <button className="button" type="submit" disabled={!apiKey.trim() || !tenantId.trim()}>
            Continue
          </button>
        </form>
      </section>
    </main>
  );
}
