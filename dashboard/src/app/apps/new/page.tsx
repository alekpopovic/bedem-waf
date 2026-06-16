"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useState } from "react";
import { AppShell } from "../../../components/AppShell";
import { ErrorState, LoadingState } from "../../../components/State";
import { slugFromHost, useApiClient } from "../../../lib/hooks";
import type { Tenant } from "../../../lib/types";

export default function NewAppPage() {
  const client = useApiClient();
  const router = useRouter();
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [tenantId, setTenantId] = useState("");
  const [hostname, setHostname] = useState("");
  const [originUrl, setOriginUrl] = useState("");
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!client) {
      return;
    }
    client
      .listTenants()
      .then((items) => {
        setTenants(items);
        setTenantId(items[0]?.id ?? "");
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load tenants"))
      .finally(() => setLoading(false));
  }, [client]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!client) {
      return;
    }
    setSaving(true);
    setError("");
    try {
      const created = await client.createApp({
        tenant_id: tenantId,
        name: name.trim() || hostname,
        slug: slugFromHost(hostname),
        hostnames: [hostname.trim()],
        origin_url: originUrl.trim(),
      });
      router.push(`/apps/${created.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create app");
    } finally {
      setSaving(false);
    }
  }

  return (
    <AppShell>
      <div className="page-header">
        <div>
          <h1 className="page-title">New App</h1>
          <p className="page-description">Create a protected hostname and primary NGINX origin.</p>
        </div>
      </div>
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading ? (
        <form className="card form" onSubmit={submit}>
          <div className="field">
            <label htmlFor="tenant">Tenant</label>
            <select id="tenant" value={tenantId} onChange={(event) => setTenantId(event.target.value)} required>
              {tenants.map((tenant) => (
                <option key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="hostname">Hostname</label>
            <input id="hostname" value={hostname} onChange={(event) => setHostname(event.target.value)} placeholder="app.example.com" required />
          </div>
          <div className="field">
            <label htmlFor="origin">Origin URL</label>
            <input id="origin" value={originUrl} onChange={(event) => setOriginUrl(event.target.value)} placeholder="http://localhost:9000" required />
          </div>
          <div className="field">
            <label htmlFor="name">Display name</label>
            <input id="name" value={name} onChange={(event) => setName(event.target.value)} placeholder="Defaults to hostname" />
          </div>
          <button className="button" disabled={saving || !tenantId || !hostname || !originUrl} type="submit">
            {saving ? "Creating..." : "Create app"}
          </button>
        </form>
      ) : null}
    </AppShell>
  );
}
