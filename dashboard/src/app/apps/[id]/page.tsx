"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { AppShell } from "../../../components/AppShell";
import { ErrorState, LoadingState } from "../../../components/State";
import { formatDate, useApiClient } from "../../../lib/hooks";
import type { App, GatewayPolicy, Policy } from "../../../lib/types";

export default function AppDetailPage() {
  const { id } = useParams<{ id: string }>();
  const client = useApiClient();
  const [app, setApp] = useState<App | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [activePolicy, setActivePolicy] = useState<GatewayPolicy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!client || !id) {
      return;
    }
    setLoading(true);
    Promise.all([
      client.getApp(id),
      client.listPolicies(id),
      client.getActivePolicy(id).catch(() => null),
    ])
      .then(([nextApp, nextPolicies, nextActive]) => {
        setApp(nextApp);
        setPolicies(nextPolicies);
        setActivePolicy(nextActive);
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load app"))
      .finally(() => setLoading(false));
  }, [client, id]);

  return (
    <AppShell>
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {app ? (
        <div className="grid">
          <div className="page-header">
            <div>
              <h1 className="page-title">{app.name}</h1>
              <p className="page-description">{app.hostnames.join(", ")}</p>
            </div>
            <Link className="button" href={`/apps/${app.id}/policy`}>
              Edit policy
            </Link>
          </div>

          <div className="grid cols-2">
            <section className="card">
              <h2 className="section-title">Origin</h2>
              <p>{activePolicy?.origin?.url ?? app.origins?.[0]?.url ?? "-"}</p>
              <p className="muted">Created {formatDate(app.created_at)}</p>
            </section>
            <section className="card">
              <h2 className="section-title">Active policy</h2>
              <p>Mode: {activePolicy?.mode ?? "-"}</p>
              <p>Version: {activePolicy?.policy_version_id ?? "-"}</p>
            </section>
          </div>

          <section className="card table-wrap">
            <h2 className="section-title">Policy drafts</h2>
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Mode</th>
                  <th>Enabled</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {policies.map((policy) => (
                  <tr key={policy.id}>
                    <td>{policy.name}</td>
                    <td>{policy.mode}</td>
                    <td>{policy.enabled ? "yes" : "no"}</td>
                    <td>{formatDate(policy.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      ) : null}
    </AppShell>
  );
}
