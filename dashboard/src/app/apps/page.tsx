"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { AppShell } from "../../components/AppShell";
import { ErrorState, LoadingState } from "../../components/State";
import { useApiClient } from "../../lib/hooks";
import type { App, GatewayPolicy } from "../../lib/types";

type AppRow = App & { activePolicy?: GatewayPolicy | null };

export default function AppsPage() {
  const client = useApiClient();
  const [apps, setApps] = useState<AppRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!client) {
      return;
    }
    setLoading(true);
    client
      .listApps()
      .then(async (items) => {
        const withPolicies = await Promise.all(
          items.map(async (app) => ({
            ...app,
            activePolicy: await client.getActivePolicy(app.id).catch(() => null),
          })),
        );
        setApps(withPolicies);
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load apps"))
      .finally(() => setLoading(false));
  }, [client]);

  return (
    <AppShell>
      <div className="page-header">
        <div>
          <h1 className="page-title">Apps</h1>
          <p className="page-description">Protected hostnames and their active WAF policy state.</p>
        </div>
        <Link className="button" href="/apps/new">
          New app
        </Link>
      </div>
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error ? (
        <section className="card table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Hostname</th>
                <th>Mode</th>
                <th>Origin</th>
                <th>Active version</th>
              </tr>
            </thead>
            <tbody>
              {apps.map((app) => (
                <tr key={app.id}>
                  <td>
                    <Link href={`/apps/${app.id}`}>
                      <strong>{app.name}</strong>
                    </Link>
                    <div className="muted">{app.status}</div>
                  </td>
                  <td>{app.hostnames.join(", ")}</td>
                  <td>{app.activePolicy?.mode ?? "-"}</td>
                  <td>{app.activePolicy?.origin?.url ?? app.origins?.[0]?.url ?? "-"}</td>
                  <td>{app.activePolicy?.policy_version_id ?? app.activePolicy?.policy_id ?? "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
    </AppShell>
  );
}
