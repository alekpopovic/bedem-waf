"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { AppShell } from "../../components/AppShell";
import { EmptyState, ErrorState, LoadingState } from "../../components/State";
import type { WafEvent } from "../../lib/types";
import { actionClass, formatDate, useApiClient } from "../../lib/hooks";

export default function DashboardPage() {
  const client = useApiClient();
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!client) {
      return;
    }
    setLoading(true);
    client
      .searchEvents({ limit: 1000 })
      .then(setEvents)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load dashboard"))
      .finally(() => setLoading(false));
  }, [client]);

  const blocked = events.filter((event) => event.action === "block" || event.action === "rate_limit");
  const topHosts = useMemo(() => topCounts(events.map((event) => event.host).filter(Boolean)), [events]);
  const topRules = useMemo(() => topCounts(events.map((event) => event.matched_rule_id).filter(Boolean)), [events]);

  return (
    <AppShell>
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Overview</h1>
          <p className="page-description">Recent WAF traffic and blocking activity from ClickHouse events.</p>
        </div>
        <Link className="button" href="/events">
          Search events
        </Link>
      </div>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}

      {!loading && !error ? (
        <div className="grid">
          <div className="grid cols-4">
            <Metric label="Total requests" value={events.length} />
            <Metric label="Blocked requests" value={blocked.length} />
            <Metric label="Count mode events" value={events.filter((event) => event.action === "count").length} />
            <Metric label="Unique hosts" value={new Set(events.map((event) => event.host)).size} />
          </div>

          <div className="grid cols-2">
            <TopList title="Top attacked hosts" items={topHosts} />
            <TopList title="Top matched rules" items={topRules} />
          </div>

          <section className="card">
            <h2 className="section-title">Recent blocks</h2>
            {blocked.length === 0 ? (
              <EmptyState message="No recent block events found." />
            ) : (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Host</th>
                      <th>Path</th>
                      <th>Action</th>
                      <th>Rule</th>
                      <th>IP</th>
                    </tr>
                  </thead>
                  <tbody>
                    {blocked.slice(0, 8).map((event) => (
                      <tr key={event.request_id}>
                        <td>{formatDate(event.timestamp)}</td>
                        <td>{event.host}</td>
                        <td>{event.path}</td>
                        <td>
                          <span className={actionClass(event.action)}>{event.action}</span>
                        </td>
                        <td>{event.matched_rule_id || "-"}</td>
                        <td>{event.client_ip}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      ) : null}
    </AppShell>
  );
}

function Metric({ label, value }: Readonly<{ label: string; value: number }>) {
  return (
    <div className="card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value.toLocaleString()}</div>
    </div>
  );
}

function TopList({ title, items }: Readonly<{ title: string; items: Array<[string, number]> }>) {
  return (
    <section className="card">
      <h2 className="section-title">{title}</h2>
      {items.length === 0 ? (
        <p className="muted">No data yet.</p>
      ) : (
        <table>
          <tbody>
            {items.map(([label, count]) => (
              <tr key={label}>
                <td>{label}</td>
                <td style={{ textAlign: "right" }}>{count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function topCounts(values: string[]): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
}
