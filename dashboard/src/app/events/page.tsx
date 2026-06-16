"use client";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { AppShell } from "../../components/AppShell";
import { ErrorState, LoadingState } from "../../components/State";
import type { App, WafEvent } from "../../lib/types";
import { actionClass, formatDate, useApiClient } from "../../lib/hooks";

export default function EventsPage() {
  const client = useApiClient();
  const [apps, setApps] = useState<App[]>([]);
  const [events, setEvents] = useState<WafEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [filters, setFilters] = useState({
    app_id: "",
    host: "",
    action: "",
    client_ip: "",
    matched_rule_id: "",
    from: "",
    to: "",
  });

  useEffect(() => {
    if (!client) {
      return;
    }
    void loadEvents();
    client.listApps().then(setApps).catch(() => setApps([]));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [client]);

  async function loadEvents() {
    if (!client) {
      return;
    }
    setLoading(true);
    setError("");
    try {
      const nextEvents = await client.searchEvents({
        ...filters,
        from: toRFC3339(filters.from),
        to: toRFC3339(filters.to),
        limit: 100,
      });
      setEvents(nextEvents);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to search events");
    } finally {
      setLoading(false);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void loadEvents();
  }

  return (
    <AppShell>
      <div className="page-header">
        <div>
          <h1 className="page-title">Events</h1>
          <p className="page-description">Search WAF audit events stored in ClickHouse.</p>
        </div>
      </div>

      <form className="card form" onSubmit={submit} style={{ maxWidth: "none", marginBottom: 16 }}>
        <div className="grid cols-4">
          <div className="field">
            <label>App</label>
            <select value={filters.app_id} onChange={(event) => setFilters({ ...filters, app_id: event.target.value })}>
              <option value="">All apps</option>
              {apps.map((app) => (
                <option key={app.id} value={app.id}>
                  {app.name}
                </option>
              ))}
            </select>
          </div>
          <Field label="Host" value={filters.host} onChange={(value) => setFilters({ ...filters, host: value })} />
          <div className="field">
            <label>Action</label>
            <select value={filters.action} onChange={(event) => setFilters({ ...filters, action: event.target.value })}>
              <option value="">Any</option>
              <option value="allow">allow</option>
              <option value="count">count</option>
              <option value="block">block</option>
              <option value="rate_limit">rate_limit</option>
            </select>
          </div>
          <Field label="Client IP" value={filters.client_ip} onChange={(value) => setFilters({ ...filters, client_ip: value })} />
        </div>
        <div className="grid cols-4">
          <Field label="Rule ID" value={filters.matched_rule_id} onChange={(value) => setFilters({ ...filters, matched_rule_id: value })} />
          <Field label="From" type="datetime-local" value={filters.from} onChange={(value) => setFilters({ ...filters, from: value })} />
          <Field label="To" type="datetime-local" value={filters.to} onChange={(value) => setFilters({ ...filters, to: value })} />
          <div className="field">
            <label>&nbsp;</label>
            <button className="button" type="submit">
              Search
            </button>
          </div>
        </div>
      </form>

      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {!loading && !error ? (
        <section className="card table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Host</th>
                <th>Path</th>
                <th>Action</th>
                <th>Rule</th>
                <th>IP</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.request_id}>
                  <td>
                    <Link href={`/events/${event.request_id}`}>{formatDate(event.timestamp)}</Link>
                  </td>
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
        </section>
      ) : null}
    </AppShell>
  );
}

function Field({
  label,
  value,
  onChange,
  type = "text",
}: Readonly<{
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
}>) {
  return (
    <div className="field">
      <label>{label}</label>
      <input type={type} value={value} onChange={(event) => onChange(event.target.value)} />
    </div>
  );
}

function toRFC3339(value: string): string {
  if (!value) {
    return "";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "";
  }
  return date.toISOString();
}
