"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { AppShell } from "../../../components/AppShell";
import { ErrorState, LoadingState } from "../../../components/State";
import { actionClass, formatDate, useApiClient } from "../../../lib/hooks";
import type { WafEvent } from "../../../lib/types";

export default function EventDetailPage() {
  const { request_id: requestId } = useParams<{ request_id: string }>();
  const client = useApiClient();
  const [event, setEvent] = useState<WafEvent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!client || !requestId) {
      return;
    }
    setLoading(true);
    client
      .getEvent(requestId)
      .then(setEvent)
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load event"))
      .finally(() => setLoading(false));
  }, [client, requestId]);

  return (
    <AppShell>
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {event ? (
        <div className="grid">
          <div className="page-header">
            <div>
              <h1 className="page-title">Event {event.request_id}</h1>
              <p className="page-description">{formatDate(event.timestamp)}</p>
            </div>
            <span className={actionClass(event.action)}>{event.action}</span>
          </div>

          <div className="grid cols-4">
            <Detail label="Host" value={event.host} />
            <Detail label="Path" value={event.path} />
            <Detail label="Client IP" value={event.client_ip} />
            <Detail label="Status" value={String(event.status)} />
          </div>

          <section className="card">
            <h2 className="section-title">Matched rule</h2>
            <p>{event.matched_rule_id || "-"}</p>
            <p className="muted">{event.matched_rule_name || event.reason || "No rule metadata"}</p>
          </section>

          <section className="card">
            <h2 className="section-title">Full event details</h2>
            <p className="muted">Request bodies are not stored. Sensitive fields are redacted before event storage.</p>
            <pre className="code-block">{JSON.stringify(event, null, 2)}</pre>
          </section>
        </div>
      ) : null}
    </AppShell>
  );
}

function Detail({ label, value }: Readonly<{ label: string; value: string }>) {
  return (
    <div className="card">
      <div className="metric-label">{label}</div>
      <div style={{ marginTop: 8, overflowWrap: "anywhere" }}>{value || "-"}</div>
    </div>
  );
}
