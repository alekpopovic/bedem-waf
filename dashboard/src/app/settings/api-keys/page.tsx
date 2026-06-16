"use client";

import { AppShell } from "../../../components/AppShell";

export default function ApiKeysPage() {
  return (
    <AppShell>
      <div className="page-header">
        <div>
          <h1 className="page-title">API Keys</h1>
          <p className="page-description">Placeholder for scoped Control API and Gateway API key management.</p>
        </div>
      </div>
      <section className="card">
        <h2 className="section-title">MVP status</h2>
        <p className="muted">
          BedemWAF currently uses static development keys from environment variables. TODO: add hashed key creation,
          scoped permissions, expiration, rotation, and one-time plaintext display.
        </p>
      </section>
    </AppShell>
  );
}
