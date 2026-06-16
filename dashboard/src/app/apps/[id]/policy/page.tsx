"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import { AppShell } from "../../../../components/AppShell";
import { ErrorState, LoadingState } from "../../../../components/State";
import { useApiClient } from "../../../../lib/hooks";
import type { Policy } from "../../../../lib/types";

const defaultSnapshot = {
  mode: "count",
  ip_sets: {},
  custom_rules: [],
  rate_limits: [],
  waf: {
    enabled: true,
    engine: "coraza",
    rule_engine: "DetectionOnly",
  },
};

export default function PolicyEditorPage() {
  const { id } = useParams<{ id: string }>();
  const client = useApiClient();
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [jsonText, setJsonText] = useState(JSON.stringify(defaultSnapshot, null, 2));
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!client || !id) {
      return;
    }
    setLoading(true);
    client
      .listPolicies(id)
      .then(async (policies) => {
        if (policies[0]) {
          const fullPolicy = await client.getPolicy(policies[0].id);
          setPolicy(fullPolicy);
          setJsonText(JSON.stringify(fullPolicy.snapshot ?? defaultSnapshot, null, 2));
        }
      })
      .catch((err: unknown) => setError(err instanceof Error ? err.message : "Failed to load policy"))
      .finally(() => setLoading(false));
  }, [client, id]);

  async function savePolicy(): Promise<Policy | null> {
    if (!client || !id) {
      return null;
    }
    setSaving(true);
    setError("");
    setMessage("");
    try {
      const parsed = JSON.parse(jsonText) as unknown;
      const mode = readMode(parsed);
      const nextPolicy = policy
        ? await client.updatePolicy(policy.id, {
            expected_updated_at: policy.updated_at,
            mode,
            snapshot: parsed,
          })
        : await client.createPolicy(id, {
            name: "Default policy",
            mode,
            snapshot: parsed,
          });
      setPolicy(nextPolicy);
      setMessage("Policy draft saved.");
      return nextPolicy;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Policy JSON is invalid");
      return null;
    } finally {
      setSaving(false);
    }
  }

  async function publishPolicy() {
    const saved = await savePolicy();
    if (!client || !saved) {
      return;
    }
    setPublishing(true);
    setError("");
    try {
      const published = await client.publishPolicy(saved.id);
      setMessage(`Published version ${published.version} (${published.policy_version_id}).`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to publish policy");
    } finally {
      setPublishing(false);
    }
  }

  return (
    <AppShell>
      <div className="page-header">
        <div>
          <h1 className="page-title">Policy Editor</h1>
          <p className="page-description">MVP JSON editor for the app policy draft.</p>
        </div>
      </div>
      {loading ? <LoadingState /> : null}
      {error ? <ErrorState message={error} /> : null}
      {message ? <div className="notice">{message}</div> : null}
      {!loading ? (
        <section className="card form">
          <div className="notice">
            Count mode records rules that would block without denying requests. Block mode enforces block and rate-limit decisions.
          </div>
          <div className="field">
            <label htmlFor="policy-json">Policy JSON</label>
            <textarea id="policy-json" value={jsonText} onChange={(event) => setJsonText(event.target.value)} spellCheck={false} />
          </div>
          <div className="actions">
            <button className="button secondary" type="button" onClick={() => void savePolicy()} disabled={saving || publishing}>
              {saving ? "Saving..." : "Save draft"}
            </button>
            <button className="button" type="button" onClick={() => void publishPolicy()} disabled={saving || publishing}>
              {publishing ? "Publishing..." : "Publish"}
            </button>
          </div>
        </section>
      ) : null}
    </AppShell>
  );
}

function readMode(value: unknown): "count" | "block" {
  if (typeof value === "object" && value !== null && "mode" in value) {
    const mode = (value as { mode?: unknown }).mode;
    if (mode === "block") {
      return "block";
    }
  }
  return "count";
}
