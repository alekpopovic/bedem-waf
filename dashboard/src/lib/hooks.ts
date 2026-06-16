"use client";

import { useEffect, useMemo, useState } from "react";
import { ControlApiClient, getStoredApiKey } from "./api";

export function useApiClient(): ControlApiClient | null {
  const [apiKey, setApiKey] = useState("");

  useEffect(() => {
    setApiKey(getStoredApiKey());
  }, []);

  return useMemo(() => {
    if (!apiKey) {
      return null;
    }
    return new ControlApiClient(apiKey);
  }, [apiKey]);
}

export function formatDate(value?: string): string {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

export function actionClass(action: string): string {
  return `badge ${action || "allow"}`;
}

export function slugFromHost(hostname: string): string {
  return hostname
    .toLowerCase()
    .replace(/:\d+$/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63);
}
