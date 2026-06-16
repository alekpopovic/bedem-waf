"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { clearStoredApiKey, clearStoredTenantId, getControlApiUrl, getStoredApiKey, getStoredTenantId } from "../lib/api";

const navItems = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/apps", label: "Apps" },
  { href: "/events", label: "Events" },
  { href: "/settings/api-keys", label: "API Keys" },
];

export function AppShell({ children }: Readonly<{ children: React.ReactNode }>) {
  const pathname = usePathname();
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getStoredApiKey() || !getStoredTenantId()) {
      router.replace("/login");
      return;
    }
    setReady(true);
  }, [router]);

  const section = useMemo(() => navItems.find((item) => pathname.startsWith(item.href))?.label ?? "Console", [pathname]);

  if (!ready) {
    return <div className="content">Loading...</div>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-name">BedemWAF</span>
          <span className="brand-subtitle">Managed WAF console</span>
        </div>
        <nav className="nav">
          {navItems.map((item) => (
            <Link key={item.href} className={`nav-link ${pathname.startsWith(item.href) ? "active" : ""}`} href={item.href}>
              {item.label}
            </Link>
          ))}
        </nav>
      </aside>
      <main className="main">
        <header className="topbar">
          <strong>{section}</strong>
          <div className="actions">
            <span className="env-pill">Development mode</span>
            <span className="muted">Tenant: {getStoredTenantId()}</span>
            <span className="muted">{getControlApiUrl()}</span>
            <button
              className="button secondary"
              type="button"
              onClick={() => {
                clearStoredApiKey();
                clearStoredTenantId();
                router.replace("/login");
              }}
            >
              Sign out
            </button>
          </div>
        </header>
        <div className="content">{children}</div>
      </main>
    </div>
  );
}
