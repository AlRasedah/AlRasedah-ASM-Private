import { NavLink, Outlet } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity, Boxes, Building2, FileText, Gauge, Globe2, LogOut, Plug, Radar, ScrollText, Settings, ShieldAlert,
  Siren, SlidersHorizontal, Users, Workflow,
} from "lucide-react";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { api } from "@/api/client";
import type { Page } from "@/api/types";

export function BrandMark({ className = "brand-mark" }: { className?: string }) {
  return <img className={className} src="/brand-symbol.svg" alt="" aria-hidden="true" width={42} height={28} />;
}

export function Brand() {
  return (
    <div className="brand">
      <BrandMark />
      <div>
        <div className="brand-name">Exteriq ASM</div>
        <div className="brand-sub">Attack Surface Management</div>
      </div>
    </div>
  );
}

function Nav({ to, icon: Icon, children, count }: { to: string; icon: typeof Gauge; children: string; count?: number }) {
  return (
    <NavLink to={to} end={to === "/"}>
      <Icon /> {children}
      {count ? <span className="count">{count > 999 ? "999+" : count}</span> : null}
    </NavLink>
  );
}

export default function Layout() {
  const { me, can, logout, switchTenant } = useAuth();
  const { orgId, setOrgId, orgs } = useOrg();
  const { data: unacked } = useQuery({
    queryKey: ["events", "unacked-count", orgId],
    queryFn: () => api<Page<unknown>>("/events", { query: { acknowledged: false, min_severity: "medium", page_size: 1, organization_id: orgId } }),
    refetchInterval: 60_000,
  });
  const initials = (me?.user.full_name || me?.user.email || "?").split(/[\s@.]/).filter(Boolean).slice(0, 2).map((s) => s[0]?.toUpperCase()).join("");

  return (
    <div className="app">
      <aside className="sidebar">
        <Brand />
        <nav className="nav">
          <Nav to="/" icon={Gauge}>Dashboard</Nav>
          <Nav to="/inventory" icon={Boxes}>Inventory</Nav>
          <Nav to="/shadow-it" icon={Radar}>Shadow IT</Nav>
          <Nav to="/findings" icon={ShieldAlert}>Findings</Nav>
          <Nav to="/changes" icon={Activity} count={unacked?.total}>Changes</Nav>
          <Nav to="/scans" icon={Workflow}>Scans</Nav>
          <Nav to="/reports" icon={FileText}>Reports</Nav>
          <div className="nav-section">Configuration</div>
          <Nav to="/organizations" icon={Building2}>Organizations & scope</Nav>
          {can("scans:read") && <Nav to="/scan-profiles" icon={SlidersHorizontal}>Scan profiles</Nav>}
          {can("integrations:read") && <Nav to="/integrations" icon={Plug}>Integrations</Nav>}
          {can("users:read") && <Nav to="/users" icon={Users}>Users</Nav>}
          {can("settings:write") && <Nav to="/settings" icon={Settings}>Settings</Nav>}
          {can("audit:read") && <Nav to="/audit" icon={ScrollText}>Audit log</Nav>}
          {can("tenants:admin") && (<><div className="nav-section">Platform</div><Nav to="/platform" icon={Globe2}>Tenants</Nav></>)}
        </nav>
      </aside>
      <div className="main">
        <header className="topbar">
          <select className="org-select" value={orgId ?? ""} onChange={(e) => setOrgId(e.target.value || undefined)}
                  aria-label="Organization">
            <option value="">All organizations</option>
            {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
          {me && me.memberships.length > 1 && (
            <select value={me.tenant?.id ?? ""} onChange={(e) => switchTenant(e.target.value)} aria-label="Tenant">
              {me.memberships.map((m) => <option key={m.tenant.id} value={m.tenant.id}>{m.tenant.name}</option>)}
            </select>
          )}
          <span className="spacer" />
          <NavLink to="/changes" className="btn ghost sm" title="Unacknowledged changes"><Siren /> {unacked?.total ?? 0}</NavLink>
          <NavLink to="/account" className="user-chip" title="Account">
            <span className="avatar">{initials}</span>
            <span className="small">{me?.user.email}<br /><span className="muted">{me?.role.replace(/_/g, " ")}</span></span>
          </NavLink>
          <button className="btn ghost sm" onClick={logout} title="Sign out"><LogOut /></button>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

