import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { api } from "@/api/client";
import type { DashboardSummary, TrendPoint } from "@/api/types";
import { useOrg } from "@/auth/OrgContext";
import { useAuth } from "@/auth/AuthContext";
import { HBarChart, TrendChart } from "@/components/Charts";
import { Card, Empty, ErrorBox, Kpi, Loading, PageHead, RiskScore, SeverityBadge, StatusBadge } from "@/components/ui";
import { ASSET_TYPE_LABELS, EVENT_LABELS, SEV_COLOR, timeAgo } from "@/lib/format";

export default function Dashboard() {
  const { orgId, orgs } = useOrg();
  const { can, me } = useAuth();
  const summary = useQuery({
    queryKey: ["dashboard", orgId],
    queryFn: () => api<DashboardSummary>("/dashboard/summary", { query: { organization_id: orgId } }),
    refetchInterval: 60_000,
  });
  const trends = useQuery({
    queryKey: ["trends", orgId],
    queryFn: () => api<TrendPoint[]>("/dashboard/trends", { query: { organization_id: orgId, days: 30 } }),
  });

  if (summary.isLoading) return <Loading />;
  if (summary.error) return <ErrorBox error={summary.error} />;
  const s = summary.data!;
  const t = s.totals;
  const trend = trends.data ?? [];

  if (!orgs.length) {
    // An empty tenant and the wrong tenant look identical here, so name the tenant and
    // the others this account belongs to rather than assuming a fresh deployment.
    const others = me?.memberships.filter((m) => m.tenant.id !== me.tenant?.id) ?? [];
    return (
      <>
        <PageHead title={me?.tenant ? `${me.tenant.name} has no data yet` : "Welcome to Exteriq ASM"}
                  sub="Continuous external attack surface management" />
        <Card>
          <div className="stack">
            {others.length > 0 && (
              <p>You are signed in to <strong>{me!.tenant!.name}</strong>, which has no organizations. Your other
                tenants — {others.map((m) => m.tenant.name).join(", ")} — are in the tenant selector at the top of
                the page.</p>
            )}
            {!me?.tenant && (
              <p>You are not signed in to a tenant, so no data is visible.
                {can("tenants:admin") && <> Open one from <Link to="/platform">Platform → Tenants</Link>.</>}</p>
            )}
            <p>Start by creating an organization and defining its <strong>authorized scope</strong> — the root domains,
              IP addresses and networks you are permitted to monitor. Active scanning is only ever performed against
              targets inside that scope.</p>
            {can("orgs:write") && me?.tenant && <div><Link className="btn primary" to="/organizations">Create an organization</Link></div>}
          </div>
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHead title="Attack surface overview" sub="What is exposed, what changed, and what matters most."
                actions={can("scans:run") && <Link to="/scans" className="btn primary"><Play /> Run a scan</Link>} />

      <div className="grid kpis" style={{ marginBottom: 14 }}>
        <Kpi label="Risk score" value={t.risk_score} tone={t.risk_score >= 80 ? "danger" : t.risk_score >= 60 ? "warn" : "accent"} delta="0–100, higher is worse"
             to="/inventory?sort=risk&order=desc" />
        <Kpi label="Total assets" value={t.total_assets.toLocaleString()} delta={`${t.active_assets.toLocaleString()} active`} to="/inventory" />
        <Kpi label="New (7 days)" value={t.new_assets_7d} tone={t.new_assets_7d ? "accent" : undefined} to={`/inventory?first_seen_after=${daysAgo(7)}`} />
        <Kpi label="Unknown / shadow IT" value={t.unknown_assets} tone={t.unknown_assets ? "warn" : undefined} to="/shadow-it" />
        <Kpi label="Critical findings" value={t.critical_findings} tone={t.critical_findings ? "danger" : undefined} to="/findings?severity=critical" />
        <Kpi label="High findings" value={t.high_findings} tone={t.high_findings ? "warn" : undefined} to="/findings?severity=high" />
        <Kpi label="Known exploited" value={t.kev_findings} tone={t.kev_findings ? "danger" : undefined} delta="CISA KEV" to="/findings?kev=true" />
        <Kpi label="Changes (24h)" value={t.changes_24h} to={`/changes?since=${daysAgo(1)}`} />
      </div>

      <div className="grid cols-3" style={{ marginBottom: 14 }}>
        <Card title="Risk trend" hint="last 30 days" className="span-2">
          <TrendChart data={trend as unknown as Record<string, unknown>[]} max={100}
                      keys={[{ key: "risk_score", color: "var(--brand)", name: "Risk score" }]} />
        </Card>
        <Card title="Open findings by severity">
          <HBarChart data={(["critical", "high", "medium", "low", "info"] as const).map((k) => ({ name: k, value: s.findings_by_severity[k] ?? 0 }))}
                     colors={SEV_COLOR} />
        </Card>
      </div>

      <div className="grid cols-3" style={{ marginBottom: 14 }}>
        <Card title="Attack surface growth" hint="active assets" className="span-2">
          <TrendChart data={trend as unknown as Record<string, unknown>[]}
                      keys={[{ key: "active_assets", color: "var(--brand)", name: "Active assets" },
                             { key: "unknown_assets", color: "var(--sev-medium)", name: "Unverified" }]} />
        </Card>
        <Card title="Asset types">
          <HBarChart data={Object.entries(s.asset_types).filter(([k]) => !["technology", "asn", "service", "dns_record"].includes(k))
            .sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ name: ASSET_TYPE_LABELS[k] ?? k, value: v }))} />
        </Card>
      </div>

      <div className="grid cols-2" style={{ marginBottom: 14 }}>
        <Card title="Recent changes" right={<Link to="/changes" className="small">View all</Link>} flush>
          {s.recent_changes.length ? (
            <ul className="list">
              {s.recent_changes.map((e) => (
                <li key={e.id}>
                  <SeverityBadge value={e.severity} />
                  <div className="grow">
                    <div className="truncate">{e.asset_id ? <Link to={`/assets/${e.asset_id}`}>{e.title}</Link> : e.title}</div>
                    <div className="cell-sub">{EVENT_LABELS[e.event_type] ?? e.event_type}</div>
                  </div>
                  <span className="muted small">{timeAgo(e.occurred_at)}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>No changes since the baseline scan.</Empty>}
        </Card>
        <Card title="Most exposed assets" right={<Link to="/inventory" className="small">Inventory</Link>} flush>
          {s.most_exposed_assets.length ? (
            <ul className="list">
              {s.most_exposed_assets.map((a) => (
                <li key={a.id}>
                  <RiskScore score={a.risk_score} />
                  <div className="grow">
                    <Link to={`/assets/${a.id}`} className="truncate" style={{ display: "block" }}>{a.value}</Link>
                    <div className="cell-sub">{ASSET_TYPE_LABELS[a.asset_type] ?? a.asset_type} · {a.open_findings} open finding(s)</div>
                  </div>
                  <StatusBadge value={a.approval_status} />
                </li>
              ))}
            </ul>
          ) : <Empty>No risky assets identified.</Empty>}
        </Card>
      </div>

      <div className="grid cols-3" style={{ marginBottom: 14 }}>
        <Card title="Recently opened services" flush>
          {s.recently_opened_services.length ? (
            <ul className="list">
              {s.recently_opened_services.map((e) => (
                <li key={e.id}>
                  <span className="dot" style={{ background: SEV_COLOR[e.severity] }} />
                  <div className="grow truncate">{e.asset_id ? <Link to={`/assets/${e.asset_id}`}>{e.title}</Link> : e.title}</div>
                  <span className="muted small">{timeAgo(e.occurred_at)}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>No newly exposed services.</Empty>}
        </Card>
        <Card title="Top vulnerable assets" flush>
          {s.top_vulnerable_assets.length ? (
            <ul className="list">
              {s.top_vulnerable_assets.map((a) => (
                <li key={a.id}>
                  <span className="badge neutral">{a.open_findings}</span>
                  <Link to={`/assets/${a.id}`} className="grow truncate">{a.value}</Link>
                  <RiskScore score={a.risk_score} />
                </li>
              ))}
            </ul>
          ) : <Empty>No open findings.</Empty>}
        </Card>
        <Card title="Certificates expiring soon" hint="≤ 30 days" flush>
          {s.expiring_certificates.length ? (
            <ul className="list">
              {s.expiring_certificates.map((c) => (
                <li key={c.id}>
                  <span className={`badge ${c.days_left < 0 ? "bad" : c.days_left <= 7 ? "warn" : "neutral"}`}>
                    {c.days_left < 0 ? "expired" : `${c.days_left}d`}
                  </span>
                  <Link to={`/assets/${c.id}`} className="grow truncate">{c.subject}</Link>
                  <span className="muted small truncate">{c.issuer}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>No certificates expiring within 30 days.</Empty>}
        </Card>
      </div>

      <div className="grid cols-3">
        <Card title="Technologies">
          <HBarChart data={s.technologies.slice(0, 10).map((x) => ({ name: x.name, value: x.count }))} />
        </Card>
        <Card title="Hosting & cloud">
          <HBarChart data={s.hosting_distribution.slice(0, 10).map((x) => ({ name: x.provider, value: x.count }))} />
        </Card>
        <Card title="Networks (ASN)" flush>
          {s.asn_distribution.length ? (
            <ul className="list">
              {s.asn_distribution.map((a) => (
                <li key={a.asn}>
                  <Link to={`/inventory?asn=${a.asn}`} className="mono">{a.asn}</Link>
                  <span className="grow truncate muted">{a.name}</span>
                  <span className="badge neutral">{a.count}</span>
                </li>
              ))}
            </ul>
          ) : <Empty>Network ownership appears after enrichment.</Empty>}
        </Card>
      </div>
    </>
  );
}

/** ISO timestamp n days ago, for date filters in links. */
function daysAgo(n: number): string {
  return new Date(Date.now() - n * 86_400_000).toISOString().replace(/.d{3}Z$/, "Z");
}
