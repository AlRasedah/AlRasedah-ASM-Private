import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Save } from "lucide-react";
import { api } from "@/api/client";
import type { AssetDetail as TAsset, AssetEvent, Finding, Observation, Page, RelatedAsset } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import {
  Card, Empty, ErrorBox, Field, JsonView, Loading, PageHead, Pagination, RiskScore, SeverityBadge, StatusBadge, Tabs,
} from "@/components/ui";
import { Timeline } from "@/components/Timeline";
import ExposureGraph from "@/exposure/ExposureGraph";
import Screenshots from "./Screenshots";
import { APPROVAL_STATES, ASSET_TYPE_LABELS, fmtDate, fmtDay, label, timeAgo } from "@/lib/format";

type Tab = "overview" | "relationships" | "dns" | "ports" | "web" | "tech" | "certs" | "screenshots" | "exposure" | "findings" | "timeline" | "raw";

const HOSTNAME = ["root_domain", "domain", "subdomain"];

export default function AssetDetail() {
  const { id } = useParams();
  const [tab, setTab] = useState<Tab>("overview");
  const navigate = useNavigate();
  const asset = useQuery({ queryKey: ["asset", id], queryFn: () => api<TAsset>(`/assets/${id}`) });
  useEffect(() => setTab("overview"), [id]);

  if (asset.isLoading) return <Loading />;
  if (asset.error) return <ErrorBox error={asset.error} />;
  const a = asset.data!;
  const rel = (relation: string, direction: "in" | "out" = "out") =>
    a.relationships.filter((r) => r.relation === relation && r.direction === direction);

  const tabs: { id: Tab; label: string }[] = [{ id: "overview", label: "Overview" }];
  tabs.push({ id: "relationships", label: `Relationships (${a.relationships.length})` });
  if (HOSTNAME.includes(a.asset_type) && a.meta.dns) tabs.push({ id: "dns", label: "DNS" });
  if (a.asset_type === "ip_address" || a.asset_type === "port") tabs.push({ id: "ports", label: "Ports & services" });
  if (HOSTNAME.includes(a.asset_type) || a.asset_type === "ip_address") tabs.push({ id: "web", label: "Web endpoints" });
  if (a.asset_type === "http_endpoint") tabs.push({ id: "tech", label: "Technologies" });
  if (a.asset_type === "http_endpoint" || a.asset_type === "certificate") tabs.push({ id: "certs", label: "Certificates" });
  if (a.asset_type === "http_endpoint" || a.asset_type === "web_application") tabs.push({ id: "screenshots", label: "Screenshots" });
  if (!["technology", "certificate", "cloud_resource", "asn"].includes(a.asset_type)) tabs.push({ id: "exposure", label: "Exposure map" });
  tabs.push({ id: "findings", label: `Findings (${a.open_findings})` }, { id: "timeline", label: "Timeline" },
            { id: "raw", label: "Raw observations" });

  return (
    <>
      <div className="small" style={{ marginBottom: 8 }}><Link to="/inventory"><ArrowLeft size={13} /> Inventory</Link></div>
      <PageHead
        title={<span className="mono" style={{ fontSize: 18, wordBreak: "break-all" }}>{a.value}</span>}
        sub={<div className="row">
          <span className="badge accent">{ASSET_TYPE_LABELS[a.asset_type] ?? a.asset_type}</span>
          <StatusBadge value={a.status} /><StatusBadge value={a.scope_status} /><StatusBadge value={a.approval_status} />
          <span className="muted small">First seen {fmtDay(a.first_seen)} · last seen {timeAgo(a.last_seen)}</span>
        </div>}
        actions={<div className="row"><span className="muted small">Risk</span><RiskScore score={a.risk_score} /></div>} />
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      {tab === "overview" && <Overview a={a} />}
      {tab === "relationships" && <Relationships items={a.relationships} />}
      {tab === "dns" && <Dns dns={a.meta.dns ?? {}} ips={rel("resolves_to")} cnames={rel("cname")} />}
      {tab === "ports" && <Ports a={a} />}
      {tab === "web" && <RelatedTable items={[...rel("serves")]} empty="No web endpoints observed." />}
      {tab === "tech" && <Technologies items={rel("uses_technology")} />}
      {tab === "certs" && <Certificates a={a} />}
      {tab === "screenshots" && <Screenshots assetId={a.id} />}
      {tab === "exposure" && <ExposureGraph key={a.id} assetId={a.id} onRecenter={(id) => navigate(`/assets/${id}`)} />}
      {tab === "findings" && <AssetFindings assetId={a.id} />}
      {tab === "timeline" && <AssetTimeline assetId={a.id} />}
      {tab === "raw" && <RawObservations assetId={a.id} />}
    </>
  );
}

function Overview({ a }: { a: TAsset }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [form, setForm] = useState({ owner: a.owner ?? "", business_unit: a.business_unit ?? "", criticality: a.criticality,
    approval_status: a.approval_status, tags: a.tags.join(", "), notes: a.notes ?? "" });
  const save = useMutation({
    mutationFn: () => api(`/assets/${a.id}`, { method: "PATCH", body: {
      owner: form.owner || null, business_unit: form.business_unit || null, criticality: form.criticality,
      approval_status: form.approval_status, tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean),
      notes: form.notes || null } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["asset", a.id] }); qc.invalidateQueries({ queryKey: ["assets"] }); },
  });
  const attrs = useMemo(() => Object.entries(a.meta).filter(([k]) => !["dns", "expiry_alerts"].includes(k)), [a.meta]);

  return (
    <div className="grid cols-3">
      <Card title="Attributes" className="span-2">
        <dl className="kv">
          <dt>Discovered</dt><dd>{fmtDate(a.discovered_at)} via {label(a.discovery_method)}</dd>
          <dt>Last scanned</dt><dd>{fmtDate(a.last_scanned_at)}</dd>
          {a.inactive_since && (<><dt>Inactive since</dt><dd>{fmtDate(a.inactive_since)}</dd></>)}
          <dt>Detection sources</dt><dd>{a.sources.join(", ") || "—"}</dd>
          <dt>Confidence</dt><dd>{a.confidence}%</dd>
          {a.ips.length > 0 && (<><dt>IP addresses</dt><dd className="mono">{a.ips.join(", ")}</dd></>)}
          {attrs.map(([k, v]) => (
            <Attr key={k} k={k} v={v} />
          ))}
        </dl>
      </Card>
      <div className="stack">
        <Card title="Why this risk score" hint={`${a.risk_score}/100`}>
          {a.risk_factors.length ? (
            <ul className="list" style={{ margin: "-6px -16px" }}>
              {[...a.risk_factors].sort((x, y) => Math.abs(y.points) - Math.abs(x.points)).map((f, i) => (
                <li key={i}><span className="grow">{f.label}</span><span className="mono small">{f.points > 0 ? "+" : ""}{f.points}</span></li>
              ))}
            </ul>
          ) : <span className="muted">No contributing factors.</span>}
        </Card>
        <Card title="Ownership & classification">
          <div className="form">
            <ErrorBox error={save.error} />
            <Field label="Approval">
              <select value={form.approval_status} disabled={!can("assets:write")}
                      onChange={(e) => setForm({ ...form, approval_status: e.target.value })}>
                {APPROVAL_STATES.map((s) => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
              </select>
            </Field>
            <Field label="Owner"><input value={form.owner} disabled={!can("assets:write")} placeholder="Unknown"
                                        onChange={(e) => setForm({ ...form, owner: e.target.value })} /></Field>
            <Field label="Business unit"><input value={form.business_unit} disabled={!can("assets:write")}
                                                onChange={(e) => setForm({ ...form, business_unit: e.target.value })} /></Field>
            <Field label="Business criticality">
              <select value={form.criticality} disabled={!can("assets:write")} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
                {["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}
              </select>
            </Field>
            <Field label="Tags (comma separated)"><input value={form.tags} disabled={!can("assets:write")}
                                                         onChange={(e) => setForm({ ...form, tags: e.target.value })} /></Field>
            <Field label="Notes"><textarea value={form.notes} disabled={!can("assets:write")}
                                           onChange={(e) => setForm({ ...form, notes: e.target.value })} /></Field>
            {can("assets:write") && (
              <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}><Save /> Save</button>
            )}
            {save.isSuccess && <span className="small muted">Saved.</span>}
          </div>
        </Card>
      </div>
    </div>
  );
}

function Attr({ k, v }: { k: string; v: unknown }) {
  const text = Array.isArray(v) ? v.join(", ") : typeof v === "object" && v !== null ? JSON.stringify(v) : String(v);
  return (<><dt>{label(k)}</dt><dd className={typeof v === "object" ? "mono small" : ""}>{text || "—"}</dd></>);
}

export function RelatedTable({ items, empty = "No relationships." }: { items: RelatedAsset[]; empty?: string }) {
  if (!items.length) return <Card><Empty>{empty}</Empty></Card>;
  return (
    <Card flush>
      <div className="table-wrap">
        <table className="data">
          <thead><tr><th>Relation</th><th>Asset</th><th>Type</th><th>State</th><th>First seen</th><th>Last seen</th><th>Risk</th></tr></thead>
          <tbody>
            {items.map((r) => (
              <tr key={`${r.relation}-${r.direction}-${r.asset.id}`} style={{ opacity: r.active ? 1 : 0.55 }}>
                <td className="small">{r.direction === "in" ? "← " : "→ "}{label(r.relation)}</td>
                <td className="cell-main"><Link to={`/assets/${r.asset.id}`}>{r.asset.value}</Link>
                  {typeof r.attributes.version === "string" && <span className="muted small"> v{r.attributes.version}</span>}</td>
                <td className="small">{ASSET_TYPE_LABELS[r.asset.asset_type] ?? r.asset.asset_type}</td>
                <td>{r.active ? <StatusBadge value={r.asset.status} /> : <span className="badge neutral">no longer observed</span>}</td>
                <td className="small">{fmtDay(r.first_seen)}</td>
                <td className="small">{timeAgo(r.last_seen)}</td>
                <td><RiskScore score={r.asset.risk_score} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Relationships({ items }: { items: RelatedAsset[] }) {
  return <RelatedTable items={items} />;
}

function Dns({ dns, ips, cnames }: { dns: Record<string, string[]>; ips: RelatedAsset[]; cnames: RelatedAsset[] }) {
  const types = Object.keys(dns).sort();
  return (
    <div className="stack">
      <Card title="Current DNS records" flush>
        {types.length ? (
          <table className="data"><thead><tr><th style={{ width: 100 }}>Type</th><th>Values</th></tr></thead>
            <tbody>{types.map((t) => (
              <tr key={t}><td className="mono">{t.toUpperCase()}</td><td className="mono small">{(dns[t] ?? []).join("\n") || "—"}</td></tr>
            ))}</tbody>
          </table>
        ) : <Empty>No DNS data.</Empty>}
      </Card>
      <RelatedTable items={[...ips, ...cnames]} empty="No resolution history." />
    </div>
  );
}

function Ports({ a }: { a: TAsset }) {
  const ports = a.relationships.filter((r) => ["has_port", "runs_service"].includes(r.relation));
  return <RelatedTable items={ports} empty="No open ports observed." />;
}

function Technologies({ items }: { items: RelatedAsset[] }) {
  return <RelatedTable items={items} empty="No technologies fingerprinted." />;
}

function Certificates({ a }: { a: TAsset }) {
  if (a.asset_type === "certificate") {
    const m = a.meta;
    return (
      <div className="grid cols-2">
        <Card title="Certificate">
          <dl className="kv">
            <dt>Subject</dt><dd>{m.subject_cn ?? "—"}</dd>
            <dt>Issuer</dt><dd>{m.issuer_cn ?? "—"} {m.issuer_org ? `(${[].concat(m.issuer_org).join(", ")})` : ""}</dd>
            <dt>Valid from</dt><dd>{fmtDate(m.not_before)}</dd>
            <dt>Expires</dt><dd>{fmtDate(m.not_after)}</dd>
            <dt>Self-signed</dt><dd>{m.self_signed ? "yes" : "no"}</dd>
            <dt>SHA-256</dt><dd className="mono small">{a.value}</dd>
            <dt>Names (SAN)</dt><dd className="mono small">{(m.sans ?? []).join(", ") || "—"}</dd>
          </dl>
        </Card>
        <RelatedTable items={a.relationships} empty="Not presented by any known endpoint." />
      </div>
    );
  }
  return <RelatedTable items={a.relationships.filter((r) => r.relation === "presents_certificate")} empty="No TLS certificate observed." />;
}

function AssetFindings({ assetId }: { assetId: string }) {
  const q = useQuery({ queryKey: ["findings", "asset", assetId], queryFn: () => api<Page<Finding>>("/findings", { query: { asset_id: assetId, page_size: 100 } }) });
  if (q.isLoading) return <Loading />;
  if (!q.data?.items.length) return <Card><Empty>No findings for this asset.</Empty></Card>;
  return (
    <Card flush>
      <table className="data">
        <thead><tr><th>Risk</th><th>Severity</th><th>Finding</th><th>Status</th><th>First seen</th><th>Last seen</th></tr></thead>
        <tbody>{q.data.items.map((f) => (
          <tr key={f.id}>
            <td><RiskScore score={f.risk_score} /></td>
            <td><SeverityBadge value={f.severity} /></td>
            <td className="cell-main"><Link to={`/findings/${f.id}`}>{f.title}</Link>{f.kev && <span className="badge bad" style={{ marginInlineStart: 6 }}>KEV</span>}</td>
            <td><StatusBadge value={f.status} /></td>
            <td className="small">{fmtDay(f.first_seen)}</td>
            <td className="small">{timeAgo(f.last_seen)}</td>
          </tr>
        ))}</tbody>
      </table>
    </Card>
  );
}

function AssetTimeline({ assetId }: { assetId: string }) {
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["timeline", assetId, page], queryFn: () => api<Page<AssetEvent>>(`/assets/${assetId}/timeline`, { query: { page, page_size: 50 } }) });
  if (q.isLoading) return <Loading />;
  if (!q.data?.items.length) return <Card><Empty>No recorded changes yet.</Empty></Card>;
  return (
    <Card flush>
      <Timeline events={q.data.items} showAsset currentAssetId={assetId} />
      <Pagination page={page} pageSize={50} total={q.data.total} onPage={setPage} />
    </Card>
  );
}

function RawObservations({ assetId }: { assetId: string }) {
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["observations", assetId, page], queryFn: () => api<Page<Observation>>(`/assets/${assetId}/observations`, { query: { page, page_size: 20 } }) });
  if (q.isLoading) return <Loading />;
  if (!q.data?.items.length) return <Card><Empty>No observations recorded.</Empty></Card>;
  return (
    <div className="stack">
      {q.data.items.map((o) => (
        <Card key={o.id} title={o.source_label ?? "Scan"} hint={fmtDate(o.observed_at)}
              right={o.scan_id && <Link to={`/scans/${o.scan_id}`} className="small">scan</Link>}>
          {Object.keys(o.data).length ? <JsonView value={o.data} /> : <span className="muted">Seen (no attributes)</span>}
        </Card>
      ))}
      <Pagination page={page} pageSize={20} total={q.data.total} onPage={setPage} />
    </div>
  );
}
