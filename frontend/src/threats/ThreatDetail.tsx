import { useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Download, ExternalLink, ScanSearch } from "lucide-react";
import { api, ApiError, download } from "@/api/client";
import type { AdvisoryDetail, Member, Page, ThreatMatch } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import {
  Card, Empty, ErrorBox, Field, Kpi, Loading, Modal, PageHead, Pagination, SeverityBadge, StatusBadge,
} from "@/components/ui";
import { ASSESSMENT_LABELS, ASSET_TYPE_LABELS, fmtDate, fmtDay, label, REMEDIATION_STATES, timeAgo } from "@/lib/format";
import { Freshness } from "./ThreatCenter";

const FILTERS: { id: string; label: string; values: string[] }[] = [
  { id: "affected", label: "May be affected", values: ["confirmed", "check_pending", "not_detected", "inconclusive", "potentially_affected", "version_unknown", "reported_unverified"] },
  { id: "confirmed", label: "Confirmed", values: ["confirmed"] },
  { id: "unchecked", label: "Not yet checked", values: ["potentially_affected", "version_unknown", "reported_unverified"] },
  { id: "not_detected", label: "Checked — not detected", values: ["not_detected"] },
  { id: "inconclusive", label: "Inconclusive", values: ["inconclusive"] },
  { id: "other", label: "Not affected / gone", values: ["not_affected_version", "no_longer_observed"] },
  { id: "all", label: "Everything", values: [] },
];

export function AssessmentBadge({ value }: { value: string }) {
  const a = ASSESSMENT_LABELS[value] ?? { text: label(value), tone: "neutral", hint: "" };
  return <span className={`badge ${a.tone}`} title={a.hint}>{a.text}</span>;
}

function Evidence({ m }: { m: ThreatMatch }) {
  const obs = m.evidence.observations ?? [];
  if (!obs.length) return <span className="small muted">{m.evidence.reason ?? "—"}</span>;
  const o = obs[0];
  return (
    <div className="small" title={obs.map((x) => `${x.product} ${x.version ?? "(no version)"} via ${label(x.source)}: ${x.reason}`).join("\n")}>
      <span className="mono">{o.matched_name}{o.version ? ` ${o.version}` : ""}</span>
      <span className="muted"> · {label(o.source)}{o.third_party ? " (third-party record)" : ""}</span>
      <div className="cell-sub">{o.reason}{obs.length > 1 ? ` (+${obs.length - 1} more)` : ""}</div>
    </div>
  );
}

function RemediationModal({ m, onClose }: { m: ThreatMatch; onClose: () => void }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<Member[]>("/users"), enabled: can("users:read") });
  const [form, setForm] = useState({ remediation_status: m.remediation_status, assigned_to: m.assigned_to ?? "",
    remediation_note: m.remediation_note ?? "" });
  const save = useMutation({
    mutationFn: () => api(`/threats/matches/${m.id}`, { method: "PATCH", body: {
      remediation_status: form.remediation_status, assigned_to: form.assigned_to || null,
      remediation_note: form.remediation_note || null } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["threat"] }); qc.invalidateQueries({ queryKey: ["threats"] }); onClose(); },
  });
  return (
    <Modal title={`Remediation — ${m.asset?.value ?? "asset"}`} onClose={onClose} footer={<>
      <button className="btn" onClick={onClose}>Cancel</button>
      <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>Save</button>
    </>}>
      <div className="form">
        <ErrorBox error={save.error} />
        <p className="small muted">Remediation is your team's workflow. It is kept separate from what scans and checks report, so a fixed
          asset stays "confirmed" in history while its remediation shows "resolved".</p>
        <Field label="Status">
          <select value={form.remediation_status} onChange={(e) => setForm({ ...form, remediation_status: e.target.value })}>
            {REMEDIATION_STATES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
          </select>
        </Field>
        {can("users:read") && (
          <Field label="Assigned to">
            <select value={form.assigned_to} onChange={(e) => setForm({ ...form, assigned_to: e.target.value })}>
              <option value="">Unassigned</option>
              {(users.data ?? []).filter((u) => u.is_active).map((u) => <option key={u.user_id} value={u.user_id}>{u.full_name || u.email}</option>)}
            </select>
          </Field>
        )}
        <Field label="Note"><textarea value={form.remediation_note} onChange={(e) => setForm({ ...form, remediation_note: e.target.value })} /></Field>
      </div>
    </Modal>
  );
}

export default function ThreatDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const { orgId } = useOrg();
  const qc = useQueryClient();
  const [filter, setFilter] = useState("affected");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [editing, setEditing] = useState<ThreatMatch | null>(null);
  const values = FILTERS.find((f) => f.id === filter)!.values;

  const detail = useQuery({
    queryKey: ["threat", id, orgId],
    queryFn: () => api<AdvisoryDetail>(`/threats/${id}`, { query: { organization_id: orgId } }),
    refetchInterval: (q) => (q.state.data?.check_runs.some((r) => r.status === "queued" || r.status === "running") ? 5000 : false),
  });
  const assets = useQuery({
    queryKey: ["threat", id, "assets", orgId, filter, page],
    queryFn: () => api<Page<ThreatMatch>>(`/threats/${id}/assets`, { query: { organization_id: orgId, assessment: values, page, page_size: 50 } }),
  });
  const check = useMutation({
    mutationFn: () => api(`/threats/${id}/checks`, { method: "POST", body: { match_ids: [...selected] } }),
    onSuccess: () => { setSelected(new Set()); qc.invalidateQueries({ queryKey: ["threat", id] }); },
  });
  const rows = useMemo(() => assets.data?.items ?? [], [assets.data]);

  if (detail.isLoading) return <Loading />;
  if (detail.error) return <ErrorBox error={detail.error} />;
  const a = detail.data!;
  const c = a.counts;
  const canCheck = can("scans:run") && !!a.check;
  const toggle = (mid: string) => setSelected((s) => { const n = new Set(s); if (n.has(mid)) n.delete(mid); else n.add(mid); return n; });
  const checkable = rows.filter((m) => m.asset && m.asset.status === "active" && m.assessment !== "check_pending");
  const conflictRun = check.error instanceof ApiError && check.error.status === 409;

  return (
    <>
      <div className="small" style={{ marginBottom: 8 }}><Link to="/threats"><ArrowLeft size={13} /> Threat Center</Link></div>
      <PageHead
        title={a.title}
        sub={<div className="row">
          <SeverityBadge value={a.severity} />
          {a.status === "archived" && <span className="badge neutral">archived</span>}
          {a.cves.map((cv) => <span key={cv} className="tag mono">{cv}</span>)}
          <span className="muted small">
            Published {fmtDay(a.source_published_at ?? a.version_published_at)}
            {a.source_updated_at && ` · updated ${fmtDay(a.source_updated_at)}`} · version {a.published_version}
          </span>
        </div>}
        actions={<button className="btn" onClick={() => download(`/threats/${id}/assets/export.csv`, { organization_id: orgId }, `threat-${a.slug}.csv`)}><Download /> Export CSV</button>} />

      <div className="grid kpis" style={{ marginBottom: 14 }}>
        <Kpi label="May be affected" value={c.affected} onClick={() => { setFilter("affected"); setPage(1); }} />
        <Kpi label="Confirmed" value={c.confirmed} tone={c.confirmed ? "danger" : undefined} onClick={() => { setFilter("confirmed"); setPage(1); }} />
        <Kpi label="Not yet checked" value={c.unchecked} onClick={() => { setFilter("unchecked"); setPage(1); }} />
        <Kpi label="Checked — not detected" value={c.not_detected} delta="not proof of safety" onClick={() => { setFilter("not_detected"); setPage(1); }} />
        <Kpi label="Inconclusive" value={c.inconclusive} tone={c.inconclusive ? "warn" : undefined} onClick={() => { setFilter("inconclusive"); setPage(1); }} />
        <Kpi label="Remediation" value={c.affected ? `${c.remediated}/${c.affected}` : "—"} delta={c.affected ? `${Math.round((c.remediated / c.affected) * 100)}% resolved, accepted or n/a` : undefined} />
      </div>

      <div className="grid cols-3" style={{ marginBottom: 14 }}>
        <Card title="What it is" className="span-2">
          <p style={{ whiteSpace: "pre-wrap", marginTop: 0 }}>{a.summary || <span className="muted">No summary.</span>}</p>
          {a.affected_products.length > 0 && (
            <>
              <h4 className="small muted" style={{ margin: "12px 0 6px" }}>AFFECTED PRODUCTS (how inventory is matched)</h4>
              <ul className="small" style={{ margin: 0, paddingInlineStart: 18 }}>
                {a.affected_products.map((p, i) => (
                  <li key={i}>
                    <b>{p.vendor ? `${p.vendor} ` : ""}{p.product}</b> — names <span className="mono">{p.match_names.join(", ")}</span>;{" "}
                    {p.versions.length ? p.versions.map((r) => [r.introduced && `from ${r.introduced}`, r.fixed && `fixed in ${r.fixed}`, r.last_affected && `up to ${r.last_affected}`].filter(Boolean).join(", ")).join(" · ") : "every version"}
                  </li>
                ))}
              </ul>
            </>
          )}
          {a.remediation && (<><h4 className="small muted" style={{ margin: "12px 0 6px" }}>REMEDIATION GUIDANCE</h4>
            <p style={{ whiteSpace: "pre-wrap", margin: 0 }}>{a.remediation}</p></>)}
        </Card>
        <div className="stack">
          <Card title="Assessment" hint={<Freshness a={a} />}>
            <p className="small" style={{ marginTop: 0 }}>Matched automatically against recorded inventory when this advisory is published or updated and after every scan. No scan is started for you.</p>
            {a.check ? <p className="small" style={{ margin: 0 }}>Approved check available: <b>{a.check.name}</b>.</p>
              : <p className="small muted" style={{ margin: 0 }}>No approved check exists for this advisory; it can only be assessed from inventory and existing findings.</p>}
          </Card>
          {a.intel.length > 0 && (
            <Card title="Exploitation intelligence">
              <ul className="list" style={{ margin: "-6px -16px" }}>
                {a.intel.map((i) => (
                  <li key={i.cve}><span className="grow mono small">{i.cve}</span>
                    {i.kev && <span className="badge bad" title={i.kev_due_date ? `Due ${i.kev_due_date}` : undefined}>KEV</span>}
                    {i.epss_score !== null && <span className="small muted">EPSS {(i.epss_score * 100).toFixed(1)}%</span>}
                    {i.cvss_score !== null && <span className="small muted">CVSS {i.cvss_score}</span>}</li>
                ))}
              </ul>
            </Card>
          )}
          {a.references.length > 0 && (
            <Card title="References">
              <ul className="small" style={{ margin: 0, paddingInlineStart: 18 }}>
                {a.references.map((r) => <li key={r} style={{ wordBreak: "break-all" }}>
                  <a href={r} target="_blank" rel="noopener noreferrer nofollow">{r} <ExternalLink size={11} /></a></li>)}
              </ul>
            </Card>
          )}
        </div>
      </div>

      <Card flush title="Assets" right={canCheck && (
        <button className="btn primary sm" disabled={!selected.size || check.isPending} onClick={() => check.mutate()}
                title="Runs the approved check through the normal scan pipeline: scope authorization, quotas and scheduling apply">
          <ScanSearch /> Check selected assets{selected.size ? ` (${selected.size})` : ""}
        </button>
      )}>
        <div className="filters">
          {FILTERS.map((f) => (
            <button key={f.id} className={`btn sm ${filter === f.id ? "primary" : "ghost"}`} onClick={() => { setFilter(f.id); setPage(1); setSelected(new Set()); }}>{f.label}</button>
          ))}
        </div>
        {check.error && <div className="card-body"><ErrorBox error={check.error} />{conflictRun && <span className="small muted">Wait for the running check to finish; its results appear below.</span>}</div>}
        {check.isSuccess && <div className="card-body small">Check requested. Results appear here when the scan finishes (see Scans for progress).</div>}
        {assets.isLoading ? <Loading /> : assets.error ? <div className="card-body"><ErrorBox error={assets.error} /></div> :
          !rows.length ? <Empty>{filter === "affected" ? "None of your recorded assets match this advisory. That reflects your inventory, not a guarantee: assets never scanned, or products that were not fingerprinted, cannot be matched." : "Nothing in this view."}</Empty> : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr>
                    {canCheck && <th style={{ width: 28 }}><input type="checkbox" aria-label="Select all"
                      checked={checkable.length > 0 && checkable.every((m) => selected.has(m.id))}
                      onChange={(e) => setSelected(e.target.checked ? new Set(checkable.map((m) => m.id)) : new Set())} /></th>}
                    <th>Asset</th><th>Assessment</th><th>Evidence</th><th>Findings</th><th>Last check</th><th>Owner</th><th>Remediation</th>
                  </tr></thead>
                  <tbody>
                    {rows.map((m) => (
                      <tr key={m.id}>
                        {canCheck && <td><input type="checkbox" aria-label={`Select ${m.asset?.value}`} disabled={!checkable.includes(m)}
                                                checked={selected.has(m.id)} onChange={() => toggle(m.id)} /></td>}
                        <td>
                          {m.asset ? <div className="cell-main"><Link to={`/assets/${m.asset.id}`}>{m.asset.value}</Link></div> : <span className="muted">deleted asset</span>}
                          <div className="cell-sub">{m.asset ? ASSET_TYPE_LABELS[m.asset.asset_type] ?? m.asset.asset_type : ""}{m.asset?.status === "inactive" ? " · inactive" : ""}</div>
                        </td>
                        <td><AssessmentBadge value={m.assessment} /></td>
                        <td style={{ maxWidth: 320 }}><Evidence m={m} /></td>
                        <td className="small">{m.findings.length ? m.findings.map((f) => (
                          <div key={f.id}><Link to={`/findings/${f.id}`}>{f.title}</Link> <StatusBadge value={f.status} />{f.unverified && <span className="badge neutral">unverified</span>}</div>
                        )) : <span className="muted">—</span>}</td>
                        <td className="small">{m.check_outcome === "none" ? <span className="muted">never</span> : (
                          <span title={m.check_detail ?? undefined}>{label(m.check_outcome)}{m.checked_at ? <div className="cell-sub">{timeAgo(m.checked_at)}</div> : null}</span>
                        )}</td>
                        <td className="small">{m.owner || <span className="muted">unknown</span>}{m.business_unit && <div className="cell-sub">{m.business_unit}</div>}</td>
                        <td>
                          {can("findings:write")
                            ? <button className="btn ghost sm" onClick={() => setEditing(m)} title={m.remediation_note ?? undefined}><StatusBadge value={m.remediation_status} /></button>
                            : <StatusBadge value={m.remediation_status} />}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} pageSize={50} total={assets.data!.total} onPage={setPage} />
            </>
          )}
      </Card>

      {a.check_runs.length > 0 && (
        <div style={{ marginTop: 14 }}><Card flush title="Checks">
          <table className="data">
            <thead><tr><th>Requested</th><th>Status</th><th className="num">Detected</th><th className="num">Not detected</th><th className="num">Inconclusive</th><th>Note</th><th /></tr></thead>
            <tbody>{a.check_runs.map((r) => (
              <tr key={r.id}>
                <td className="small" title={fmtDate(r.created_at)}>{timeAgo(r.created_at)}</td>
                <td><StatusBadge value={r.status} /></td>
                <td className="num">{r.summary.detected ?? "—"}</td>
                <td className="num">{r.summary.not_detected ?? "—"}</td>
                <td className="num">{r.summary.inconclusive ?? "—"}</td>
                <td className="small">{r.summary.reason ?? ""}</td>
                <td>{r.scan_id && can("scans:read") && <Link className="small" to={`/scans/${r.scan_id}`}>scan</Link>}</td>
              </tr>
            ))}</tbody>
          </table>
        </Card></div>
      )}
      {editing && <RemediationModal m={editing} onClose={() => setEditing(null)} />}
    </>
  );
}
