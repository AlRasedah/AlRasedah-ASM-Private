import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Archive, ArrowLeft, Plus, RotateCcw, Save, Send, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { AdvisoryAdmin, AdvisoryContent, AffectedProduct, ApprovedCheck } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { Card, Confirm, Empty, ErrorBox, Field, Loading, Modal, PageHead, SeverityBadge, StatusBadge } from "@/components/ui";
import { fmtDate, SEVERITIES, timeAgo } from "@/lib/format";

const BLANK: AdvisoryContent = {
  title: "", summary: "", severity: "high", cves: [], references: [], remediation: "", check_keys: [],
  affected: [{ vendor: "", product: "", match_names: [], versions: [] }], source_published_at: null, source_updated_at: null,
};

const lines = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
const day = (v: string | null) => (v ? v.slice(0, 10) : "");

function ProductEditor({ p, onChange, onRemove }: { p: AffectedProduct; onChange: (p: AffectedProduct) => void; onRemove: () => void }) {
  const [names, setNames] = useState(p.match_names.join(", "));
  return (
    <div className="card" style={{ padding: 12 }}>
      <div className="form-row">
        <Field label="Vendor"><input value={p.vendor ?? ""} onChange={(e) => onChange({ ...p, vendor: e.target.value })} /></Field>
        <Field label="Product"><input value={p.product} onChange={(e) => onChange({ ...p, product: e.target.value })} /></Field>
        <Field label="Names as fingerprinted (comma separated)">
          <input value={names} placeholder="e.g. nginx" onChange={(e) => { setNames(e.target.value); onChange({ ...p, match_names: lines(e.target.value) }); }} />
        </Field>
      </div>
      <div className="small muted" style={{ margin: "8px 0 4px" }}>Affected versions — leave empty if every version is affected. "Fixed in" is exclusive, "up to" inclusive.</div>
      {p.versions.map((r, i) => (
        <div key={i} className="row" style={{ marginBottom: 6 }}>
          <input style={{ width: 130 }} placeholder="from (optional)" value={r.introduced ?? ""} aria-label="Introduced in"
                 onChange={(e) => onChange({ ...p, versions: p.versions.map((x, j) => j === i ? { ...x, introduced: e.target.value || null } : x) })} />
          <input style={{ width: 130 }} placeholder="fixed in" value={r.fixed ?? ""} aria-label="Fixed in"
                 onChange={(e) => onChange({ ...p, versions: p.versions.map((x, j) => j === i ? { ...x, fixed: e.target.value || null } : x) })} />
          <input style={{ width: 130 }} placeholder="or up to" value={r.last_affected ?? ""} aria-label="Last affected"
                 onChange={(e) => onChange({ ...p, versions: p.versions.map((x, j) => j === i ? { ...x, last_affected: e.target.value || null } : x) })} />
          <button className="btn ghost sm" onClick={() => onChange({ ...p, versions: p.versions.filter((_, j) => j !== i) })} aria-label="Remove range"><Trash2 /></button>
        </div>
      ))}
      <div className="row">
        <button className="btn sm" onClick={() => onChange({ ...p, versions: [...p.versions, { introduced: null, fixed: null, last_affected: null }] })}><Plus /> Version range</button>
        <span className="spacer" />
        <button className="btn ghost sm" onClick={onRemove}><Trash2 /> Remove product</button>
      </div>
    </div>
  );
}

function Editor({ item, checks, onDone }: { item: AdvisoryAdmin | null; checks: ApprovedCheck[]; onDone: () => void }) {
  const qc = useQueryClient();
  const start = item?.draft ?? item?.published ?? BLANK;
  const [slug, setSlug] = useState(item?.slug ?? "");
  const [c, setC] = useState<AdvisoryContent>(start);
  const [cves, setCves] = useState(start.cves.join(", "));
  const [refs, setRefs] = useState(start.references.join("\n"));
  const [confirm, setConfirm] = useState<null | "publish" | "archive">(null);
  useEffect(() => { setC(start); setCves(start.cves.join(", ")); setRefs(start.references.join("\n")); }, [item?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const body = (): AdvisoryContent => ({
    ...c, cves: lines(cves), references: lines(refs).filter((r) => !r.includes(",")),
    source_published_at: c.source_published_at || null, source_updated_at: c.source_updated_at || null,
    affected: c.affected.map((p) => ({ ...p, vendor: p.vendor || null })),
  });
  const refresh = () => { qc.invalidateQueries({ queryKey: ["threat-catalog"] }); qc.invalidateQueries({ queryKey: ["threats"] }); };
  const save = useMutation({
    mutationFn: () => item ? api<AdvisoryAdmin>(`/threat-catalog/${item.id}/draft`, { method: "PUT", body: body() })
      : api<AdvisoryAdmin>("/threat-catalog", { method: "POST", body: { slug, content: body() } }),
    onSuccess: refresh,
  });
  const action = useMutation({
    mutationFn: (kind: "publish" | "archive" | "restore") => api(`/threat-catalog/${item!.id}/${kind}`, { method: "POST" }),
    onSuccess: refresh,
  });

  return (
    <Modal wide title={item ? `Edit ${item.slug}` : "New advisory"} onClose={onDone} footer={<>
      <button className="btn" onClick={onDone}>Close</button>
      {item && item.status !== "archived" && item.published_version && <button className="btn" onClick={() => setConfirm("archive")}><Archive /> Archive</button>}
      {item && item.status === "archived" && <button className="btn" onClick={() => action.mutate("restore")}><RotateCcw /> Restore</button>}
      <button className="btn" disabled={save.isPending} onClick={() => save.mutate()}><Save /> Save draft</button>
      {item?.has_draft && <button className="btn primary" disabled={action.isPending} onClick={() => setConfirm("publish")}><Send /> Publish draft</button>}
    </>}>
      <div className="form">
        <ErrorBox error={save.error ?? action.error} />
        {save.isSuccess && <div className="small">Draft saved{item ? "" : " — close and reopen it to publish"}.</div>}
        {item && <div className="small muted">Status <StatusBadge value={item.status} /> · published version {item.published_version ?? "none"}
          {item.draft_version ? ` · editing draft v${item.draft_version}` : ""}. Tenants only ever see published versions; publishing re-evaluates every tenant's inventory.</div>}
        {!item && <Field label="Identifier (lower-case, digits, '-')"><input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="e.g. cve-2024-3400-pan-os" /></Field>}
        <div className="form-row">
          <Field label="Title"><input value={c.title} onChange={(e) => setC({ ...c, title: e.target.value })} /></Field>
          <Field label="Severity">
            <select value={c.severity} onChange={(e) => setC({ ...c, severity: e.target.value })}>{SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select>
          </Field>
          <Field label="Source published"><input type="date" value={day(c.source_published_at)} onChange={(e) => setC({ ...c, source_published_at: e.target.value ? `${e.target.value}T00:00:00Z` : null })} /></Field>
          <Field label="Source updated"><input type="date" value={day(c.source_updated_at)} onChange={(e) => setC({ ...c, source_updated_at: e.target.value ? `${e.target.value}T00:00:00Z` : null })} /></Field>
        </div>
        <Field label="CVE identifiers (comma separated)"><input value={cves} onChange={(e) => setCves(e.target.value)} placeholder="CVE-2024-3400" /></Field>
        <Field label="Summary"><textarea value={c.summary} onChange={(e) => setC({ ...c, summary: e.target.value })} /></Field>
        <Field label="Remediation guidance"><textarea value={c.remediation} onChange={(e) => setC({ ...c, remediation: e.target.value })} /></Field>
        <Field label="Reference links (one per line; shown as links, never fetched)"><textarea value={refs} onChange={(e) => setRefs(e.target.value)} /></Field>
        <div>
          <div className="small muted" style={{ marginBottom: 6 }}>Affected products — matched against names and versions that fingerprinting recorded.</div>
          <div className="stack">
            {c.affected.map((p, i) => (
              <ProductEditor key={i} p={p} onChange={(np) => setC({ ...c, affected: c.affected.map((x, j) => j === i ? np : x) })}
                             onRemove={() => setC({ ...c, affected: c.affected.filter((_, j) => j !== i) })} />
            ))}
            <button className="btn sm" style={{ alignSelf: "flex-start" }} onClick={() => setC({ ...c, affected: [...c.affected, { vendor: "", product: "", match_names: [], versions: [] }] })}><Plus /> Product</button>
          </div>
        </div>
        <Field label="Approved check (optional)">
          <select value={c.check_keys[0] ?? ""} onChange={(e) => setC({ ...c, check_keys: e.target.value ? [e.target.value] : [] })}>
            <option value="">None — assess from inventory only</option>
            {checks.map((k) => <option key={k.key} value={k.key} disabled={!k.enabled}>{k.name}{k.enabled ? "" : " (disabled)"}</option>)}
          </select>
        </Field>
      </div>
      {confirm && <Confirm danger={confirm === "archive"} onClose={() => setConfirm(null)}
                           onConfirm={() => action.mutate(confirm)}
                           text={confirm === "publish" ? "Publish this draft? Every tenant's inventory will be matched against it and tenants whose assets may be affected are notified once."
                             : "Archive this advisory? It stops being evaluated; tenants keep their history and remediation records."} />}
    </Modal>
  );
}

function Checks({ checks }: { checks: ApprovedCheck[] }) {
  const qc = useQueryClient();
  const [edit, setEdit] = useState<Partial<ApprovedCheck> | null>(null);
  const save = useMutation({
    mutationFn: (k: Partial<ApprovedCheck>) => api(`/threat-catalog/checks/${k.key}`, { method: "PUT", body: {
      key: k.key, name: k.name, description: k.description || null, template_id: k.template_id, enabled: k.enabled ?? true } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["threat-catalog"] }); setEdit(null); },
  });
  return (
    <Card flush title="Approved checks" hint="the only detections an advisory can trigger"
          right={<button className="btn sm" onClick={() => setEdit({ enabled: true })}><Plus /> Approve a check</button>}>
      {!checks.length ? <Empty>No approved checks. Advisories without a check are assessed from inventory and existing findings only.</Empty> : (
        <table className="data">
          <thead><tr><th>Check</th><th>Detection id</th><th>State</th><th>Updated</th><th /></tr></thead>
          <tbody>{checks.map((k) => (
            <tr key={k.key}>
              <td><div className="cell-main">{k.name}</div><div className="cell-sub mono">{k.key}</div></td>
              <td className="mono small">{k.template_id}</td>
              <td>{k.enabled ? <span className="badge ok">enabled</span> : <span className="badge neutral">disabled</span>}</td>
              <td className="small">{timeAgo(k.updated_at)}</td>
              <td><button className="btn ghost sm" onClick={() => setEdit(k)}>Edit</button></td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {edit && (
        <Modal title={edit.updated_at ? `Edit ${edit.key}` : "Approve a check"} onClose={() => setEdit(null)} footer={<>
          <button className="btn" onClick={() => setEdit(null)}>Cancel</button>
          <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate(edit)}>Save</button>
        </>}>
          <div className="form">
            <ErrorBox error={save.error} />
            <p className="small muted" style={{ margin: 0 }}>A check names one detection from the deployment's vetted detection set by its identifier. It runs with the
              platform's safe defaults (no intrusive or denial-of-service classes, no out-of-band callbacks), through normal scope authorization.</p>
            <Field label="Identifier"><input value={edit.key ?? ""} disabled={!!edit.updated_at} onChange={(e) => setEdit({ ...edit, key: e.target.value })} placeholder="e.g. cve-2024-3400" /></Field>
            <Field label="Name"><input value={edit.name ?? ""} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></Field>
            <Field label="Detection id"><input value={edit.template_id ?? ""} onChange={(e) => setEdit({ ...edit, template_id: e.target.value })} placeholder="e.g. CVE-2024-3400" /></Field>
            <Field label="Description"><textarea value={edit.description ?? ""} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></Field>
            <label className="row small"><input type="checkbox" checked={edit.enabled ?? true} onChange={(e) => setEdit({ ...edit, enabled: e.target.checked })} /> Enabled</label>
          </div>
        </Modal>
      )}
    </Card>
  );
}

export default function ThreatCatalog() {
  const { can } = useAuth();
  const [open, setOpen] = useState<string | "new" | null>(null);
  const list = useQuery({ queryKey: ["threat-catalog"], queryFn: () => api<AdvisoryAdmin[]>("/threat-catalog"), enabled: can("intel:admin") });
  const checks = useQuery({ queryKey: ["threat-catalog", "checks"], queryFn: () => api<ApprovedCheck[]>("/threat-catalog/checks"), enabled: can("intel:admin") });
  const item = useQuery({ queryKey: ["threat-catalog", open], queryFn: () => api<AdvisoryAdmin>(`/threat-catalog/${open}`),
                          enabled: !!open && open !== "new" });
  if (!can("intel:admin")) return <Card><Empty>Only platform administrators manage the advisory catalog.</Empty></Card>;
  return (
    <>
      <div className="small" style={{ marginBottom: 8 }}><Link to="/threats"><ArrowLeft size={13} /> Threat Center</Link></div>
      <PageHead title="Advisory catalog" sub="Curated advisories shared by every tenant. Only published versions are visible to tenants."
                actions={<button className="btn primary" onClick={() => setOpen("new")}><Plus /> New advisory</button>} />
      <div className="stack">
        <Card flush title="Advisories">
          {list.isLoading ? <Loading /> : list.error ? <div className="card-body"><ErrorBox error={list.error} /></div> :
            !list.data!.length ? <Empty>No advisories yet.</Empty> : (
              <table className="data">
                <thead><tr><th>Severity</th><th>Advisory</th><th>Status</th><th>Published version</th><th>Draft</th><th>Updated</th></tr></thead>
                <tbody>{list.data!.map((a) => (
                  <tr key={a.id} className="clickable" onClick={() => setOpen(a.id)}>
                    <td><SeverityBadge value={a.severity} /></td>
                    <td><div className="cell-main">{a.title}</div><div className="cell-sub mono">{a.slug}</div></td>
                    <td><StatusBadge value={a.status} /></td>
                    <td className="small">{a.published_version ? `v${a.published_version} · ${fmtDate(a.version_published_at)}` : "—"}</td>
                    <td>{a.has_draft ? <span className="badge accent">unpublished changes</span> : <span className="muted">—</span>}</td>
                    <td className="small">{timeAgo(a.updated_at)}</td>
                  </tr>
                ))}</tbody>
              </table>
            )}
        </Card>
        <Checks checks={checks.data ?? []} />
      </div>
      {open === "new" && <Editor item={null} checks={checks.data ?? []} onDone={() => setOpen(null)} />}
      {open && open !== "new" && (item.isLoading ? <Modal title="Loading" onClose={() => setOpen(null)}><Loading /></Modal>
        : item.data && <Editor item={item.data} checks={checks.data ?? []} onDone={() => setOpen(null)} />)}
    </>
  );
}
