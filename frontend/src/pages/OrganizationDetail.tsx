import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, BadgeCheck, Plus, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { Organization, ScopeEntry } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Confirm, Empty, ErrorBox, Field, Loading, Modal, PageHead, StatusBadge } from "@/components/ui";
import { fmtDate } from "@/lib/format";

export default function OrganizationDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const { setOrgId } = useOrg();
  const nav = useNavigate();
  const qc = useQueryClient();
  const org = useQuery({ queryKey: ["org", id], queryFn: () => api<Organization>(`/organizations/${id}`) });
  const scope = useQuery({ queryKey: ["scope", id], queryFn: () => api<ScopeEntry[]>("/scopes", { query: { organization_id: id } }) });
  const [adding, setAdding] = useState<"include" | "exclude" | null>(null);
  const [verify, setVerify] = useState<ScopeEntry | null>(null);
  const [removing, setRemoving] = useState<ScopeEntry | null>(null);
  const [deletingOrg, setDeletingOrg] = useState(false);
  const refresh = () => { qc.invalidateQueries({ queryKey: ["scope", id] }); qc.invalidateQueries({ queryKey: ["orgs"] }); };
  const patch = useMutation({
    mutationFn: ({ entry, body }: { entry: ScopeEntry; body: Record<string, unknown> }) => api(`/scopes/${entry.id}`, { method: "PATCH", body }),
    onSuccess: refresh,
  });
  const remove = useMutation({ mutationFn: (e: ScopeEntry) => api(`/scopes/${e.id}`, { method: "DELETE" }), onSuccess: refresh });
  const settings = useMutation({
    mutationFn: (body: Record<string, unknown>) => api(`/organizations/${id}`, { method: "PATCH", body: { settings: body } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["org", id] }),
  });
  const delOrg = useMutation({
    mutationFn: () => api(`/organizations/${id}`, { method: "DELETE" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["orgs"] }); nav("/organizations"); },
  });

  if (org.isLoading) return <Loading />;
  if (org.error) return <ErrorBox error={org.error} />;
  const o = org.data!;
  const includes = scope.data?.filter((e) => !e.is_exclusion) ?? [];
  const excludes = scope.data?.filter((e) => e.is_exclusion) ?? [];
  const s = o.settings as { derived_ip_scanning?: boolean; skip_cdn_ips?: boolean };
  const writable = can("scope:write");

  const table = (rows: ScopeEntry[], exclusion: boolean) => !rows.length ? <Empty>{exclusion ? "No exclusions." : "No scope yet — add the root domains and address ranges you own."}</Empty> : (
    <table className="data">
      <thead><tr><th>Entry</th><th>Type</th>{!exclusion && <th>Subdomains</th>}{!exclusion && <th>Active scanning</th>}
        {!exclusion && <th>Ownership</th>}<th>Added</th><th /></tr></thead>
      <tbody>{rows.map((e) => (
        <tr key={e.id}>
          <td className="mono">{e.value}{e.notes && <div className="cell-sub">{e.notes}</div>}</td>
          <td className="small">{e.entry_type}</td>
          {!exclusion && <td>{e.entry_type === "domain" ? (
            <label className="check small"><input type="checkbox" checked={e.include_subdomains} disabled={!writable}
              onChange={(ev) => patch.mutate({ entry: e, body: { include_subdomains: ev.target.checked } })} /> included</label>) : "—"}</td>}
          {!exclusion && <td><label className="check small"><input type="checkbox" checked={e.allow_active_scanning} disabled={!writable}
            onChange={(ev) => patch.mutate({ entry: e, body: { allow_active_scanning: ev.target.checked } })} /> permitted</label></td>}
          {!exclusion && <td>{e.entry_type === "domain" ? (
            <button className="btn sm ghost" onClick={() => setVerify(e)}><StatusBadge value={e.verification_status} /></button>) : "—"}</td>}
          <td className="small">{fmtDate(e.created_at)}</td>
          <td>{writable && <button className="btn sm danger" onClick={() => setRemoving(e)} aria-label="Remove"><Trash2 /></button>}</td>
        </tr>
      ))}</tbody>
    </table>
  );

  return (
    <>
      <div className="small" style={{ marginBottom: 8 }}><Link to="/organizations"><ArrowLeft size={13} /> Organizations</Link></div>
      <PageHead title={o.name} sub={o.description ?? "Authorized scope and scanning policy"}
        actions={<>
          <button className="btn" onClick={() => { setOrgId(o.id); nav("/inventory"); }}>Inventory</button>
          {can("orgs:write") && <button className="btn danger" onClick={() => setDeletingOrg(true)}><Trash2 /> Delete</button>}
        </>} />
      <div className="grid cols-3">
        <div className="stack span-2">
          <Card title="Authorized scope" hint="Assets outside these entries are never actively scanned"
                right={writable && <button className="btn sm primary" onClick={() => setAdding("include")}><Plus /> Add</button>} flush>
            <ErrorBox error={patch.error ?? remove.error} />
            {table(includes, false)}
          </Card>
          <Card title="Exclusions" hint="Always win over inclusions"
                right={writable && <button className="btn sm" onClick={() => setAdding("exclude")}><Plus /> Add exclusion</button>} flush>
            {table(excludes, true)}
          </Card>
        </div>
        <div className="stack">
          <Card title="Scanning policy">
            <div className="form">
              <ErrorBox error={settings.error} />
              <label className="check"><input type="checkbox" checked={s.derived_ip_scanning ?? true} disabled={!can("orgs:write")}
                onChange={(e) => settings.mutate({ derived_ip_scanning: e.target.checked })} />
                Actively scan IPs that in-scope hostnames resolve to</label>
              <label className="check"><input type="checkbox" checked={s.skip_cdn_ips ?? true} disabled={!can("orgs:write")}
                onChange={(e) => settings.mutate({ skip_cdn_ips: e.target.checked })} />
                Skip port scans of shared CDN / WAF edge addresses</label>
              <div className="small muted">Resolved IPs may be shared hosting. Disable derived scanning if you only want explicitly listed
                ranges to be contacted.</div>
            </div>
          </Card>
          <ScopeCheck orgId={o.id} />
        </div>
      </div>
      {adding && <AddScope orgId={o.id} exclusion={adding === "exclude"} onClose={() => setAdding(null)} onDone={refresh} />}
      {verify && <Verification entry={verify} onClose={() => setVerify(null)} onDone={refresh} />}
      {removing && <Confirm danger text={<>Remove <code>{removing.value}</code> from scope? Existing assets are kept but will no longer be scanned actively.</>}
                            onClose={() => setRemoving(null)} onConfirm={() => remove.mutate(removing)} />}
      {deletingOrg && <Confirm danger text={<>Delete <strong>{o.name}</strong> and <strong>all</strong> of its assets, findings and history? This cannot be undone.</>}
                               onClose={() => setDeletingOrg(false)} onConfirm={() => delOrg.mutate()} />}
    </>
  );
}

function AddScope({ orgId, exclusion, onClose, onDone }: { orgId: string; exclusion: boolean; onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState("");
  const [active, setActive] = useState(true);
  const m = useMutation({
    mutationFn: () => api<ScopeEntry[]>("/scopes/bulk", { method: "POST", body: { organization_id: orgId,
      entries: text.split(/[\s,;]+/).filter(Boolean), is_exclusion: exclusion, allow_active_scanning: active } }),
    onSuccess: () => { onDone(); onClose(); },
  });
  return (
    <Modal title={exclusion ? "Add exclusions" : "Add authorized scope"} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!text.trim()} onClick={() => m.mutate()}>Add</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <Field label="Domains, IP addresses or CIDR ranges (one per line)">
          <textarea style={{ minHeight: 160 }} placeholder={"example.com\nexample.com.sa\n203.0.113.0/24"} value={text} onChange={(e) => setText(e.target.value)} />
        </Field>
        {!exclusion && <label className="check"><input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
          Permit active scanning (port discovery, web fingerprinting, vulnerability detection)</label>}
        <div className="info-box small"><ShieldCheck size={14} /> Only add assets your organization owns or is explicitly authorized to test.
          Additions are recorded in the audit log.</div>
      </div>
    </Modal>
  );
}

function Verification({ entry, onClose, onDone }: { entry: ScopeEntry; onClose: () => void; onDone: () => void }) {
  const q = useQuery({ queryKey: ["verification", entry.id], queryFn: () => api<{ record_type: string; name: string; value: string; status: string }>(`/scopes/${entry.id}/verification`) });
  const m = useMutation({ mutationFn: () => api<ScopeEntry>(`/scopes/${entry.id}/verify`, { method: "POST" }), onSuccess: onDone });
  return (
    <Modal title={`Verify ownership of ${entry.value}`} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Close</button><button className="btn primary" onClick={() => m.mutate()}><BadgeCheck /> Check now</button></>}>
      {q.data && (
        <div className="form">
          <p style={{ margin: 0 }}>Publish this DNS record, then select <em>Check now</em>:</p>
          <dl className="kv">
            <dt>Type</dt><dd className="mono">{q.data.record_type}</dd>
            <dt>Name</dt><dd className="mono">{q.data.name}</dd>
            <dt>Value</dt><dd className="mono">{q.data.value}</dd>
          </dl>
          <ErrorBox error={m.error} />
          {m.data && <div className="info-box">Status: <StatusBadge value={m.data.verification_status} />
            {m.data.verification_status !== "verified" && " — record not found yet (DNS changes can take time to propagate)."}</div>}
        </div>
      )}
    </Modal>
  );
}

function ScopeCheck({ orgId }: { orgId: string }) {
  const [target, setTarget] = useState("");
  const m = useMutation({
    mutationFn: () => api<{ target: string; allowed: boolean; reason: string; scope_status: string }>("/scopes/check",
      { method: "POST", body: { organization_id: orgId, target, active: true } }),
  });
  return (
    <Card title="Scope checker">
      <div className="form">
        <div className="row"><input style={{ flex: 1 }} placeholder="host, IP, CIDR or URL" value={target} onChange={(e) => setTarget(e.target.value)} />
          <button className="btn" disabled={!target} onClick={() => m.mutate()}>Check</button></div>
        <ErrorBox error={m.error} />
        {m.data && <div className={m.data.allowed ? "info-box" : "error-box"}>
          <strong>{m.data.allowed ? "Authorized for active scanning" : "Not authorized"}</strong><div className="small">{m.data.reason}</div></div>}
      </div>
    </Card>
  );
}
