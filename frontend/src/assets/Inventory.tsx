import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FilterX, Tags as TagsIcon } from "lucide-react";
import { api, download } from "@/api/client";
import type { Asset, Facets, Page } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import {
  Card, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pagination, RiskScore, SortTh, StatusBadge, Tags, useDebounced,
} from "@/components/ui";
import { useTenantEmpty } from "@/components/TenantEmpty";
import { APPROVAL_STATES, ASSET_TYPE_LABELS, PRIMARY_TYPES, SEVERITIES, fmtDay, timeAgo } from "@/lib/format";
import { useFilters } from "@/lib/useFilters";

const MULTI = ["asset_type", "approval", "severity", "tag"] as const;
type Key = "asset_type" | "approval" | "severity" | "tag" | "status" | "unknown" | "owner" | "business_unit" | "technology" |
  "asn" | "risk_min" | "risk_max" | "first_seen_after" | "q" | "sort" | "order" | "page" | "include_third_party";

export default function Inventory() {
  const f = useFilters<Key>(MULTI);
  const { orgId } = useOrg();
  const { can } = useAuth();
  const tenantEmpty = useTenantEmpty();
  const nav = useNavigate();
  const qc = useQueryClient();
  const [search, setSearch] = useState(f.get("q") ?? "");
  const q = useDebounced(search, 350);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkOpen, setBulkOpen] = useState(false);

  const types = f.getAll("asset_type");
  const query = {
    ...f.query,
    asset_type: types.length ? types : PRIMARY_TYPES,
    q: q || undefined,
    organization_id: orgId,
    page: f.page,
    page_size: 50,
  };
  const assets = useQuery({ queryKey: ["assets", query], queryFn: () => api<Page<Asset>>("/assets", { query }) });
  const facets = useQuery({ queryKey: ["facets", orgId], queryFn: () => api<Facets>("/assets/facets", { query: { organization_id: orgId } }) });

  const sort = f.get("sort") ?? "risk";
  const order = f.get("order") ?? "desc";
  const th = (key: string, text: string, cls = "") => (
    <SortTh id={key} sort={sort} order={order} className={cls} onSort={(s, o) => f.setMany({ sort: s, order: o })}>{text}</SortTh>
  );
  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <>
      <PageHead title="Asset inventory" sub="Every internet-facing asset discovered for your organizations, with ownership and risk."
        actions={<>
          {can("assets:write") && selected.size > 0 && (
            <button className="btn" onClick={() => setBulkOpen(true)}><TagsIcon /> Update {selected.size} selected</button>
          )}
          <button className="btn" onClick={() => download("/assets/export.csv", { ...query, page: undefined, page_size: undefined }, "assets.csv")}>
            <Download /> Export CSV
          </button>
        </>} />
      <Card flush>
        <div className="filters">
          <input type="search" placeholder="Search assets, titles, owners…" value={search}
                 onChange={(e) => { setSearch(e.target.value); f.set("q", e.target.value || undefined); }} />
          <select value={types[0] ?? ""} onChange={(e) => f.set("asset_type", e.target.value ? [e.target.value] : undefined)}>
            <option value="">All asset types</option>
            {PRIMARY_TYPES.concat(["service", "technology", "asn"]).map((t) => <option key={t} value={t}>{ASSET_TYPE_LABELS[t]}</option>)}
          </select>
          <select value={f.get("status") ?? ""} onChange={(e) => f.set("status", e.target.value || undefined)}>
            <option value="">Active & inactive</option>
            <option value="active">Active</option>
            <option value="inactive">Inactive</option>
          </select>
          <select value={f.get("unknown") ?? f.getAll("approval")[0] ?? ""} onChange={(e) => {
            const v = e.target.value;
            if (v === "true" || v === "false") f.setMany({ approval: undefined, unknown: v });
            else f.setMany({ unknown: undefined, approval: v ? [v] : undefined });
          }}>
            <option value="">Any approval</option>
            <option value="true">Unknown / unverified</option>
            <option value="false">Known</option>
            {APPROVAL_STATES.map((a) => <option key={a} value={a}>{a.replace(/_/g, " ")}</option>)}
          </select>
          <select value={f.getAll("severity")[0] ?? ""} onChange={(e) => f.set("severity", e.target.value ? [e.target.value] : undefined)}>
            <option value="">Any findings</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>Has {s} finding</option>)}
          </select>
          <select value={f.get("technology") ?? ""} onChange={(e) => f.set("technology", e.target.value || undefined)}>
            <option value="">Any technology</option>
            {facets.data?.technologies.map((t) => <option key={t.value} value={t.value}>{t.value} ({t.count})</option>)}
          </select>
          <select value={f.get("asn") ?? ""} onChange={(e) => f.set("asn", e.target.value || undefined)}>
            <option value="">Any network</option>
            {facets.data?.asns.map((t) => <option key={t.value} value={t.value}>{t.value} ({t.count})</option>)}
          </select>
          <select value={f.getAll("tag")[0] ?? ""} onChange={(e) => f.set("tag", e.target.value ? [e.target.value] : undefined)}>
            <option value="">Any tag</option>
            {facets.data?.tags.map((t) => <option key={t.value} value={t.value}>{t.value}</option>)}
          </select>
          <input placeholder="Owner" style={{ width: 130 }} defaultValue={f.get("owner")} onBlur={(e) => f.set("owner", e.target.value || undefined)} />
          <input placeholder="Business unit" style={{ width: 130 }} defaultValue={f.get("business_unit")} onBlur={(e) => f.set("business_unit", e.target.value || undefined)} />
          <input type="number" min={0} max={100} placeholder="Risk ≥" style={{ width: 80 }} defaultValue={f.get("risk_min")}
                 onBlur={(e) => f.set("risk_min", e.target.value || undefined)} />
          <label className="small muted row">First seen after
            <input type="date" defaultValue={f.get("first_seen_after")?.slice(0, 10)}
                   onChange={(e) => f.set("first_seen_after", e.target.value ? `${e.target.value}T00:00:00Z` : undefined)} />
          </label>
          <label className="check small"><input type="checkbox" checked={f.get("include_third_party") === "true"}
                 onChange={(e) => f.set("include_third_party", e.target.checked ? "true" : undefined)} /> Third-party</label>
          <button className="btn ghost sm" onClick={() => { f.clear(); setSearch(""); }}><FilterX /> Reset</button>
        </div>
        {assets.isLoading ? <Loading /> : assets.error ? <div className="card-body"><ErrorBox error={assets.error} /></div> : (
          assets.data!.items.length === 0 ? (tenantEmpty ?? <Empty>No assets match these filters.</Empty>) : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead>
                    <tr>
                      {can("assets:write") && (
                        <th style={{ width: 30 }}>
                          <input type="checkbox" aria-label="Select all"
                                 checked={assets.data!.items.every((a) => selected.has(a.id))}
                                 onChange={(e) => setSelected(e.target.checked ? new Set(assets.data!.items.map((a) => a.id)) : new Set())} />
                        </th>
                      )}
                      {th("value", "Asset")}
                      {th("type", "Type")}
                      <th>IP</th>
                      {th("status", "Status")}
                      {th("owner", "Owner")}
                      {th("first_seen", "First seen")}
                      {th("last_seen", "Last seen")}
                      {th("risk", "Risk")}
                      {th("findings", "Findings", "num")}
                      <th>Tags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assets.data!.items.map((a) => (
                      <tr key={a.id} className="clickable" onClick={() => nav(`/assets/${a.id}`)}>
                        {can("assets:write") && (
                          <td onClick={(e) => e.stopPropagation()}>
                            <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggle(a.id)} aria-label={`Select ${a.value}`} />
                          </td>
                        )}
                        <td>
                          <div className="cell-main"><Link to={`/assets/${a.id}`} onClick={(e) => e.stopPropagation()}>{a.value}</Link></div>
                          {a.title && <div className="cell-sub truncate" style={{ maxWidth: 360 }}>{a.title}</div>}
                        </td>
                        <td className="small">{ASSET_TYPE_LABELS[a.asset_type] ?? a.asset_type}</td>
                        <td className="mono small">{a.ips.slice(0, 2).join(", ") || "—"}{a.ips.length > 2 ? ` +${a.ips.length - 2}` : ""}</td>
                        <td><div className="row"><StatusBadge value={a.status} /><StatusBadge value={a.approval_status} /></div></td>
                        <td className="small">{a.owner ?? <span className="muted">Unknown</span>}</td>
                        <td className="small" title={a.first_seen}>{fmtDay(a.first_seen)}</td>
                        <td className="small" title={a.last_seen}>{timeAgo(a.last_seen)}</td>
                        <td><RiskScore score={a.risk_score} /></td>
                        <td className="num">{a.open_findings || <span className="muted">0</span>}</td>
                        <td><Tags tags={a.tags} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={f.page} pageSize={50} total={assets.data!.total} onPage={f.setPage} />
            </>
          )
        )}
      </Card>
      {bulkOpen && <BulkUpdate ids={[...selected]} onClose={() => setBulkOpen(false)}
                               onDone={() => { setSelected(new Set()); qc.invalidateQueries({ queryKey: ["assets"] }); }} />}
    </>
  );
}

export function BulkUpdate({ ids, onClose, onDone }: { ids: string[]; onClose: () => void; onDone: () => void }) {
  const [approval, setApproval] = useState("");
  const [owner, setOwner] = useState("");
  const [bu, setBu] = useState("");
  const [criticality, setCriticality] = useState("");
  const [tags, setTags] = useState("");
  const m = useMutation({
    mutationFn: () => {
      const changes: Record<string, unknown> = {};
      if (approval) changes.approval_status = approval;
      if (owner) changes.owner = owner;
      if (bu) changes.business_unit = bu;
      if (criticality) changes.criticality = criticality;
      return api("/assets/bulk-update", { method: "POST", body: { asset_ids: ids, changes,
        add_tags: tags ? tags.split(",").map((t) => t.trim()).filter(Boolean) : undefined } });
    },
    onSuccess: () => { onDone(); onClose(); },
  });
  return (
    <Modal title={`Update ${ids.length} asset(s)`} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={m.isPending} onClick={() => m.mutate()}>Apply</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <div className="form-row">
          <Field label="Approval">
            <select value={approval} onChange={(e) => setApproval(e.target.value)}>
              <option value="">(unchanged)</option>
              {APPROVAL_STATES.map((a) => <option key={a} value={a}>{a.replace(/_/g, " ")}</option>)}
            </select>
          </Field>
          <Field label="Criticality">
            <select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
              <option value="">(unchanged)</option>
              {["low", "medium", "high", "critical"].map((c) => <option key={c}>{c}</option>)}
            </select>
          </Field>
        </div>
        <div className="form-row">
          <Field label="Owner"><input value={owner} onChange={(e) => setOwner(e.target.value)} placeholder="(unchanged)" /></Field>
          <Field label="Business unit"><input value={bu} onChange={(e) => setBu(e.target.value)} placeholder="(unchanged)" /></Field>
        </div>
        <Field label="Add tags (comma separated)"><input value={tags} onChange={(e) => setTags(e.target.value)} /></Field>
      </div>
    </Modal>
  );
}
