import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play } from "lucide-react";
import { api } from "@/api/client";
import type { Page, Scan, ScanProfile } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Field, Loading, Modal, PageHead, Pagination, StatusBadge } from "@/components/ui";
import { useTenantEmpty } from "@/components/TenantEmpty";
import { fmtDate, label } from "@/lib/format";

export default function Scans() {
  const { orgId, orgName } = useOrg();
  const { can } = useAuth();
  const tenantEmpty = useTenantEmpty();
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState(false);
  const q = useQuery({
    queryKey: ["scans", orgId, page],
    queryFn: () => api<Page<Scan>>("/scans", { query: { organization_id: orgId, page, page_size: 25 } }),
    refetchInterval: (query) => (query.state.data?.items.some((s) => ["pending", "queued", "running"].includes(s.status)) ? 5000 : 30000),
  });

  return (
    <>
      <PageHead title="Scans" sub="Discovery and exposure scans. Every target is checked against the authorized scope before it is contacted."
                actions={can("scans:run") && <button className="btn primary" onClick={() => setOpen(true)}><Play /> New scan</button>} />
      <Card flush>
        {q.isLoading ? <Loading /> : !q.data?.items.length ? (tenantEmpty ?? <Empty>No scans yet.</Empty>) : (
          <>
            <table className="data">
              <thead><tr><th>Started</th><th>Organization</th><th>Profile</th><th>Status</th><th>Trigger</th>
                <th className="num">New assets</th><th className="num">New findings</th><th className="num">Changes</th><th>Finished</th></tr></thead>
              <tbody>
                {q.data.items.map((s) => (
                  <tr key={s.id}>
                    <td><Link to={`/scans/${s.id}`}>{fmtDate(s.started_at ?? s.created_at)}</Link>
                      {s.is_baseline && <span className="badge neutral" style={{ marginInlineStart: 6 }}>baseline</span>}</td>
                    <td>{orgName(s.organization_id)}</td>
                    <td>{s.profile_name}</td>
                    <td><StatusBadge value={s.status} /></td>
                    <td className="small">{label(s.trigger)}</td>
                    <td className="num">{s.stats.new_assets ?? 0}</td>
                    <td className="num">{s.stats.new_findings ?? 0}</td>
                    <td className="num">{s.stats.events ?? 0}</td>
                    <td className="small">{fmtDate(s.finished_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={25} total={q.data.total} onPage={setPage} />
          </>
        )}
      </Card>
      {open && <NewScan onClose={() => setOpen(false)} />}
    </>
  );
}

function NewScan({ onClose }: { onClose: () => void }) {
  const { orgs, orgId } = useOrg();
  const nav = useNavigate();
  const qc = useQueryClient();
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api<ScanProfile[]>("/scan-profiles") });
  const [org, setOrg] = useState(orgId ?? orgs[0]?.id ?? "");
  const [profile, setProfile] = useState("");
  const [targets, setTargets] = useState("");
  const [authSecret, setAuthSecret] = useState("");
  const [authHeader, setAuthHeader] = useState<"Cookie" | "Authorization">("Cookie");
  const selected = profiles.data?.find((p) => p.id === (profile || profiles.data?.[0]?.id));
  // Only stages that can sign in offer the field (the API says which; engines are not exposed).
  const webAppStage = selected?.stages.some((s) => s.enabled && s.accepts_login);
  const m = useMutation({
    mutationFn: () => api<Scan>("/scans", { method: "POST", body: {
      organization_id: org, profile_id: selected?.id,
      targets: targets.trim() ? targets.split(/[\s,]+/).filter(Boolean) : undefined,
      auth_secret: webAppStage && authSecret.trim() ? authSecret.trim() : undefined,
      auth_header_name: authHeader } }),
    onSuccess: (s) => { qc.invalidateQueries({ queryKey: ["scans"] }); nav(`/scans/${s.id}`); },
  });
  return (
    <Modal title="Start a scan" onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!org || !selected || m.isPending} onClick={() => m.mutate()}><Play /> Start scan</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <Field label="Organization">
          <select value={org} onChange={(e) => setOrg(e.target.value)}>
            {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
          </select>
        </Field>
        <Field label="Scan profile">
          <select value={selected?.id ?? ""} onChange={(e) => setProfile(e.target.value)}>
            {profiles.data?.map((p) => <option key={p.id} value={p.id}>{p.name}{p.is_builtin ? "" : " (custom)"}</option>)}
          </select>
        </Field>
        {selected && (
          <div className="info-box small">
            {selected.description}
            <div style={{ marginTop: 6 }}>
              {selected.stages.filter((s) => s.enabled).map((s, i) => (
                <span key={i} className="tag">{s.label}{s.active ? " · active" : ""}</span>
              ))}
            </div>
            {selected.is_active_scanning && <div style={{ marginTop: 6 }}>This profile sends traffic to in-scope hosts. Only targets
              inside the authorized scope that permit active scanning will be contacted.</div>}
          </div>
        )}
        <Field label="Limit to specific targets (optional)">
          <textarea placeholder="api.example.com, 203.0.113.10" value={targets} onChange={(e) => setTargets(e.target.value)} />
        </Field>
        {webAppStage && (
          <>
            <Field label={`Sign in with a ${authHeader === "Cookie" ? "session cookie" : "token"} (optional)`}>
              <div className="filters" style={{ padding: 0 }}>
                <select value={authHeader} onChange={(e) => setAuthHeader(e.target.value as "Cookie" | "Authorization")}
                        aria-label="Send the value as this header">
                  <option value="Cookie">Cookie</option>
                  <option value="Authorization">Authorization</option>
                </select>
                <input type="password" autoComplete="off" style={{ flex: 1, minWidth: 260 }}
                       placeholder={authHeader === "Cookie" ? "PHPSESSID=abc123; security=low" : "Bearer eyJhbGci…"}
                       value={authSecret} onChange={(e) => setAuthSecret(e.target.value)} />
              </div>
            </Field>
            <div className="small muted">Paste a logged-in session from your browser and the web application scanner
              tests the pages behind the login. It is sent only to the authorized origin, stored encrypted, used for
              this scan only, and erased when the scan ends. Sessions expire, so start the scan soon after copying it.</div>
          </>
        )}
      </div>
    </Modal>
  );
}
