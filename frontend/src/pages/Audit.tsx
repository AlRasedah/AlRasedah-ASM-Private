import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck } from "lucide-react";
import { api } from "@/api/client";
import type { AuditEntry, AuditVerification, Page } from "@/api/types";
import { Card, Empty, JsonView, Loading, Modal, PageHead, Pagination } from "@/components/ui";
import { compactDiff, fmtDate } from "@/lib/format";

export default function Audit() {
  const [page, setPage] = useState(1);
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [open, setOpen] = useState<AuditEntry | null>(null);
  const q = useQuery({ queryKey: ["audit", page, action, actor], queryFn: () => api<Page<AuditEntry>>("/audit-logs",
    { query: { page, page_size: 50, action: action || undefined, actor: actor || undefined } }) });
  const verify = useQuery({ queryKey: ["audit-verify"], queryFn: () => api<AuditVerification>("/audit-logs/verify") });
  const v = verify.data;
  return (
    <>
      <PageHead title="Audit log"
                sub="Append-only, hash-chained record of security-relevant actions. # is the entry's position in this tenant's chain."
                actions={v && (v.intact
                  ? <span className="badge ok" title="Every entry is numbered without gaps, links to the previous entry's hash and matches its own hash.">
                      <ShieldCheck size={12} /> Chain intact{v.entries != null ? ` · ${v.entries.toLocaleString()} entries` : ""}</span>
                  : <span className="badge bad" title={v.reason ?? undefined}>
                      <ShieldAlert size={12} /> Integrity check failed at #{v.first_tampered_seq ?? v.first_tampered_id}</span>)} />
      {v && !v.intact && (
        <div className="error-box" style={{ marginBottom: 14 }}>
          The audit chain does not verify from entry #{v.first_tampered_seq ?? v.first_tampered_id} onward: {v.reason}.
          Entries may have been removed or altered outside the application. Preserve the database and investigate.
        </div>
      )}
      <Card flush>
        <div className="filters">
          <select value={action} onChange={(e) => { setAction(e.target.value); setPage(1); }}>
            <option value="">All actions</option>
            {["auth.", "user.", "tenant.", "scope.", "scan.", "finding.", "asset.", "integration.", "credential.", "settings.", "report.", "organization."]
              .map((a) => <option key={a} value={a}>{a.replace(".", "")}</option>)}
          </select>
          <input placeholder="Actor email" value={actor} onChange={(e) => { setActor(e.target.value); setPage(1); }} />
          {(action || actor) && <span className="small subtle">Filtered — numbers skip entries that don't match.</span>}
        </div>
        {q.isLoading ? <Loading /> : !q.data?.items.length ? <Empty>No audit entries.</Empty> : (
          <>
            <table className="data">
              <thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Object</th><th>Change</th><th>IP</th></tr></thead>
              <tbody>{q.data.items.map((a) => (
                <tr key={a.id} className="clickable" onClick={() => setOpen(a)} title="Show full entry">
                  <td className="mono small">{a.chain_seq}</td>
                  <td className="small">{fmtDate(a.created_at)}</td>
                  <td className="small">{a.actor ?? "system"}</td>
                  <td><span className={`badge ${a.success ? "neutral" : "bad"}`}>{a.action}</span></td>
                  <td className="small">{a.object_type}{a.object_id ? <div className="cell-sub mono">{a.object_id.slice(0, 13)}</div> : null}</td>
                  <td className="mono small truncate" style={{ maxWidth: 420 }}>{compactDiff(a.previous, a.new)}</td>
                  <td className="mono small">{a.ip_address ?? ""}</td>
                </tr>
              ))}</tbody>
            </table>
            <Pagination page={page} pageSize={50} total={q.data.total} onPage={setPage} />
          </>
        )}
      </Card>
      {open && <EntryDetail entry={open} onClose={() => setOpen(null)} />}
    </>
  );
}

function EntryDetail({ entry: a, onClose }: { entry: AuditEntry; onClose: () => void }) {
  return (
    <Modal wide title={<>Audit entry #{a.chain_seq}</>} onClose={onClose}
           footer={<button className="btn" onClick={onClose}>Close</button>}>
      <div className="stack">
        <dl className="kv">
          <dt>Action</dt><dd><span className={`badge ${a.success ? "neutral" : "bad"}`}>{a.action}</span>{!a.success && " (failed)"}</dd>
          <dt>Time</dt><dd>{fmtDate(a.created_at)}</dd>
          <dt>Actor</dt><dd>{a.actor ?? "system"}</dd>
          {a.object_type && (<><dt>Object</dt><dd>{a.object_type} <span className="mono small">{a.object_id}</span></dd></>)}
          {a.ip_address && (<><dt>IP address</dt><dd className="mono">{a.ip_address}</dd></>)}
          {a.user_agent && (<><dt>User agent</dt><dd className="small">{a.user_agent}</dd></>)}
          {a.request_id && (<><dt>Request ID</dt><dd className="mono small">{a.request_id}</dd></>)}
          <dt>Record ID</dt><dd className="mono small">{a.id}</dd>
        </dl>
        {a.previous && <div><div className="small subtle" style={{ marginBottom: 6 }}>Before</div><JsonView value={a.previous} /></div>}
        {a.new && <div><div className="small subtle" style={{ marginBottom: 6 }}>After</div><JsonView value={a.new} /></div>}
      </div>
    </Modal>
  );
}
