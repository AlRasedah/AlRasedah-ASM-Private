import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { api } from "@/api/client";
import type { Organization } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Field, Modal, PageHead, RiskScore } from "@/components/ui";
import { fmtDate } from "@/lib/format";

export default function Organizations() {
  const { orgs } = useOrg();
  const { can } = useAuth();
  const [open, setOpen] = useState(false);
  return (
    <>
      <PageHead title="Organizations & authorized scope"
                sub="Each organization's scope defines exactly which domains, IPs and networks may be monitored and scanned."
                actions={can("orgs:write") && <button className="btn primary" onClick={() => setOpen(true)}><Plus /> New organization</button>} />
      <Card flush>
        {!orgs.length ? <Empty>No organizations yet.</Empty> : (
          <table className="data">
            <thead><tr><th>Organization</th><th className="num">Scope entries</th><th className="num">Active assets</th>
              <th className="num">Open findings</th><th>Risk</th><th>Baseline</th><th>Last scan</th></tr></thead>
            <tbody>{orgs.map((o) => (
              <tr key={o.id}>
                <td><div className="cell-main"><Link to={`/organizations/${o.id}`}>{o.name}</Link></div>
                  <div className="cell-sub">{o.industry ?? ""}</div></td>
                <td className="num">{o.scope_entries}</td>
                <td className="num">{o.assets}</td>
                <td className="num">{o.open_findings}</td>
                <td><RiskScore score={o.risk_score ?? 0} /></td>
                <td className="small">{o.baseline_completed_at ? fmtDate(o.baseline_completed_at) : <span className="muted">not yet</span>}</td>
                <td className="small">{fmtDate(o.last_scan_at)}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
      {open && <NewOrg onClose={() => setOpen(false)} />}
    </>
  );
}

function NewOrg({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [name, setName] = useState("");
  const [industry, setIndustry] = useState("");
  const [description, setDescription] = useState("");
  const m = useMutation({
    mutationFn: () => api<Organization>("/organizations", { method: "POST", body: { name, industry: industry || null, description: description || null } }),
    onSuccess: (o) => { qc.invalidateQueries({ queryKey: ["orgs"] }); nav(`/organizations/${o.id}`); },
  });
  return (
    <Modal title="New organization" onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!name} onClick={() => m.mutate()}>Create</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} autoFocus /></Field>
        <Field label="Industry"><input value={industry} onChange={(e) => setIndustry(e.target.value)} /></Field>
        <Field label="Description"><input value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
      </div>
    </Modal>
  );
}
