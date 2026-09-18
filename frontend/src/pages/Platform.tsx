import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { api } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { Card, Confirm, ErrorBox, Field, Loading, Modal, PageHead, StatusBadge } from "@/components/ui";
import { fmtDate } from "@/lib/format";

interface Plan { id: string; code: string; name: string; max_assets: number | null; max_concurrent_scans: number }
interface Tenant { id: string; name: string; slug: string; status: string; worker_pool: string; data_region: string | null; plan: Plan | null; created_at: string }

export default function Platform() {
  const qc = useQueryClient();
  const { me, switchTenant } = useAuth();
  const tenants = useQuery({ queryKey: ["tenants"], queryFn: () => api<Tenant[]>("/tenants") });
  const plans = useQuery({ queryKey: ["plans"], queryFn: () => api<Plan[]>("/tenants/plans") });
  const [open, setOpen] = useState(false);
  const [suspending, setSuspending] = useState<Tenant | null>(null);
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api(`/tenants/${id}`, { method: "PATCH", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["tenants"] }),
  });
  return (
    <>
      <PageHead title="Tenants" sub="Platform administration: tenants, plans (quotas) and sensor pools."
                actions={<button className="btn primary" onClick={() => setOpen(true)}><Plus /> New tenant</button>} />
      <ErrorBox error={update.error} />
      <Card flush>
        {tenants.isLoading ? <Loading /> : (
          <table className="data">
            <thead><tr><th>Tenant</th><th>Plan</th><th>Sensor pool</th><th>Region</th><th>Status</th><th>Created</th><th /></tr></thead>
            <tbody>{tenants.data?.map((t) => (
              <tr key={t.id}>
                <td><div className="cell-main">{t.name}</div><div className="cell-sub mono">{t.slug}</div></td>
                <td><select value={t.plan?.code ?? ""} onChange={(e) => update.mutate({ id: t.id, body: { plan_code: e.target.value } })}>
                  {plans.data?.map((p) => <option key={p.code} value={p.code}>{p.name}</option>)}</select></td>
                <td className="mono small">{t.worker_pool}</td>
                <td className="small">{t.data_region ?? "—"}</td>
                <td><StatusBadge value={t.status === "active" ? "active" : "inactive"} /></td>
                <td className="small">{fmtDate(t.created_at)}</td>
                <td><div className="btn-group">
                  {t.status === "active" && me?.tenant?.id !== t.id && <button className="btn sm" onClick={() => switchTenant(t.id)}>Open</button>}
                  {t.status === "active"
                    ? <button className="btn sm danger" disabled={me?.tenant?.id === t.id} onClick={() => setSuspending(t)}
                              title={me?.tenant?.id === t.id ? "You are signed in to this tenant. Switch to another tenant to suspend it." : undefined}>Suspend</button>
                    : <button className="btn sm" onClick={() => update.mutate({ id: t.id, body: { status: "active" } })}>Reactivate</button>}
                </div></td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
      {suspending && (
        <Confirm danger onClose={() => setSuspending(null)}
                 onConfirm={() => update.mutate({ id: suspending.id, body: { status: "suspended" } })}
                 text={<>Suspend <strong>{suspending.name}</strong>? Every member is signed out immediately and cannot sign in,
                   scheduled scans stop, and its data is kept. You can reactivate it here at any time.</>} />
      )}
      {open && <NewTenant plans={plans.data ?? []} onClose={() => setOpen(false)} />}
    </>
  );
}

function NewTenant({ plans, onClose }: { plans: Plan[]; onClose: () => void }) {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [plan, setPlan] = useState("");
  const [email, setEmail] = useState("");
  const [link, setLink] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: () => api<{ admin_password_reset_token: string | null }>("/tenants", { method: "POST",
      body: { name, plan_code: plan || undefined, admin_email: email || undefined } }),
    onSuccess: (r) => { qc.invalidateQueries({ queryKey: ["tenants"] });
      if (r.admin_password_reset_token) setLink(`${window.location.origin}/reset-password?token=${r.admin_password_reset_token}`); else onClose(); },
  });
  return (
    <Modal title="New tenant" onClose={onClose} footer={link ? <button className="btn primary" onClick={onClose}>Done</button> :
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!name} onClick={() => m.mutate()}>Create</button></>}>
      {link ? (<div className="form"><div className="info-box">Send this one-time link to the tenant administrator:</div>
        <textarea readOnly value={link} onFocus={(e) => e.target.select()} /></div>) : (
        <div className="form">
          <ErrorBox error={m.error} />
          <Field label="Tenant name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Plan"><select value={plan} onChange={(e) => setPlan(e.target.value)}>
            <option value="">Default</option>{plans.map((p) => <option key={p.code} value={p.code}>{p.name}</option>)}</select></Field>
          <Field label="Initial administrator email (optional)"><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
        </div>
      )}
    </Modal>
  );
}
