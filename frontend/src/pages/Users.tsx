import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { UserPlus } from "lucide-react";
import { api } from "@/api/client";
import type { Member } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { Card, Confirm, ErrorBox, Field, Loading, Modal, PageHead, StatusBadge } from "@/components/ui";
import { fmtDate, label, timeAgo } from "@/lib/format";

const ROLES = ["viewer", "security_analyst", "tenant_admin"];

export default function UsersPage() {
  const { can, me } = useAuth();
  const qc = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<Member[]>("/users") });
  const [open, setOpen] = useState(false);
  const update = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api(`/users/${id}`, { method: "PATCH", body }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });
  const remove = useMutation({ mutationFn: (id: string) => api(`/users/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }) });
  const resetMfa = useMutation({ mutationFn: (id: string) => api<{ message: string }>(`/users/${id}/mfa/reset`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }) });
  const [confirm, setConfirm] = useState<{ text: ReactNode; run: () => void; danger?: boolean } | null>(null);
  const who = (u: Member) => <strong>{u.full_name || u.email}</strong>;

  return (
    <>
      <PageHead title="Users" sub="Tenant members and roles. Role changes take effect immediately and are audited."
                actions={can("users:write") && <button className="btn primary" onClick={() => setOpen(true)}><UserPlus /> Add user</button>} />
      <ErrorBox error={update.error ?? remove.error ?? resetMfa.error} />
      {resetMfa.data && <div className="info-box" style={{ marginBottom: 14 }}>{resetMfa.data.message}</div>}
      <Card flush>
        {users.isLoading ? <Loading /> : (
          <table className="data">
            <thead><tr><th>User</th><th>Role</th><th>State</th><th>MFA</th><th>Last sign-in</th><th>Member since</th><th /></tr></thead>
            <tbody>{users.data?.map((u) => (
              <tr key={u.user_id}>
                <td><div className="cell-main">{u.full_name || u.email}</div><div className="cell-sub">{u.email}</div></td>
                <td>{can("users:write") && u.user_id !== me?.user.id ? (
                  <select value={u.role} onChange={(e) => update.mutate({ id: u.user_id, body: { role: e.target.value } })}>
                    {ROLES.map((r) => <option key={r} value={r}>{label(r)}</option>)}</select>) : label(u.role)}</td>
                <td><StatusBadge value={u.is_active ? "active" : "inactive"} /></td>
                <td>{u.mfa_enabled ? <span className="badge ok">on</span> : <span className="badge warn">off</span>}</td>
                <td className="small">{timeAgo(u.last_login_at)}</td>
                <td className="small">{fmtDate(u.created_at)}</td>
                <td>{u.user_id === me?.user.id ? <span className="small subtle">You · <Link to="/account">manage in Account</Link></span>
                  : can("users:write") && <div className="btn-group">
                  {u.is_active
                    ? <button className="btn sm" onClick={() => setConfirm({ text: <>Deactivate {who(u)}? They are signed out and cannot sign in to this tenant until reactivated.</>,
                        run: () => update.mutate({ id: u.user_id, body: { is_active: false } }) })}>Deactivate</button>
                    : <button className="btn sm" onClick={() => update.mutate({ id: u.user_id, body: { is_active: true } })}>Activate</button>}
                  {u.mfa_enabled && <button className="btn sm" onClick={() => setConfirm({ danger: true,
                    text: <>Reset two-factor authentication for {who(u)}? Use this when they have lost their authenticator.
                      They are signed out everywhere and can sign in with their password only until they set up MFA again.</>,
                    run: () => resetMfa.mutate(u.user_id) })}>Reset MFA</button>}
                  <button className="btn sm danger" onClick={() => setConfirm({ danger: true,
                    text: <>Remove {who(u)} from this tenant? Their access ends immediately; their past actions stay in the audit log.</>,
                    run: () => remove.mutate(u.user_id) })}>Remove</button></div>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
      {open && <AddUser onClose={() => setOpen(false)} />}
      {confirm && <Confirm danger={confirm.danger} text={confirm.text} onClose={() => setConfirm(null)} onConfirm={confirm.run} />}
    </>
  );
}

function AddUser({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("viewer");
  const [link, setLink] = useState<string | null>(null);
  const m = useMutation({
    mutationFn: () => api<{ password_reset_token: string | null }>("/users", { method: "POST", body: { email, full_name: name || null, role } }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["users"] });
      if (r.password_reset_token) setLink(`${window.location.origin}/reset-password?token=${r.password_reset_token}`);
      else onClose();
    },
  });
  return (
    <Modal title="Add user" onClose={onClose} footer={link ? <button className="btn primary" onClick={onClose}>Done</button> :
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!email} onClick={() => m.mutate()}>Add</button></>}>
      {link ? (
        <div className="form">
          <div className="info-box">Email delivery is not configured. Send this one-time link to the user over a trusted channel (valid 3 days):</div>
          <textarea readOnly value={link} onFocus={(e) => e.target.select()} />
        </div>
      ) : (
        <div className="form">
          <ErrorBox error={m.error} />
          <Field label="Email"><input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus /></Field>
          <Field label="Full name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Role"><select value={role} onChange={(e) => setRole(e.target.value)}>
            {ROLES.map((r) => <option key={r} value={r}>{label(r)}</option>)}</select></Field>
          <div className="small muted">Viewer: read-only · Security analyst: triage, scans, reports · Tenant admin: scope, users, integrations, settings.</div>
        </div>
      )}
    </Modal>
  );
}
