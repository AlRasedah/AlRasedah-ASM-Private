import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, ShieldCheck, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { Card, Confirm, Empty, ErrorBox, Field, Loading, PageHead } from "@/components/ui";
import { fmtDate, label, timeAgo } from "@/lib/format";

interface Token { id: string; name: string; token_prefix: string; role: string; expires_at: string | null; last_used_at: string | null; revoked_at: string | null; created_at: string }

export default function Account() {
  const { me, reload } = useAuth();
  return (
    <>
      <PageHead title="Your account" sub={me?.user.email} />
      <div className="grid cols-2">
        <PasswordCard />
        <MfaCard enabled={!!me?.user.mfa_enabled} onChange={reload} />
        <div className="span-2"><AlertsCard /></div>
        <div className="span-2"><TokensCard /></div>
      </div>
    </>
  );
}

function PasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const m = useMutation({
    mutationFn: () => api("/auth/password/change", { method: "POST", body: { current_password: current, new_password: next } }),
    onSuccess: () => { window.location.href = "/login"; },
  });
  return (
    <Card title="Change password">
      <div className="form">
        <ErrorBox error={m.error} />
        <Field label="Current password"><input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></Field>
        <Field label="New password"><input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></Field>
        <div className="small muted">Changing your password signs out all of your sessions.</div>
        <button className="btn primary" disabled={!current || !next} onClick={() => m.mutate()}><KeyRound /> Change password</button>
      </div>
    </Card>
  );
}

function MfaCard({ enabled, onChange }: { enabled: boolean; onChange: () => Promise<void> }) {
  const [setup, setSetup] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const begin = useMutation({ mutationFn: () => api<{ secret: string; otpauth_uri: string }>("/auth/mfa/setup", { method: "POST", body: { password } }),
    onSuccess: (r) => { setSetup(r); setPassword(""); } });
  const enable = useMutation({ mutationFn: () => api("/auth/mfa/enable", { method: "POST", body: { code } }),
    onSuccess: async () => { setSetup(null); setCode(""); await onChange(); } });
  const disable = useMutation({ mutationFn: () => api("/auth/mfa/disable", { method: "POST", body: { password, code } }),
    onSuccess: async () => { setCode(""); setPassword(""); await onChange(); } });
  return (
    <Card title="Two-factor authentication" right={enabled ? <span className="badge ok"><ShieldCheck size={12} /> enabled</span> : <span className="badge warn">disabled</span>}>
      <div className="form">
        <ErrorBox error={begin.error ?? enable.error ?? disable.error} />
        {!enabled && !setup && <>
          <div className="muted">Protect your account with a time-based one-time code (TOTP) from an authenticator app.</div>
          <Field label="Confirm your password"><input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          <button className="btn primary" disabled={!password} onClick={() => begin.mutate()}>Set up authenticator</button>
        </>}
        {!enabled && setup && <>
          <div>Add this key to your authenticator app, then enter the 6-digit code it shows:</div>
          <div className="mono" style={{ wordBreak: "break-all", fontSize: 15 }}>{setup.secret.match(/.{1,4}/g)?.join(" ")}</div>
          <details><summary className="small muted">otpauth URI</summary><code className="small" style={{ wordBreak: "break-all" }}>{setup.otpauth_uri}</code></details>
          <Field label="Code"><input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.trim())} /></Field>
          <button className="btn primary" disabled={code.length < 6} onClick={() => enable.mutate()}>Verify and enable</button>
        </>}
        {enabled && <>
          <Field label="Password"><input type="password" value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
          <Field label="Current code"><input inputMode="numeric" value={code} onChange={(e) => setCode(e.target.value.trim())} /></Field>
          <button className="btn danger" disabled={!password || code.length < 6} onClick={() => disable.mutate()}>Disable two-factor</button>
        </>}
      </div>
    </Card>
  );
}

interface MyAlerts {
  enabled: boolean; min_severity: string; event_types: string[]; organization_ids: string[];
  include_baseline: boolean; email: string; email_configured: boolean; is_default: boolean;
}

/** Alerts to the signed-in user's own login address — no mail server access needed. */
function AlertsCard() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["my-alerts"], queryFn: () => api<MyAlerts>("/settings/my-alerts") });
  const [draft, setDraft] = useState<MyAlerts | null>(null);
  const prefs = draft ?? q.data;
  const save = useMutation({
    mutationFn: (body: Partial<MyAlerts>) => api<MyAlerts>("/settings/my-alerts", { method: "PUT", body: {
      enabled: body.enabled, min_severity: body.min_severity, include_baseline: body.include_baseline,
      event_types: [], organization_ids: [] } }),
    onSuccess: (r) => { setDraft(r); qc.invalidateQueries({ queryKey: ["my-alerts"] }); },
  });
  if (q.isLoading || !prefs) return <Card title="Email alerts"><Loading /></Card>;
  const update = (patch: Partial<MyAlerts>) => { const next = { ...prefs, ...patch }; setDraft(next); save.mutate(next); };
  return (
    <Card title="Email alerts" hint={`sent to ${prefs.email}`}>
      <div className="form">
        <ErrorBox error={save.error} />
        {!prefs.email_configured &&
          <div className="info-box">Email delivery is not set up yet — ask a platform administrator to configure the
            mail server in Settings → Email delivery. Your choice here is saved and used as soon as it is.</div>}
        <label className="check"><input type="checkbox" checked={prefs.enabled}
          onChange={(e) => update({ enabled: e.target.checked })} /> Email me when my attack surface changes</label>
        <Field label="Only at this severity or above">
          <select value={prefs.min_severity} disabled={!prefs.enabled}
                  onChange={(e) => update({ min_severity: e.target.value })}>
            {["critical", "high", "medium", "low", "info"].map((s) => <option key={s} value={s}>{label(s)}</option>)}
          </select>
        </Field>
        <label className="check"><input type="checkbox" checked={prefs.include_baseline} disabled={!prefs.enabled}
          onChange={(e) => update({ include_baseline: e.target.checked })} /> Include the first (baseline) scan of an organization</label>
        <div className="small muted">Alerts cover the organizations of the tenant you are signed in to, and always go
          to your login address.</div>
      </div>
    </Card>
  );
}

function TokensCard() {
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ["api-tokens"], queryFn: () => api<Token[]>("/auth/api-tokens") });
  const [name, setName] = useState("");
  const [role, setRole] = useState("viewer");
  const [created, setCreated] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<Token | null>(null);
  const create = useMutation({ mutationFn: () => api<{ token: string }>("/auth/api-tokens", { method: "POST", body: { name, role } }),
    onSuccess: (r) => { setCreated(r.token); setName(""); qc.invalidateQueries({ queryKey: ["api-tokens"] }); } });
  const revoke = useMutation({ mutationFn: (id: string) => api(`/auth/api-tokens/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["api-tokens"] }) });
  return (
    <Card title="API tokens" hint="for automation (SIEM, SOAR, CI). Tokens never exceed your own role." flush>
      <div className="filters">
        <input placeholder="Token name" value={name} onChange={(e) => setName(e.target.value)} />
        <select value={role} onChange={(e) => setRole(e.target.value)}>
          {["viewer", "security_analyst", "tenant_admin"].map((r) => <option key={r} value={r}>{label(r)}</option>)}</select>
        <button className="btn primary" disabled={!name} onClick={() => create.mutate()}>Create token</button>
        <ErrorBox error={create.error} />
      </div>
      {created && <div className="card-body"><div className="info-box">Copy this token now — it will not be shown again:
        <div className="mono" style={{ wordBreak: "break-all", marginTop: 6 }}>{created}</div></div></div>}
      {!tokens.data?.length ? <Empty>No API tokens.</Empty> : (
        <table className="data"><thead><tr><th>Name</th><th>Prefix</th><th>Role</th><th>Created</th><th>Last used</th><th>State</th><th /></tr></thead>
          <tbody>{tokens.data.map((t) => (
            <tr key={t.id}><td>{t.name}</td><td className="mono small">{t.token_prefix}…</td><td>{label(t.role)}</td>
              <td className="small">{fmtDate(t.created_at)}</td><td className="small">{timeAgo(t.last_used_at)}</td>
              <td>{t.revoked_at ? <span className="badge neutral">revoked</span> : <span className="badge ok">active</span>}</td>
              <td>{!t.revoked_at && <button className="btn sm danger" onClick={() => setRevoking(t)} aria-label="Revoke token" title="Revoke"><Trash2 /></button>}</td></tr>
          ))}</tbody></table>
      )}
      {revoking && <Confirm danger text={<>Revoke API token <strong>{revoking.name}</strong>? Any automation using it stops working immediately.</>}
                            onClose={() => setRevoking(null)} onConfirm={() => revoke.mutate(revoking.id)} />}
    </Card>
  );
}
