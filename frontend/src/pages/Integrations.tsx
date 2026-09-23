import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Plus, Send, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { Integration, Policy } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Confirm, Empty, ErrorBox, Field, Loading, Modal, PageHead, StatusBadge, Tabs } from "@/components/ui";
import { EVENT_LABELS, SEVERITIES, fmtDate, label, timeAgo } from "@/lib/format";

const TYPE_HELP: Record<string, string> = {
  email: "Email digest of matching changes to a list of recipients. For alerts to your own login address, use your account page instead.",
  webhook: "JSON POST to your endpoint. Set a signing secret to receive an HMAC-SHA256 signature (X-ASM-Signature).",
  wazuh: "Send structured JSON events to Wazuh. Syslog over TCP is the tested path; a Wazuh agent can also read the JSON file.",
  slack: "Slack incoming webhook (store the webhook URL as the secret).",
  teams: "Microsoft Teams: create a Workflows webhook (\"Post to a channel when a webhook request is received\") and store the URL as the secret.",
};

export default function Integrations() {
  const [tab, setTab] = useState<"channels" | "policies" | "deliveries" | "credentials">("channels");
  return (
    <>
      <PageHead title="Integrations" sub="Notification channels, alerting policies, SIEM (Wazuh) forwarding and data-source API keys." />
      <Tabs value={tab} onChange={setTab} tabs={[{ id: "channels", label: "Channels" }, { id: "policies", label: "Alert policies" },
        { id: "deliveries", label: "Delivery log" }, { id: "credentials", label: "Data-source API keys" }]} />
      {tab === "channels" && <Channels />}
      {tab === "policies" && <Policies />}
      {tab === "deliveries" && <Deliveries />}
      {tab === "credentials" && <Credentials />}
    </>
  );
}

function Channels() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const list = useQuery({ queryKey: ["integrations"], queryFn: () => api<Integration[]>("/integrations") });
  const [editing, setEditing] = useState<Integration | "new" | null>(null);
  const [deleting, setDeleting] = useState<Integration | null>(null);
  const [result, setResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null);
  const test = useMutation({
    mutationFn: (i: Integration) => api<{ message: string }>(`/integrations/${i.id}/test`, { method: "POST" }),
    onSuccess: (r, i) => { setResult({ id: i.id, ok: true, msg: r.message }); qc.invalidateQueries({ queryKey: ["integrations"] }); },
    onError: (e, i) => setResult({ id: i.id, ok: false, msg: (e as Error).message }),
  });
  const del = useMutation({ mutationFn: (i: Integration) => api(`/integrations/${i.id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }) });
  const toggle = useMutation({ mutationFn: (i: Integration) => api(`/integrations/${i.id}`, { method: "PATCH", body: { enabled: !i.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["integrations"] }) });
  return (
    <Card flush title="Notification channels" right={can("integrations:write") && <button className="btn sm primary" onClick={() => setEditing("new")}><Plus /> Add channel</button>}>
      {list.isLoading ? <Loading /> : !list.data?.length ? <Empty>No channels configured.</Empty> : (
        <table className="data">
          <thead><tr><th>Name</th><th>Type</th><th>State</th><th>Last delivery</th><th>Last error</th><th /></tr></thead>
          <tbody>{list.data.map((i) => (
            <tr key={i.id}>
              <td className="cell-main">{i.name}{result?.id === i.id && <div className={`small ${result.ok ? "" : "muted"}`} style={{ color: result.ok ? "var(--success)" : "var(--sev-critical-text)" }}>{result.msg}</div>}</td>
              <td>{label(i.integration_type)}</td>
              <td><StatusBadge value={i.enabled ? "active" : "inactive"} /></td>
              <td className="small">{timeAgo(i.last_success_at)}</td>
              <td className="small muted truncate" style={{ maxWidth: 260 }}>{i.last_error ? `${i.last_error} (${timeAgo(i.last_error_at)})` : "—"}</td>
              <td>{can("integrations:write") && <div className="btn-group">
                <button className="btn sm" onClick={() => test.mutate(i)}><Send /> Test</button>
                <button className="btn sm" onClick={() => setEditing(i)}>Edit</button>
                <button className="btn sm" onClick={() => toggle.mutate(i)}>{i.enabled ? "Disable" : "Enable"}</button>
                <button className="btn sm danger" onClick={() => setDeleting(i)}><Trash2 /></button></div>}</td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {editing && <ChannelEditor existing={editing === "new" ? undefined : editing} onClose={() => setEditing(null)} />}
      {deleting && <Confirm danger text={`Delete channel "${deleting.name}"?`} onClose={() => setDeleting(null)} onConfirm={() => del.mutate(deleting)} />}
    </Card>
  );
}

function ChannelEditor({ existing, onClose }: { existing?: Integration; onClose: () => void }) {
  const qc = useQueryClient();
  const [type, setType] = useState(existing?.integration_type ?? "webhook");
  const [name, setName] = useState(existing?.name ?? "");
  const c = existing?.config ?? {};
  const [url, setUrl] = useState<string>(c.url ?? "");
  const [recipients, setRecipients] = useState<string>((c.recipients ?? []).join(", "));
  const [mode, setMode] = useState<string>(c.mode ?? "syslog");
  const [host, setHost] = useState<string>(c.host ?? "");
  const [port, setPort] = useState<number>(c.port ?? 514);
  const [protocol, setProtocol] = useState<string>(c.protocol ?? "udp");
  const [fileName, setFileName] = useState<string>(c.file_name ?? "exteriq-asm.json");
  const [batch, setBatch] = useState<boolean>(c.batch ?? false);
  const [secret, setSecret] = useState("");

  const config = (): Record<string, unknown> => {
    if (type === "email") return { recipients: recipients.split(/[\s,;]+/).filter(Boolean) };
    if (type === "webhook") return { url, batch };
    if (type === "wazuh") return mode === "syslog" ? { mode, host, port, protocol } : mode === "webhook" ? { mode, url } : { mode, file_name: fileName };
    return {};
  };
  const m = useMutation({
    mutationFn: () => existing
      ? api(`/integrations/${existing.id}`, { method: "PATCH", body: { name, config: config(), secret: secret || undefined } })
      : api("/integrations", { method: "POST", body: { name, integration_type: type, config: config(), secret: secret || undefined } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["integrations"] }); onClose(); },
  });
  const secretLabel = type === "webhook" ? "Signing secret (optional)" : type === "wazuh" ? "Bearer token for HTTP receiver (optional)"
    : type === "slack" || type === "teams" ? "Incoming webhook URL" : null;
  return (
    <Modal title={existing ? `Edit ${existing.name}` : "Add notification channel"} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" disabled={!name} onClick={() => m.mutate()}>Save</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <div className="form-row">
          <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <Field label="Type"><select value={type} disabled={!!existing} onChange={(e) => setType(e.target.value)}>
            {Object.keys(TYPE_HELP).map((t) => <option key={t} value={t} disabled={t === "jira" || t === "servicenow"}>{label(t)}{t === "jira" || t === "servicenow" ? " (planned)" : ""}</option>)}
          </select></Field>
        </div>
        <div className="info-box small">{TYPE_HELP[type]}</div>
        {type === "email" && <Field label="Recipients"><input value={recipients} onChange={(e) => setRecipients(e.target.value)} placeholder="soc@example.com, it@example.com" /></Field>}
        {type === "webhook" && (<>
          <Field label="URL"><input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://soar.example.com/hooks/asm" /></Field>
          <label className="check"><input type="checkbox" checked={batch} onChange={(e) => setBatch(e.target.checked)} /> Batch events into one request</label>
        </>)}
        {type === "wazuh" && (<>
          <Field label="Delivery mode"><select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="syslog">Syslog to Wazuh manager</option><option value="webhook">HTTP receiver</option>
            <option value="file">JSON file (Wazuh agent localfile)</option></select></Field>
          {mode === "syslog" && <div className="form-row">
            <Field label="Wazuh manager host"><input value={host} onChange={(e) => setHost(e.target.value)} /></Field>
            <Field label="Port"><input type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} /></Field>
            <Field label="Protocol"><select value={protocol} onChange={(e) => setProtocol(e.target.value)}><option>udp</option><option>tcp</option></select></Field>
          </div>}
          {mode === "webhook" && <Field label="Receiver URL"><input value={url} onChange={(e) => setUrl(e.target.value)} /></Field>}
          {mode === "file" && <Field label="File name (inside the export volume)"><input value={fileName} onChange={(e) => setFileName(e.target.value)} /></Field>}
        </>)}
        {secretLabel && <Field label={`${secretLabel}${existing?.has_secret ? " — leave empty to keep the stored value" : ""}`}>
          <input type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} /></Field>}
      </div>
    </Modal>
  );
}

function Policies() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["policies"], queryFn: () => api<Policy[]>("/integrations/policies") });
  const channels = useQuery({ queryKey: ["integrations"], queryFn: () => api<Integration[]>("/integrations") });
  const [editing, setEditing] = useState<Policy | "new" | null>(null);
  const [deleting, setDeleting] = useState<Policy | null>(null);
  const del = useMutation({ mutationFn: (id: string) => api(`/integrations/policies/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["policies"] }) });
  const chName = (id: string) => channels.data?.find((c) => c.id === id)?.name ?? "?";
  return (
    <Card flush title="Alert policies" hint="Events from an organization's first (baseline) scan are never alerted unless explicitly enabled"
          right={can("integrations:write") && <button className="btn sm primary" onClick={() => setEditing("new")}><Plus /> Add policy</button>}>
      {!policies.data?.length ? <Empty>No alert policies. Changes are recorded but nobody is notified.</Empty> : (
        <table className="data">
          <thead><tr><th>Policy</th><th>Minimum severity</th><th>Change types</th><th>Channels</th><th>State</th><th /></tr></thead>
          <tbody>{policies.data.map((p) => (
            <tr key={p.id}>
              <td className="cell-main">{p.name}{p.throttle_minutes ? <div className="cell-sub">throttle {p.throttle_minutes} min</div> : null}</td>
              <td>{p.min_severity}+</td>
              <td className="small">{p.event_types.length ? p.event_types.map((e) => EVENT_LABELS[e] ?? e).join(", ") : "All"}</td>
              <td className="small">{p.integration_ids.map(chName).join(", ")}</td>
              <td><StatusBadge value={p.enabled ? "active" : "inactive"} /></td>
              <td>{can("integrations:write") && <div className="btn-group"><button className="btn sm" onClick={() => setEditing(p)}>Edit</button>
                <button className="btn sm danger" onClick={() => setDeleting(p)} aria-label="Delete policy" title="Delete"><Trash2 /></button></div>}</td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {deleting && <Confirm danger text={<>Delete alert policy <strong>{deleting.name}</strong>? Matching changes will no longer be sent to its channels.</>}
                            onClose={() => setDeleting(null)} onConfirm={() => del.mutate(deleting.id)} />}
      {editing && <PolicyEditor existing={editing === "new" ? undefined : editing} channels={channels.data ?? []} onClose={() => setEditing(null)} />}
    </Card>
  );
}

function PolicyEditor({ existing, channels, onClose }: { existing?: Policy; channels: Integration[]; onClose: () => void }) {
  const qc = useQueryClient();
  const { orgs } = useOrg();
  const [p, setP] = useState({
    name: existing?.name ?? "High and critical changes", enabled: existing?.enabled ?? true,
    event_types: existing?.event_types ?? [], min_severity: existing?.min_severity ?? "high",
    organization_ids: existing?.organization_ids ?? [], integration_ids: existing?.integration_ids ?? [],
    include_baseline: existing?.include_baseline ?? false, throttle_minutes: existing?.throttle_minutes ?? 0,
  });
  const m = useMutation({
    mutationFn: () => {
      const body = { ...p, organization_ids: p.organization_ids.length ? p.organization_ids : null };
      return existing ? api(`/integrations/policies/${existing.id}`, { method: "PUT", body }) : api("/integrations/policies", { method: "POST", body });
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["policies"] }); onClose(); },
  });
  const toggleIn = (key: "event_types" | "organization_ids" | "integration_ids", v: string) =>
    setP({ ...p, [key]: p[key].includes(v) ? p[key].filter((x) => x !== v) : [...p[key], v] });
  return (
    <Modal wide title={existing ? "Edit alert policy" : "New alert policy"} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={() => m.mutate()}>Save</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <div className="form-row">
          <Field label="Name"><input value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} /></Field>
          <Field label="Minimum severity"><select value={p.min_severity} onChange={(e) => setP({ ...p, min_severity: e.target.value as Policy["min_severity"] })}>
            {SEVERITIES.map((s) => <option key={s}>{s}</option>)}</select></Field>
          <Field label="Throttle (minutes per asset & change type)"><input type="number" min={0} value={p.throttle_minutes}
            onChange={(e) => setP({ ...p, throttle_minutes: Number(e.target.value) })} /></Field>
        </div>
        <Field label="Deliver to">
          <div className="row">{channels.map((c) => (
            <label key={c.id} className="check"><input type="checkbox" checked={p.integration_ids.includes(c.id)} onChange={() => toggleIn("integration_ids", c.id)} /> {c.name}</label>
          ))}{!channels.length && <span className="muted">Add a channel first.</span>}</div>
        </Field>
        <Field label="Change types (none selected = all)">
          <div className="row">{Object.entries(EVENT_LABELS).map(([k, v]) => (
            <label key={k} className="check small"><input type="checkbox" checked={p.event_types.includes(k)} onChange={() => toggleIn("event_types", k)} /> {v}</label>
          ))}</div>
        </Field>
        <Field label="Organizations (none selected = all)">
          <div className="row">{orgs.map((o) => (
            <label key={o.id} className="check small"><input type="checkbox" checked={p.organization_ids.includes(o.id)} onChange={() => toggleIn("organization_ids", o.id)} /> {o.name}</label>
          ))}</div>
        </Field>
        <div className="row">
          <label className="check"><input type="checkbox" checked={p.enabled} onChange={(e) => setP({ ...p, enabled: e.target.checked })} /> Enabled</label>
          <label className="check"><input type="checkbox" checked={p.include_baseline} onChange={(e) => setP({ ...p, include_baseline: e.target.checked })} /> Include baseline events</label>
        </div>
      </div>
    </Modal>
  );
}

function Deliveries() {
  const q = useQuery({ queryKey: ["deliveries"], queryFn: () => api<{ id: string; status: string; attempts: number; last_error: string | null; created_at: string; sent_at: string | null; integration_id: string | null }[]>("/integrations/deliveries") });
  const channels = useQuery({ queryKey: ["integrations"], queryFn: () => api<Integration[]>("/integrations") });
  if (q.isLoading) return <Loading />;
  return (
    <Card flush title="Recent deliveries">
      {!q.data?.length ? <Empty>No notifications sent yet.</Empty> : (
        <table className="data"><thead><tr><th>Created</th><th>Channel</th><th>Status</th><th className="num">Attempts</th><th>Sent</th><th>Error</th></tr></thead>
          <tbody>{q.data.map((d) => (
            <tr key={d.id}><td className="small">{fmtDate(d.created_at)}</td>
              <td>{channels.data?.find((c) => c.id === d.integration_id)?.name ?? "—"}</td>
              <td><StatusBadge value={d.status} /></td><td className="num">{d.attempts}</td>
              <td className="small">{fmtDate(d.sent_at)}</td><td className="small muted">{d.last_error ?? ""}</td></tr>
          ))}</tbody></table>
      )}
    </Card>
  );
}

interface Provider {
  provider: string; used_by: string[]; label: string; description: string; group: string; group_label: string;
  key_format: string; paid: boolean; url: string | null; testable: boolean;
}

function Credentials() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers"], queryFn: () => api<Provider[]>("/credentials/providers") });
  const creds = useQuery({ queryKey: ["credentials"], queryFn: () => api<{ id: string; provider: string; last_four: string | null; updated_at: string }[]>("/credentials") });
  const [provider, setProvider] = useState("");
  const [value, setValue] = useState("");
  const [deleting, setDeleting] = useState<{ id: string; provider: string } | null>(null);
  const [checked, setChecked] = useState<{ provider: string; ok: boolean; msg: string } | null>(null);
  const save = useMutation({
    mutationFn: () => api(`/credentials/${provider}`, { method: "PUT", body: { value } }),
    onSuccess: () => { setValue(""); qc.invalidateQueries({ queryKey: ["credentials"] }); },
  });
  const del = useMutation({ mutationFn: (id: string) => api(`/credentials/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["credentials"] }) });
  const check = useMutation({
    mutationFn: (p: string) => api<{ message: string }>(`/credentials/${p}/test`, { method: "POST" }),
    onSuccess: (r, p) => setChecked({ provider: p, ok: true, msg: r.message }),
    onError: (e, p) => setChecked({ provider: p, ok: false, msg: (e as Error).message }),
  });
  const meta = (key: string) => providers.data?.find((p) => p.provider === key);
  const selected = meta(provider);
  // One section per kind of source, so the list explains itself.
  const groups = (providers.data ?? []).reduce<Record<string, Provider[]>>((acc, p) => {
    (acc[p.group_label] ??= []).push(p);
    return acc;
  }, {});
  return (
    <div className="grid cols-3">
      <Card title="Stored keys" className="span-2" flush
            hint="each key lets the platform ask one more source about your attack surface">
        {!creds.data?.length ? <Empty>No data-source keys yet. Discovery still works with the free sources.</Empty> : (
          <table className="data"><thead><tr><th>Source</th><th>Key</th><th>Used by</th><th>Updated</th><th /></tr></thead>
            <tbody>{creds.data.map((c) => (
              <tr key={c.id}>
                <td className="cell-main">{meta(c.provider)?.label ?? c.provider}
                  <div className="cell-sub">{meta(c.provider)?.description}</div>
                  {checked?.provider === c.provider && <div className="small" style={{ color: checked.ok ? "var(--success)" : "var(--sev-critical-text)" }}>{checked.msg}</div>}</td>
                <td className="mono">{c.last_four ? `••••${c.last_four}` : "••••"}</td>
                <td className="small muted">{meta(c.provider)?.used_by.join(", ")}</td>
                <td className="small">{fmtDate(c.updated_at)}</td>
                <td style={{ whiteSpace: "nowrap" }}>
                  {meta(c.provider)?.testable && can("credentials:write") &&
                    <button className="btn sm" disabled={check.isPending} onClick={() => check.mutate(c.provider)}
                            title="Check this key against the provider">Test</button>}
                  {can("credentials:write") && <button className="btn sm danger" style={{ marginInlineStart: 6 }}
                    onClick={() => setDeleting(c)} aria-label="Delete key" title="Delete"><Trash2 /></button>}</td></tr>
            ))}</tbody></table>
        )}
      </Card>
      {deleting && <Confirm danger text={<>Delete the stored <strong>{meta(deleting.provider)?.label ?? deleting.provider}</strong> API key? Sensors that use it fall back to free sources until a new key is saved. The key cannot be recovered.</>}
                            onClose={() => setDeleting(null)} onConfirm={() => del.mutate(deleting.id)} />}
      {can("credentials:write") && (
        <Card title="Add or replace a key">
          <div className="form">
            <ErrorBox error={save.error} />
            <Field label="Source"><select value={provider} onChange={(e) => { setProvider(e.target.value); setChecked(null); }}>
              <option value="">Select…</option>
              {Object.entries(groups).map(([group, items]) => (
                <optgroup key={group} label={group}>
                  {items.map((p) => <option key={p.provider} value={p.provider}>{p.label}{p.paid ? " (paid)" : ""}</option>)}
                </optgroup>
              ))}</select></Field>
            {selected && <div className="info-box small">
              {selected.description}
              <div style={{ marginTop: 4 }}>Used by: {selected.used_by.join(", ")}</div>
              {selected.url && <div><a href={selected.url} target="_blank" rel="noopener noreferrer">Where to get this key</a></div>}
            </div>}
            <Field label={selected ? `Key (${selected.key_format})` : "API key"}>
              <input type="password" autoComplete="off" placeholder={selected?.key_format}
                     value={value} onChange={(e) => setValue(e.target.value)} /></Field>
            <button className="btn primary" disabled={!provider || value.length < 4} onClick={() => save.mutate()}><KeyRound /> Save encrypted</button>
            <div className="small muted">Keys are encrypted at rest (AES-256-GCM), never shown again, and delivered to
              sensors in sealed envelopes. See the <a href="/user-guide.html#integrations" target="_blank" rel="noopener noreferrer">user guide</a> for what each source adds.</div>
          </div>
        </Card>
      )}
    </div>
  );
}
