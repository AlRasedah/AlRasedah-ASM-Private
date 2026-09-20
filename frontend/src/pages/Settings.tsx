import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Mail, Save, Send } from "lucide-react";
import { api } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { Card, ErrorBox, Field, Loading, PageHead } from "@/components/ui";
import { label } from "@/lib/format";

type Settings = Record<string, any>;

interface EmailSettings {
  configured: boolean; source: string; host: string | null; port: number; username: string | null;
  sender: string; starttls: boolean; ssl: boolean; has_password: boolean;
}

/** Mail server for password resets, invitations and alerts (platform administrators). */
function EmailDeliveryCard() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const enabled = can("tenants:admin");
  const q = useQuery({ queryKey: ["email-settings"], queryFn: () => api<EmailSettings>("/settings/email"), enabled });
  const [form, setForm] = useState<Record<string, any>>({});
  useEffect(() => { if (q.data) setForm({ host: q.data.host ?? "", port: q.data.port ?? 587, username: q.data.username ?? "",
    sender: q.data.sender ?? "", starttls: q.data.starttls, ssl: q.data.ssl, password: "" }); }, [q.data]);
  const save = useMutation({
    // An empty password keeps the stored one; clearing the field on purpose is a separate action.
    mutationFn: () => api("/settings/email", { method: "PUT", body: { ...form, password: form.password || undefined } }),
    onSuccess: () => { setForm({ ...form, password: "" }); qc.invalidateQueries({ queryKey: ["email-settings"] }); },
  });
  const test = useMutation({ mutationFn: () => api<{ message: string }>("/settings/email/test", { method: "POST" }) });
  if (!enabled) return null;
  if (q.isLoading) return <Card title="Email delivery"><Loading /></Card>;
  const set = (k: string, v: unknown) => setForm({ ...form, [k]: v });
  return (
    <Card title="Email delivery" hint="used for password resets, invitations and alerts — no server access needed">
      <div className="form">
        <ErrorBox error={save.error ?? test.error} />
        {q.data?.source === "environment" &&
          <div className="info-box">Currently using the mail server from the deployment's environment. Saving here overrides it.</div>}
        {!q.data?.configured && <div className="info-box">No mail server configured yet — password resets and alert emails cannot be sent.</div>}
        <div className="form-row">
          <Field label="Server (SMTP host)"><input value={form.host ?? ""} onChange={(e) => set("host", e.target.value)} placeholder="smtp.example.com" /></Field>
          <Field label="Port"><input type="number" value={form.port ?? 587} onChange={(e) => set("port", Number(e.target.value))} /></Field>
        </div>
        <div className="form-row">
          <Field label="Username"><input value={form.username ?? ""} onChange={(e) => set("username", e.target.value)} autoComplete="off" /></Field>
          <Field label={q.data?.has_password ? "Password (leave blank to keep)" : "Password"}>
            <input type="password" value={form.password ?? ""} onChange={(e) => set("password", e.target.value)} autoComplete="new-password" /></Field>
        </div>
        <Field label="Send from"><input value={form.sender ?? ""} onChange={(e) => set("sender", e.target.value)} placeholder="Exteriq ASM <asm@example.com>" /></Field>
        <label className="check"><input type="checkbox" checked={!!form.starttls} onChange={(e) => set("starttls", e.target.checked)} /> Use STARTTLS (recommended)</label>
        <label className="check"><input type="checkbox" checked={!!form.ssl} onChange={(e) => set("ssl", e.target.checked)} /> Connect over TLS directly (port 465)</label>
        {test.isSuccess && <div className="info-box">{test.data.message}</div>}
        <div className="filters">
          <button className="btn primary" disabled={!form.host || save.isPending} onClick={() => save.mutate()}><Mail /> Save mail server</button>
          <button className="btn" disabled={!q.data?.configured || test.isPending} onClick={() => test.mutate()}><Send /> Send test email</button>
        </div>
      </div>
    </Card>
  );
}

export default function SettingsPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["settings"], queryFn: () => api<{ effective: Settings; defaults: Settings }>("/settings") });
  const [s, setS] = useState<Settings | null>(null);
  useEffect(() => { if (q.data) setS(structuredClone(q.data.effective)); }, [q.data]);
  const save = useMutation({
    mutationFn: () => api("/settings", { method: "PUT", body: {
      inactivity: s!.inactivity, risk: s!.risk, scanning: s!.scanning, detection_rules: s!.detection_rules,
      branding: { name: s!.branding?.name || null, primary_color: s!.branding?.primary_color || null } } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });
  if (q.isLoading || !s) return <Loading />;
  const set = (section: string, key: string, value: unknown) => setS({ ...s, [section]: { ...(s[section] ?? {}), [key]: value } });
  const num = (section: string, key: string, text?: string) => (
    <Field key={key} label={text ?? label(key)}>
      <input type="number" value={s[section]?.[key] ?? ""} onChange={(e) => set(section, key, Number(e.target.value))} />
    </Field>
  );

  return (
    <>
      <PageHead title="Settings" sub="Tenant-wide policies for change detection, risk scoring and detection rules."
                actions={<button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}><Save /> Save settings</button>} />
      <ErrorBox error={save.error} />
      {save.isSuccess && <div className="info-box" style={{ marginBottom: 12 }}>Settings saved. Risk scores are being recomputed.</div>}
      <div className="grid cols-2">
        <Card title="Asset lifecycle" hint="consecutive covered scans without observation before something is considered gone">
          <div className="form-row">
            {["subdomain", "port", "service", "http_endpoint", "relation", "finding", "default"].map((k) => num("inactivity", k, `${label(k)} misses`))}
            {num("inactivity", "max_age_days", "Age out after (days unseen)")}
          </div>
        </Card>
        <Card title="Scanning governance">
          <div className="form">
            <label className="check"><input type="checkbox" checked={!!s.scanning?.require_scope_verification}
              onChange={(e) => set("scanning", "require_scope_verification", e.target.checked)} />
              Require DNS ownership verification before active scanning of domains</label>
          </div>
        </Card>
        <Card title="Risk scoring weights" hint="points added to the 0–100 score">
          <div className="form-row">
            {["kev_points", "epss_max_points", "exploit_points", "exposure_points", "management_interface_points",
              "auth_exposure_points", "risky_port_points", "shadow_it_points", "unauthorized_points", "new_asset_points",
              "age_points_per_30_days", "age_max_points"].map((k) => num("risk", k))}
          </div>
          <hr />
          <div className="form-row">
            {["critical", "high", "medium", "low", "info"].map((sev) => (
              <Field key={sev} label={`Severity: ${sev}`}>
                <input type="number" value={s.risk.severity_points?.[sev] ?? 0}
                       onChange={(e) => set("risk", "severity_points", { ...s.risk.severity_points, [sev]: Number(e.target.value) })} />
              </Field>
            ))}
          </div>
          <hr />
          <div className="form-row">
            {["critical", "high", "medium", "low"].map((lv) => (
              <Field key={lv} label={`${label(lv)} level from`}>
                <input type="number" value={s.risk.levels?.[lv] ?? 0}
                       onChange={(e) => set("risk", "levels", { ...s.risk.levels, [lv]: Number(e.target.value) })} />
              </Field>
            ))}
          </div>
        </Card>
        <EmailDeliveryCard />
        <div className="stack">
          <Card title="Built-in detection rules">
            <div className="form">
              {["risky_ports", "management_interfaces", "certificates", "weak_tls", "api_documentation"].map((k) => (
                <label key={k} className="check"><input type="checkbox" checked={!!s.detection_rules?.[k]}
                  onChange={(e) => set("detection_rules", k, e.target.checked)} /> {label(k)}</label>
              ))}
              {num("detection_rules", "certificate_expiry_days", "Certificate expiry warning (days)")}
            </div>
          </Card>
          <Card title="Report branding">
            <div className="form-row">
              <Field label="Brand name"><input value={s.branding?.name ?? ""} onChange={(e) => set("branding", "name", e.target.value)} placeholder="Exteriq ASM" /></Field>
              <Field label="Accent colour (#RRGGBB)"><input value={s.branding?.primary_color ?? ""} onChange={(e) => set("branding", "primary_color", e.target.value)} placeholder="#a3571f" /></Field>
            </div>
          </Card>
        </div>
      </div>
    </>
  );
}
