import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Save } from "lucide-react";
import { api } from "@/api/client";
import { Card, ErrorBox, Field, Loading, PageHead } from "@/components/ui";
import { label } from "@/lib/format";

type Settings = Record<string, any>;

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
