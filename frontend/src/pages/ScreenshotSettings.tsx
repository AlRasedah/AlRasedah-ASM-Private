import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Save } from "lucide-react";
import { api } from "@/api/client";
import type { ScreenshotPolicy, ScreenshotStatus } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { Card, ErrorBox, Field, Loading } from "@/components/ui";
import { bytes } from "@/lib/format";

/** Tenant administrators: turn website screenshots on and choose the cadence. Saved with the page. */
export function TenantScreenshotsCard({ value, onChange }: {
  value: { enabled?: boolean; cadence?: string } | undefined; onChange: (v: { enabled: boolean; cadence: string }) => void;
}) {
  const st = useQuery({ queryKey: ["screenshot-status"], queryFn: () => api<ScreenshotStatus>("/screenshots/status") });
  const v = { enabled: !!value?.enabled, cadence: value?.cadence ?? "manual" };
  const quota = st.data ? st.data.limits.storage_quota_mb * 1024 * 1024 : 0;
  return (
    <Card title="Website screenshots" hint="a picture of each web endpoint, so analysts recognise applications">
      <div className="form">
        {st.data && !st.data.available && <div className="info-box">{st.data.reason}</div>}
        <label className="check"><input type="checkbox" checked={v.enabled} disabled={!st.data?.available}
          onChange={(e) => onChange({ ...v, enabled: e.target.checked })} /> Allow screenshots of this tenant's web endpoints</label>
        <Field label="Cadence">
          <select value={v.cadence} disabled={!st.data?.available || !v.enabled} onChange={(e) => onChange({ ...v, cadence: e.target.value })}>
            <option value="manual">On request only ("Capture screenshot" on an endpoint)</option>
            <option value="weekly">Weekly, plus on request</option>
          </select>
        </Field>
        <p className="small muted" style={{ margin: 0 }}>A capture visits the page once, like a browser, from your scanner: it needs
          active-scanning authorization in scope. Only public pages are captured; nothing is signed in to.</p>
        {st.data && (
          <div className="small muted">
            Today {st.data.usage.captures_today}/{st.data.limits.per_tenant_daily} captures · stored {bytes(st.data.usage.stored_bytes)} of
            {" "}{bytes(quota)} · the latest {st.data.limits.retention_per_endpoint} per endpoint are kept
          </div>
        )}
      </div>
    </Card>
  );
}

const FIELDS: [keyof ScreenshotPolicy, string][] = [
  ["max_concurrent", "Active captures, whole deployment"], ["per_tenant_daily", "Captures per tenant per day"],
  ["per_tenant_queued", "Waiting captures per tenant"], ["retention_per_endpoint", "Images kept per endpoint"],
  ["storage_quota_mb", "Storage per tenant (MB)"], ["failed_retention_days", "Keep failure records (days)"],
  ["timeout_seconds", "Page load limit (seconds)"], ["viewport_width", "Viewport width (px)"],
  ["viewport_height", "Viewport height (px)"], ["max_image_kb", "Largest image (KB)"],
];

/** Platform administrators: whether the capability exists in this deployment, and its limits. */
export function ScreenshotPolicyCard() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const enabled = can("tenants:admin");
  const q = useQuery({ queryKey: ["screenshot-policy"], enabled,
    queryFn: () => api<{ policy: ScreenshotPolicy; bounds: Record<string, [number, number]> }>("/settings/screenshots") });
  const [form, setForm] = useState<ScreenshotPolicy | null>(null);
  useEffect(() => { if (q.data) setForm(q.data.policy); }, [q.data]);
  const save = useMutation({
    mutationFn: () => api("/settings/screenshots", { method: "PUT", body: form }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["screenshot-policy"] }); qc.invalidateQueries({ queryKey: ["screenshot-status"] }); },
  });
  if (!enabled) return null;
  if (q.isLoading || !form) return <Card title="Website screenshots — platform"><Loading /></Card>;
  return (
    <Card title="Website screenshots — platform" hint="applies to every tenant">
      <div className="form">
        <ErrorBox error={save.error} />
        <label className="check"><input type="checkbox" checked={form.available} onChange={(e) => setForm({ ...form, available: e.target.checked })} />
          The scanners have the screenshot browser (the self-test passed) — offer screenshots to tenants</label>
        {!form.available && <div className="info-box">Off: tenants see an explanation instead of the capture button. Enable after deploying the
          scanner image with the pinned browser and running its self-test (deployment guide, website screenshots).</div>}
        <div className="form-row">
          {FIELDS.map(([k, text]) => (
            <Field key={k} label={text}>
              <input type="number" min={q.data!.bounds[k]?.[0]} max={q.data!.bounds[k]?.[1]} value={form[k] as number}
                     onChange={(e) => setForm({ ...form, [k]: Number(e.target.value) })} />
            </Field>
          ))}
        </div>
        {save.isSuccess && <div className="small muted">Saved.</div>}
        <div className="filters"><button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}><Save /> Save screenshot policy</button></div>
      </div>
    </Card>
  );
}
