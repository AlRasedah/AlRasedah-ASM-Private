import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Play, Save } from "lucide-react";
import { api } from "@/api/client";
import type { FeedConfig } from "@/api/types";
import { Card, ErrorBox, Field, Loading } from "@/components/ui";
import { timeAgo } from "@/lib/format";

/** "vendor:product = name, name" per line ⇄ {"vendor:product": ["name", "name"]}. */
export function parseAliases(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [key, names = ""] = line.split("=", 2);
    out[key.trim().toLowerCase()] = names.split(",").map((n) => n.trim()).filter(Boolean);
  }
  return out;
}

const formatAliases = (a: Record<string, string[]>) => Object.entries(a).map(([k, v]) => `${k} = ${v.join(", ")}`).join("\n");

/** Platform administrators: automatic advisories from CISA KEV and NVD. */
export default function FeedSettings() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["threat-feed"], queryFn: () => api<FeedConfig>("/threat-catalog/feed") });
  const [form, setForm] = useState<FeedConfig["settings"] | null>(null);
  const [aliases, setAliases] = useState("");
  const [key, setKey] = useState("");
  useEffect(() => {
    if (q.data && !form) { setForm(q.data.settings); setAliases(formatAliases(q.data.settings.aliases)); }
  }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps
  const save = useMutation({
    mutationFn: (extra: { clear_nvd_api_key?: boolean } = {}) => api<FeedConfig>("/threat-catalog/feed", {
      method: "PUT", body: { ...form, aliases: parseAliases(aliases), nvd_api_key: key || undefined, ...extra } }),
    onSuccess: (d) => { qc.setQueryData(["threat-feed"], d); setKey(""); },
  });
  const run = useMutation({
    mutationFn: () => api("/threat-catalog/feed/run", { method: "POST" }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["threat-feed"] }); qc.invalidateQueries({ queryKey: ["threat-catalog"] }); },
  });
  if (q.isLoading || !form) return <Card title="Automatic advisories"><Loading /></Card>;
  const st = q.data!.status;
  const by = st.by_status;
  const kev = st.sources.kev;
  const set = <K extends keyof FeedConfig["settings"]>(k: K, v: FeedConfig["settings"][K]) => setForm({ ...form, [k]: v });
  return (
    <Card title="Automatic advisories" hint="from CISA's known-exploited catalog and NVD, checked every hour">
      <div className="form">
        <ErrorBox error={save.error ?? run.error} />
        <div className="small">
          {st.items ? <>
            <b>{st.items}</b> CVEs tracked ({st.kev_items} exploited in the wild) · {by.published ?? 0} published ·{" "}
            {by.draft ?? 0} waiting as drafts{by.failed ? ` · ${by.failed} could not be used` : ""}
            {by.manual ? ` · ${by.manual} left to your own advisories` : ""}
          </> : "Nothing fetched yet."}
          {kev?.last_success_at && <span className="muted"> · last update {timeAgo(kev.last_success_at)}</span>}
        </div>
        {kev?.last_error && <div className="callout small" style={{ fontWeight: 400 }}>Last attempt failed: {kev.last_error}</div>}
        <label className="row small"><input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          Write advisories automatically</label>
        <Field label="Publishing">
          <select value={form.publish} onChange={(e) => set("publish", e.target.value as FeedConfig["settings"]["publish"])}>
            <option value="kev">Publish exploited-in-the-wild vulnerabilities automatically; keep others as drafts</option>
            <option value="all">Publish everything automatically</option>
            <option value="none">Keep everything as drafts for review</option>
          </select>
        </Field>
        <div className="row small">
          <label className="row"><input type="checkbox" checked={form.include_critical} onChange={(e) => set("include_critical", e.target.checked)} />
            Also critical CVEs (CVSS 9+) published in the last</label>
          <input type="number" min={1} max={110} style={{ width: 70 }} value={form.critical_days} aria-label="Days"
                 onChange={(e) => set("critical_days", Number(e.target.value))} /> days
        </div>
        <label className="row small"><input type="checkbox" checked={form.auto_checks} onChange={(e) => set("auto_checks", e.target.checked)} />
          Link each CVE's community detection as its approved check. A detection the scanner does not have, or that is intrusive,
          makes a check inconclusive — never "not detected".</label>
        <Field label={`NVD API key (optional, free from nvd.nist.gov; faster first import)${st.has_api_key ? " — configured" : ""}`}>
          <div className="row">
            <input type="password" autoComplete="off" value={key} placeholder={st.has_api_key ? "•••••••• (unchanged)" : "not set"}
                   onChange={(e) => setKey(e.target.value)} />
            {st.has_api_key && <button className="btn ghost sm" onClick={() => save.mutate({ clear_nvd_api_key: true })}>Remove</button>}
          </div>
        </Field>
        <Field label="Product names — how your scans name products NVD calls something else (one per line: vendor:product = name, name)">
          <textarea rows={4} className="mono" value={aliases} placeholder="acme:web_gateway = acme gateway, acmegw" onChange={(e) => setAliases(e.target.value)} />
        </Field>
        <details className="small muted">
          <summary>{Object.keys(q.data!.builtin_aliases).length} built-in names</summary>
          <pre className="mono small" style={{ whiteSpace: "pre-wrap" }}>{formatAliases(q.data!.builtin_aliases)}</pre>
        </details>
        <div className="row">
          <button className="btn primary" disabled={save.isPending} onClick={() => save.mutate({})}><Save /> Save</button>
          <button className="btn" disabled={run.isPending || !form.enabled} onClick={() => run.mutate()}><Play /> Update now</button>
          {run.isSuccess && <span className="small muted">Running — new advisories appear within a few minutes.</span>}
        </div>
        <p className="small muted" style={{ margin: 0 }}>This product uses the NVD API but is not endorsed or certified by the NVD.
          Exploitation data: CISA Known Exploited Vulnerabilities catalog. Exploit likelihood: FIRST EPSS.</p>
      </div>
    </Card>
  );
}
