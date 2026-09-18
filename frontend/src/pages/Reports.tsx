import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, Eye } from "lucide-react";
import { api, download, openBlob } from "@/api/client";
import type { Page, Report } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Field, Loading, PageHead, Pagination, StatusBadge } from "@/components/ui";
import { bytes, fmtDate, label } from "@/lib/format";

const TYPES = [
  { id: "executive", label: "Executive ASM report", formats: ["html", "pdf"] },
  { id: "technical", label: "Technical attack surface report", formats: ["html", "pdf"] },
  { id: "asset_inventory", label: "Asset inventory", formats: ["html", "pdf", "csv"] },
  { id: "vulnerability", label: "Vulnerability report", formats: ["html", "pdf", "csv"] },
  { id: "changes", label: "New assets & changes", formats: ["html", "pdf", "csv"] },
  { id: "risk_trend", label: "Risk trend", formats: ["html", "pdf", "csv"] },
];

export default function Reports() {
  const { orgId, orgs, orgName } = useOrg();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [type, setType] = useState("executive");
  const [format, setFormat] = useState("html");
  const [org, setOrg] = useState(orgId ?? "");
  const [days, setDays] = useState(30);
  const reports = useQuery({
    queryKey: ["reports", page], queryFn: () => api<Page<Report>>("/reports", { query: { page, page_size: 25 } }),
    refetchInterval: (q) => (q.state.data?.items.some((r) => ["pending", "running"].includes(r.status)) ? 3000 : false),
  });
  const create = useMutation({
    mutationFn: () => api<Report>("/reports", { method: "POST", body: { report_type: type, report_format: format,
      organization_id: org || null, days } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["reports"] }),
  });
  const formats = TYPES.find((t) => t.id === type)!.formats;

  return (
    <>
      <PageHead title="Reports" sub="Executive, technical, inventory, vulnerability, change and trend reports (HTML, PDF, CSV)." />
      <div className="grid cols-3">
        {can("reports:create") && (
          <Card title="Generate a report">
            <div className="form">
              <ErrorBox error={create.error} />
              <Field label="Report"><select value={type} onChange={(e) => { setType(e.target.value); setFormat("html"); }}>
                {TYPES.map((t) => <option key={t.id} value={t.id}>{t.label}</option>)}</select></Field>
              <Field label="Format"><select value={format} onChange={(e) => setFormat(e.target.value)}>
                {formats.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}</select></Field>
              <Field label="Organization"><select value={org} onChange={(e) => setOrg(e.target.value)}>
                <option value="">All organizations</option>{orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></Field>
              <Field label="Period (days)"><input type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} /></Field>
              <button className="btn primary" disabled={create.isPending} onClick={() => create.mutate()}><FileText /> Generate</button>
            </div>
          </Card>
        )}
        <Card title="Generated reports" className={can("reports:create") ? "span-2" : "span-2"} flush>
          {reports.isLoading ? <Loading /> : !reports.data?.items.length ? <Empty>No reports yet.</Empty> : (
            <>
              <table className="data">
                <thead><tr><th>Report</th><th>Scope</th><th>Format</th><th>Status</th><th>Created</th><th>Size</th><th /></tr></thead>
                <tbody>{reports.data.items.map((r) => (
                  <tr key={r.id}>
                    <td><div className="cell-main">{r.title}</div><div className="cell-sub">{label(r.report_type)}</div></td>
                    <td className="small">{r.organization_id ? orgName(r.organization_id) : "All organizations"}</td>
                    <td className="small">{r.report_format.toUpperCase()}</td>
                    <td><StatusBadge value={r.status} />{r.error && <div className="cell-sub">{r.error}</div>}</td>
                    <td className="small">{fmtDate(r.created_at)}</td>
                    <td className="small">{bytes(r.size)}</td>
                    <td>{r.status === "completed" && <div className="btn-group">
                      {r.report_format === "html" && <button className="btn sm" onClick={() => openBlob(`/reports/${r.id}/download`)}><Eye /></button>}
                      <button className="btn sm" onClick={() => download(`/reports/${r.id}/download`, undefined,
                        `${r.report_type}-${r.created_at.slice(0, 10)}.${r.report_format}`)}><Download /></button></div>}</td>
                  </tr>
                ))}</tbody>
              </table>
              <Pagination page={page} pageSize={25} total={reports.data.total} onPage={setPage} />
            </>
          )}
        </Card>
      </div>
    </>
  );
}
