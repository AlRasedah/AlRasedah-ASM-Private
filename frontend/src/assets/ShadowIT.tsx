import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { Asset, Page } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Loading, PageHead, Pagination, RiskScore, StatusBadge } from "@/components/ui";
import { ASSET_TYPE_LABELS, fmtDay } from "@/lib/format";

const TYPES = ["subdomain", "domain", "ip_address", "http_endpoint", "cloud_resource", "port"];
const ACTIONS: { value: string; label: string; tone?: string }[] = [
  { value: "approved", label: "Approve" },
  { value: "expected", label: "Expected" },
  { value: "third_party", label: "Third party" },
  { value: "unauthorized", label: "Unauthorized", tone: "danger" },
  { value: "decommissioned", label: "Decommissioned" },
];

export default function ShadowIT() {
  const { orgId } = useOrg();
  const { can } = useAuth();
  const qc = useQueryClient();
  const [type, setType] = useState("");
  const [page, setPage] = useState(1);
  const query = { unknown: true, status: "active", asset_type: type ? [type] : TYPES, organization_id: orgId,
                  sort: "first_seen", order: "desc", page, page_size: 50 };
  const q = useQuery({ queryKey: ["shadow", query], queryFn: () => api<Page<Asset>>("/assets", { query }) });
  const classify = useMutation({
    mutationFn: ({ id, approval }: { id: string; approval: string }) =>
      api(`/assets/${id}`, { method: "PATCH", body: { approval_status: approval } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["shadow"] }); qc.invalidateQueries({ queryKey: ["dashboard"] }); },
  });

  return (
    <>
      <PageHead title="Shadow IT review"
                sub="Assets discovered outside your known inventory. Ownership is unknown and approval unverified until reviewed." />
      <Card flush>
        <div className="filters">
          <select value={type} onChange={(e) => { setType(e.target.value); setPage(1); }}>
            <option value="">All relevant types</option>
            {TYPES.map((t) => <option key={t} value={t}>{ASSET_TYPE_LABELS[t]}</option>)}
          </select>
          <span className="muted small">{q.data?.total ?? 0} asset(s) awaiting classification</span>
        </div>
        <ErrorBox error={classify.error} />
        {q.isLoading ? <Loading /> : !q.data?.items.length ? <Empty>Nothing to review — every active asset has a known status.</Empty> : (
          <>
            <table className="data">
              <thead><tr><th>Asset</th><th>Type</th><th>Discovered</th><th>Risk</th><th>Status</th>{can("assets:write") && <th>Classify</th>}</tr></thead>
              <tbody>
                {q.data.items.map((a) => (
                  <tr key={a.id}>
                    <td><div className="cell-main"><Link to={`/assets/${a.id}`}>{a.value}</Link></div>
                      <div className="cell-sub">{a.ips.join(", ")}{a.title ? ` · ${a.title}` : ""}</div></td>
                    <td className="small">{ASSET_TYPE_LABELS[a.asset_type]}</td>
                    <td className="small">{fmtDay(a.first_seen)}<div className="cell-sub">{a.source_label}</div></td>
                    <td><RiskScore score={a.risk_score} /></td>
                    <td><StatusBadge value={a.approval_status} /></td>
                    {can("assets:write") && (
                      <td><div className="btn-group">
                        {ACTIONS.map((x) => (
                          <button key={x.value} className={`btn sm ${x.tone ?? ""}`} disabled={classify.isPending}
                                  onClick={() => classify.mutate({ id: a.id, approval: x.value })}>{x.label}</button>
                        ))}
                      </div></td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination page={page} pageSize={50} total={q.data.total} onPage={setPage} />
          </>
        )}
      </Card>
    </>
  );
}
