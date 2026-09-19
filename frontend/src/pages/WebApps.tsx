import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Check } from "lucide-react";
import { api } from "@/api/client";
import type { Page, WebApp } from "@/api/types";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Loading, PageHead, Pagination, RiskScore } from "@/components/ui";
import { SEV_COLOR, timeAgo } from "@/lib/format";

const SEVS = ["critical", "high", "medium", "low"] as const;

/** Small coloured count chips for a web app's open findings by severity. */
function SeverityCounts({ by }: { by: Record<string, number> }) {
  const shown = SEVS.filter((s) => (by[s] ?? 0) > 0);
  if (!shown.length) return <span className="muted">—</span>;
  return (
    <div className="row" style={{ gap: 6 }}>
      {shown.map((s) => (
        <span key={s} title={`${by[s]} ${s}`} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
          <span className="dot" style={{ background: SEV_COLOR[s] }} />
          <span className="small mono">{by[s]}</span>
        </span>
      ))}
    </div>
  );
}

export default function WebApps() {
  const { orgId } = useOrg();
  const nav = useNavigate();
  const [page, setPage] = useState(1);
  const q = useQuery({
    queryKey: ["web-apps", orgId, page],
    queryFn: () => api<Page<WebApp>>("/dashboard/web-apps", { query: { organization_id: orgId, page, page_size: 50 } }),
  });

  return (
    <>
      <PageHead title="Web applications"
                sub="Every discovered web application, with its risk, open web findings and DAST coverage (crawling & active testing)." />
      <Card flush>
        {q.isLoading ? <Loading /> : q.error ? <div className="card-body"><ErrorBox error={q.error} /></div> :
          !q.data!.items.length ? <Empty>No web applications discovered yet. Run a scan with web fingerprinting or the Web Application Scan (DAST) profile.</Empty> : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr>
                    <th>Risk</th><th>Application</th><th>Open findings</th><th className="num">Total</th>
                    <th>DAST</th><th>Crawled</th><th>Last seen</th>
                  </tr></thead>
                  <tbody>
                    {q.data!.items.map((w) => (
                      <tr key={w.id} className="clickable" onClick={() => nav(`/assets/${w.id}`)}>
                        <td><RiskScore score={w.risk_score} /></td>
                        <td>
                          <div className="cell-main"><Link to={`/assets/${w.id}`} onClick={(e) => e.stopPropagation()}>{w.url}</Link></div>
                          {(w.title || w.webserver) && <div className="cell-sub truncate" style={{ maxWidth: 340 }}>
                            {w.title || w.webserver}</div>}
                        </td>
                        <td><SeverityCounts by={w.by_severity} /></td>
                        <td className="num">{w.open_findings || <span className="muted">0</span>}</td>
                        <td>{w.dast_verified > 0
                          ? <span className="badge accent" title="Findings dynamically confirmed by active web scanning">{w.dast_verified} verified</span>
                          : <span className="muted">—</span>}</td>
                        <td>{w.crawled ? <span className="row" style={{ gap: 4, color: "var(--success)" }}><Check size={14} /> yes</span>
                          : <span className="muted">no</span>}</td>
                        <td className="small" title={w.last_seen}>{timeAgo(w.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} pageSize={50} total={q.data!.total} onPage={setPage} />
            </>
          )}
      </Card>
    </>
  );
}
