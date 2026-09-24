import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Settings2 } from "lucide-react";
import { api } from "@/api/client";
import type { AdvisorySummary, Page } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Loading, PageHead, Pagination, SeverityBadge, useDebounced } from "@/components/ui";
import { fmtDay, timeAgo } from "@/lib/format";

/** Assessment freshness: when this tenant's inventory was last matched against the advisory. */
export function Freshness({ a }: { a: Pick<AdvisorySummary, "last_evaluated_at" | "stale" | "incomplete"> }) {
  if (!a.last_evaluated_at) return <span className="badge warn" title="Not yet matched against your inventory">not assessed yet</span>;
  if (a.stale) return <span className="badge warn" title="A newer advisory version is being matched">updating</span>;
  if (a.incomplete?.length) return <span className="badge warn" title={a.incomplete.join(" ")}>partial</span>;
  return <span className="small" title={a.last_evaluated_at}>{timeAgo(a.last_evaluated_at)}</span>;
}

function Num({ n, tone, title }: { n: number; tone?: string; title: string }) {
  if (!n) return <span className="muted">0</span>;
  return <span className={tone ? `badge ${tone}` : "mono"} title={title}>{n}</span>;
}

export default function ThreatCenter() {
  const { can } = useAuth();
  const { orgId } = useOrg();
  const nav = useNavigate();
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState<"published" | "archived">("published");
  const [search, setSearch] = useState("");
  const q = useDebounced(search);
  const list = useQuery({
    queryKey: ["threats", orgId, status, q, page],
    queryFn: () => api<Page<AdvisorySummary>>("/threats", { query: { organization_id: orgId, status, q: q || undefined, page, page_size: 25 } }),
  });

  return (
    <>
      <PageHead title="Threat Center"
                sub="Serious vulnerabilities curated by the platform team, matched against your recorded inventory. A match means “may be affected” until a check or scan confirms it."
                actions={can("intel:admin") && <Link className="btn" to="/threats/catalog"><Settings2 /> Manage advisories</Link>} />
      <Card flush>
        <div className="filters">
          <input placeholder="Search title or CVE…" value={search} onChange={(e) => { setSearch(e.target.value); setPage(1); }} aria-label="Search advisories" />
          <select value={status} onChange={(e) => { setStatus(e.target.value as "published" | "archived"); setPage(1); }} aria-label="Advisory status">
            <option value="published">Current advisories</option>
            <option value="archived">Archived</option>
          </select>
        </div>
        {list.isLoading ? <Loading /> : list.error ? <div className="card-body"><ErrorBox error={list.error} /></div> :
          !list.data!.items.length ? (
            <Empty>{status === "archived" ? "No archived advisories." :
              q ? "No advisory matches that search." :
                "No advisories have been published yet. Platform administrators publish curated advisories here when a serious vulnerability is announced."}</Empty>
          ) : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr>
                    <th>Severity</th><th>Advisory</th><th>Published</th>
                    <th className="num" title="Assets that may be affected (confirmed or not)">May be affected</th>
                    <th className="num" title="A verified finding exists">Confirmed</th>
                    <th className="num" title="A completed check found nothing — not proof of safety">Not detected</th>
                    <th className="num" title="Check failed, blocked, timed out or could not reach the asset">Inconclusive</th>
                    <th>Remediation</th><th>Assessed</th>
                  </tr></thead>
                  <tbody>
                    {list.data!.items.map((a) => {
                      const pct = a.counts.affected ? Math.round((a.counts.remediated / a.counts.affected) * 100) : null;
                      return (
                        <tr key={a.id} className="clickable" onClick={() => nav(`/threats/${a.id}`)}>
                          <td><SeverityBadge value={a.severity} /></td>
                          <td>
                            <div className="cell-main"><Link to={`/threats/${a.id}`} onClick={(e) => e.stopPropagation()}>{a.title}</Link></div>
                            <div className="cell-sub mono">{a.cves.slice(0, 4).join(", ")}{a.cves.length > 4 ? ` +${a.cves.length - 4}` : ""}</div>
                          </td>
                          <td className="small" title={a.source_updated_at ? `Updated ${fmtDay(a.source_updated_at)}` : undefined}>
                            {fmtDay(a.source_published_at ?? a.version_published_at)}
                            {a.source_updated_at && <div className="cell-sub">updated {fmtDay(a.source_updated_at)}</div>}
                          </td>
                          <td className="num"><Num n={a.counts.affected} title="May be affected" /></td>
                          <td className="num"><Num n={a.counts.confirmed} tone="bad" title="Confirmed by a verified finding" /></td>
                          <td className="num"><Num n={a.counts.not_detected} title="Checked, not detected" /></td>
                          <td className="num"><Num n={a.counts.inconclusive} tone="warn" title="Check inconclusive" /></td>
                          <td className="small">{pct === null ? <span className="muted">—</span> : `${a.counts.remediated}/${a.counts.affected} (${pct}%)`}</td>
                          <td><Freshness a={a} /></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              <Pagination page={page} pageSize={25} total={list.data!.total} onPage={setPage} />
            </>
          )}
      </Card>
    </>
  );
}
