import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Download, FilterX } from "lucide-react";
import { api, download } from "@/api/client";
import type { Finding, Page } from "@/api/types";
import { useOrg } from "@/auth/OrgContext";
import { Card, Empty, ErrorBox, Loading, PageHead, Pagination, RiskScore, SeverityBadge, SortTh, StatusBadge, useDebounced } from "@/components/ui";
import { FINDING_STATES, SEVERITIES, fmtDay, isDast, label, timeAgo } from "@/lib/format";
import { useFilters } from "@/lib/useFilters";

const MULTI = ["status", "severity", "category"] as const;
type Key = "status" | "severity" | "category" | "open_only" | "kev" | "q" | "cve" | "sort" | "order" | "page" | "unassigned"
  | "unverified";
const CATEGORIES = ["vulnerability", "exposure", "misconfiguration", "certificate", "service_exposure", "information"];

export default function Findings() {
  const f = useFilters<Key>(MULTI);
  const { orgId } = useOrg();
  const nav = useNavigate();
  const [search, setSearch] = useState(f.get("q") ?? "");
  const debounced = useDebounced(search, 350);
  // Clearing (× button, Esc, deleting the text) applies at once; typing is debounced.
  const q = search.trim() === "" ? "" : debounced;
  const searchRef = useRef<HTMLInputElement>(null);
  const onSearch = (v: string) => { setSearch(v); f.set("q", v || undefined); };
  useEffect(() => {
    // Some browsers report the × clear only as a native "search" event.
    const el = searchRef.current;
    const h = () => { if (el && el.value !== search) onSearch(el.value); };
    el?.addEventListener("search", h);
    return () => el?.removeEventListener("search", h);
  });
  const statuses = f.getAll("status");
  // Third-party reports nobody tested (Shodan CVE matches) have their own view.
  const unverified = f.get("unverified") === "true";
  const query = {
    ...f.query,
    open_only: statuses.length ? undefined : f.get("open_only") ?? "true",
    q: q || undefined, organization_id: orgId, page: f.page, page_size: 50,
  };
  const findings = useQuery({ queryKey: ["findings", query], queryFn: () => api<Page<Finding>>("/findings", { query }) });
  const sort = f.get("sort") ?? "risk";
  const order = f.get("order") ?? "desc";
  const th = (key: string, text: string) => (
    <SortTh id={key} sort={sort} order={order} onSort={(s, o) => f.setMany({ sort: s, order: o })}>{text}</SortTh>
  );

  return (
    <>
      <PageHead title="Findings" sub="Vulnerabilities and exposures, prioritized by practical risk — not CVSS alone."
                actions={<button className="btn" onClick={() => download("/findings/export.csv", { ...query, page: undefined, page_size: undefined }, "findings.csv")}><Download /> Export CSV</button>} />
      <div className="tabs" style={{ marginBottom: 12 }}>
        <button className={`btn sm ${unverified ? "ghost" : "primary"}`}
                onClick={() => f.set("unverified", undefined)}>Confirmed findings</button>
        <button className={`btn sm ${unverified ? "primary" : "ghost"}`} title="Reported by a third-party database (e.g. Shodan) from the service version it saw, and not yet verified against the live service"
                onClick={() => f.set("unverified", "true")}>Reported, unverified</button>
      </div>
      <Card flush>
        {unverified && <div className="card-body"><div className="info-box">These issues were reported by an external
          database from the service version it observed — nobody tested them. They do not affect risk scores, reports or
          alerts. A scan that confirms one shows it under “Confirmed findings”.</div></div>}
        <div className="filters">
          <input ref={searchRef} type="search" placeholder="Search title, location, rule…" value={search} aria-label="Search findings"
                 onChange={(e) => onSearch(e.target.value)} />
          <select value={statuses[0] ?? (f.get("open_only") === "false" ? "all" : "")} onChange={(e) => {
            const v = e.target.value;
            if (v === "all") f.setMany({ status: undefined, open_only: "false" });
            else f.setMany({ status: v ? [v] : undefined, open_only: undefined });
          }}>
            <option value="">Open (new, investigating, reopened)</option>
            <option value="all">All statuses</option>
            {FINDING_STATES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
          </select>
          <select value={f.getAll("severity")[0] ?? ""} onChange={(e) => f.set("severity", e.target.value ? [e.target.value] : undefined)}>
            <option value="">Any severity</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{label(s)}</option>)}
          </select>
          <select value={f.getAll("category")[0] ?? ""} onChange={(e) => f.set("category", e.target.value ? [e.target.value] : undefined)}>
            <option value="">Any category</option>
            {CATEGORIES.map((c) => <option key={c} value={c}>{label(c)}</option>)}
          </select>
          <input placeholder="CVE-…" style={{ width: 140 }} defaultValue={f.get("cve")} onBlur={(e) => f.set("cve", e.target.value || undefined)} />
          <label className="check small"><input type="checkbox" checked={f.get("kev") === "true"}
                 onChange={(e) => f.set("kev", e.target.checked ? "true" : undefined)} /> Known exploited only</label>
          <label className="check small"><input type="checkbox" checked={f.get("unassigned") === "true"}
                 onChange={(e) => f.set("unassigned", e.target.checked ? "true" : undefined)} /> Unassigned</label>
          <button className="btn ghost sm" onClick={() => { f.clear(); setSearch(""); }}><FilterX /> Reset</button>
        </div>
        {findings.isLoading ? <Loading /> : findings.error ? <div className="card-body"><ErrorBox error={findings.error} /></div> :
          !findings.data!.items.length ? <Empty>No findings match these filters.</Empty> : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <thead><tr>{th("risk", "Risk")}{th("severity", "Severity")}{th("title", "Finding")}{th("asset", "Asset")}{th("status", "Status")}
                    {th("first_seen", "First seen")}{th("last_seen", "Last seen")}{th("detection", "Detection")}</tr></thead>
                  <tbody>
                    {findings.data!.items.map((x) => (
                      <tr key={x.id} className="clickable" onClick={() => nav(`/findings/${x.id}`)}>
                        <td><RiskScore score={x.risk_score} /></td>
                        <td><SeverityBadge value={x.severity} /></td>
                        <td>
                          <div className="cell-main"><Link to={`/findings/${x.id}`} className="row-link" onClick={(e) => e.stopPropagation()}>{x.title}</Link>
                            {x.kev && <span className="badge bad" style={{ marginInlineStart: 6 }}>KEV</span>}
                            {isDast(x.source) && <span className="badge accent" style={{ marginInlineStart: 6 }}
                              title="Dynamically confirmed by active web scanning (OWASP ZAP)">DAST</span>}
                            {x.unverified && <span className="badge warn" style={{ marginInlineStart: 6 }}
                              title="Reported by an external database, not verified against the live service">unverified</span>}</div>
                          <div className="cell-sub">{x.cve.join(", ")}{x.epss_score ? ` · EPSS ${(x.epss_score * 100).toFixed(0)}%` : ""}</div>
                        </td>
                        <td className="small">{x.asset ? <Link to={`/assets/${x.asset.id}`} onClick={(e) => e.stopPropagation()}>{x.asset.value}</Link> : "—"}</td>
                        <td><StatusBadge value={x.status} /></td>
                        <td className="small">{fmtDay(x.first_seen)}</td>
                        <td className="small">{timeAgo(x.last_seen)}</td>
                        <td className="small muted">{x.source_label}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination page={f.page} pageSize={50} total={findings.data!.total} onPage={f.setPage} />
            </>
          )}
      </Card>
    </>
  );
}
