import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { Crosshair, Info, Plus } from "lucide-react";
import { api } from "@/api/client";
import type { ExposureEdge, ExposureMap, ExposureNode } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { Card, Empty, ErrorBox, Loading, SeverityBadge, StatusBadge } from "@/components/ui";
import { ASSET_TYPE_LABELS, fmtDate, label, SEV_COLOR, timeAgo } from "@/lib/format";

/** Columns follow the exposure chain; a column with no nodes is not drawn. */
const COLUMNS: { title: string; types: string[] }[] = [
  { title: "Domains", types: ["root_domain", "domain", "subdomain"] },
  { title: "IP addresses", types: ["ip_address", "cidr", "asn"] },
  { title: "Ports & services", types: ["port", "service"] },
  { title: "Web", types: ["http_endpoint", "web_application"] },
  { title: "Context", types: ["technology", "certificate", "cloud_resource"] },
  { title: "Findings", types: ["finding"] },
];
const W = 190, H = 40, COL_GAP = 56, ROW_GAP = 10, TOP = 30;
const MAX_CLIENT_NODES = 600;

const FRESHNESS: Record<string, { text: string; dash?: string; color: string; opacity?: number }> = {
  current: { text: "Observed in the last 14 days.", color: "var(--foreground-muted)" },
  stale: { text: "Not observed for more than 14 days; it may no longer be true.", dash: "7 4", color: "var(--foreground-muted)" },
  inactive: { text: "No longer observed. Kept as history; not part of the current attack surface.", dash: "2 4", color: "var(--foreground-subtle)", opacity: 0.55 },
  historical: { text: "Reported by a third-party database, not observed by your scans.", dash: "9 3 2 3", color: "var(--foreground-subtle)" },
  unverified: { text: "Reported by a third-party database and never tested.", dash: "4 3", color: "var(--foreground-subtle)" },
};

function short(s: string, n = 27) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

interface Params {
  depth: number;
  include_findings: boolean;
  include_unverified: boolean;
  include_inactive: boolean;
  include_context: boolean;
}

export default function ExposureGraph({ organizationId, assetId, onRecenter }: {
  organizationId?: string; assetId?: string; onRecenter?: (assetId: string) => void;
}) {
  const { can } = useAuth();
  const [p, setP] = useState<Params>({ depth: 2, include_findings: true, include_unverified: false, include_inactive: false,
    include_context: false });
  const [extra, setExtra] = useState<{ nodes: ExposureNode[]; edges: ExposureEdge[] }>({ nodes: [], edges: [] });
  const [selected, setSelected] = useState<{ kind: "node" | "edge"; id: string } | null>(null);
  const [expandError, setExpandError] = useState<unknown>(null);
  const [capped, setCapped] = useState(false);
  const base = useQuery({
    queryKey: ["exposure-map", organizationId, assetId, p],
    queryFn: () => api<ExposureMap>("/exposure-map", { query: { organization_id: assetId ? undefined : organizationId, asset_id: assetId, ...p } }),
    placeholderData: keepPreviousData,  // changing a filter keeps the current map on screen
  });

  const graph = useMemo(() => {
    const nodes = new Map<string, ExposureNode>();
    const edges = new Map<string, ExposureEdge>();
    for (const n of [...(base.data?.nodes ?? []), ...extra.nodes]) nodes.set(n.id, n);
    for (const e of [...(base.data?.edges ?? []), ...extra.edges]) if (nodes.has(e.source) && nodes.has(e.target)) edges.set(e.id, e);
    return { nodes: [...nodes.values()], edges: [...edges.values()] };
  }, [base.data, extra]);

  const layout = useMemo(() => {
    const cols = COLUMNS.map((c) => ({ ...c, nodes: graph.nodes.filter((n) => c.types.includes(n.type))
      .sort((a, b) => a.depth - b.depth || a.label.localeCompare(b.label)) })).filter((c) => c.nodes.length);
    const pos = new Map<string, { x: number; y: number }>();
    cols.forEach((c, ci) => c.nodes.forEach((n, ri) => pos.set(n.id, { x: ci * (W + COL_GAP) + 10, y: TOP + ri * (H + ROW_GAP) })));
    const rows = Math.max(1, ...cols.map((c) => c.nodes.length));
    return { cols, pos, width: cols.length * (W + COL_GAP) - COL_GAP + 20, height: TOP + rows * (H + ROW_GAP) + 10 };
  }, [graph]);

  async function expand(n: ExposureNode) {
    setExpandError(null);
    if (graph.nodes.length >= MAX_CLIENT_NODES) { setCapped(true); return; }
    try {
      const m = await api<ExposureMap>("/exposure-map", { query: { expand: n.id, per_node: 100, ...p } });
      setExtra((x) => ({ nodes: [...x.nodes.filter((o) => o.id !== n.id), ...m.nodes], edges: [...x.edges, ...m.edges] }));
    } catch (e) { setExpandError(e); }
  }

  if (base.isLoading) return <Loading text="Drawing the map…" />;
  if (base.error) return <ErrorBox error={base.error} />;
  const m = base.data!;
  const node = selected?.kind === "node" ? graph.nodes.find((n) => n.id === selected.id) : undefined;
  const edge = selected?.kind === "edge" ? graph.edges.find((e) => e.id === selected.id) : undefined;
  const name = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  const set = (k: keyof Params, v: boolean | number) => { setExtra({ nodes: [], edges: [] }); setSelected(null); setP({ ...p, [k]: v }); };

  return (
    <div className="stack">
      <div className="info-box row" style={{ gap: 8 }}><Info size={15} /> {m.notice} Full attack-path analysis would need authoritative cloud,
        identity and network data and is not part of this view.</div>
      <Card flush>
        <div className="filters">
          <label className="small">Depth <select value={p.depth} onChange={(e) => set("depth", Number(e.target.value))} aria-label="Depth">
            {[1, 2, 3, 4].map((d) => <option key={d} value={d}>{d}</option>)}</select></label>
          <label className="check small"><input type="checkbox" checked={p.include_findings} onChange={(e) => set("include_findings", e.target.checked)} /> Findings</label>
          <label className="check small"><input type="checkbox" checked={p.include_unverified} disabled={!p.include_findings}
            onChange={(e) => set("include_unverified", e.target.checked)} /> Unverified reports</label>
          <label className="check small"><input type="checkbox" checked={p.include_inactive} onChange={(e) => set("include_inactive", e.target.checked)} /> No longer observed</label>
          <label className="check small"><input type="checkbox" checked={p.include_context} onChange={(e) => set("include_context", e.target.checked)} /> Technologies & certificates</label>
          <span className="spacer" />
          <span className="small muted">{graph.nodes.length} nodes · {graph.edges.length} relationships</span>
        </div>
        {(m.truncated || capped) && (
          <div className="card-body small" style={{ color: "var(--sev-high-text)" }}>
            Partial map: {[...m.truncation_reasons, ...(capped ? [`the view holds at most ${MAX_CLIENT_NODES} nodes`] : [])].join("; ")}.
            Nodes marked “+” have more relationships; select one and expand it, or start from a specific asset.
          </div>
        )}
        <ErrorBox error={expandError} />
        {graph.nodes.length <= 1 && !graph.edges.length ? (
          <Empty>No recorded relationships here yet. Run a discovery scan, or include assets that are no longer observed.</Empty>
        ) : (
          <div style={{ display: "grid", gridTemplateColumns: "minmax(0, 1fr) 300px" }}>
            <div className="table-wrap" style={{ maxHeight: "70vh", overflow: "auto", borderInlineEnd: "1px solid var(--border)" }}>
              <svg width={layout.width} height={layout.height} role="img" aria-label="Exposure map" style={{ display: "block" }}>
                {layout.cols.map((c, ci) => (
                  <text key={c.title} x={ci * (W + COL_GAP) + 10} y={18} fontSize={11} fill="var(--foreground-subtle)" fontWeight={600}>{c.title.toUpperCase()}</text>
                ))}
                {graph.edges.map((e) => {
                  const a = layout.pos.get(e.source), b = layout.pos.get(e.target);
                  if (!a || !b) return null;
                  const st = FRESHNESS[e.freshness] ?? FRESHNESS.current;
                  const [l, r] = a.x <= b.x ? [a, b] : [b, a];
                  const d = l.x === r.x
                    ? `M${l.x + W},${l.y + H / 2} C${l.x + W + 45},${l.y + H / 2} ${r.x + W + 45},${r.y + H / 2} ${r.x + W},${r.y + H / 2}`
                    : `M${l.x + W},${l.y + H / 2} C${l.x + W + COL_GAP / 2},${l.y + H / 2} ${r.x - COL_GAP / 2},${r.y + H / 2} ${r.x},${r.y + H / 2}`;
                  const sel = selected?.kind === "edge" && selected.id === e.id;
                  return (
                    <g key={e.id} onClick={() => setSelected({ kind: "edge", id: e.id })} style={{ cursor: "pointer" }}
                       data-edge={e.id} data-relation={e.relation} data-freshness={e.freshness}>
                      <path d={d} stroke="transparent" strokeWidth={10} fill="none" />
                      <path d={d} fill="none" stroke={sel ? "var(--brand)" : st.color} strokeWidth={sel ? 2.5 : 1.2}
                            strokeDasharray={st.dash} opacity={st.opacity ?? 0.9}>
                        <title>{`${label(e.relation)} — ${e.freshness}`}</title>
                      </path>
                    </g>
                  );
                })}
                {graph.nodes.map((n) => {
                  const at = layout.pos.get(n.id)!;
                  const sel = selected?.kind === "node" && selected.id === n.id;
                  const hidden = Object.values(n.hidden ?? {}).reduce((s, v) => s + v, 0);
                  const faded = n.status === "inactive";
                  const dashed = n.third_party_only || n.unverified || faded;
                  const root = m.root_ids.includes(n.id);
                  return (
                    <g key={n.id} transform={`translate(${at.x},${at.y})`} onClick={() => setSelected({ kind: "node", id: n.id })}
                       style={{ cursor: "pointer" }} opacity={faded ? 0.55 : 1} role="button" aria-label={`${n.type} ${n.label}`}>
                      <rect width={W} height={H} rx={6} fill="var(--surface-elevated)"
                            stroke={sel ? "var(--brand)" : root ? "var(--link)" : "var(--border-strong)"}
                            strokeWidth={sel || root ? 2 : 1} strokeDasharray={dashed ? "4 3" : undefined} />
                      {n.kind === "finding" && <rect width={4} height={H} rx={2} fill={SEV_COLOR[n.severity ?? "info"]} />}
                      <text x={10} y={16} fontSize={12} fill="var(--foreground)">{short(n.label)}</text>
                      <text x={10} y={31} fontSize={10.5} fill="var(--foreground-subtle)">
                        {n.kind === "finding" ? `${n.severity}${n.unverified ? " · unverified" : ""}` : ASSET_TYPE_LABELS[n.type] ?? n.type}
                        {n.third_party_only ? " · third-party record" : ""}{faded ? " · no longer observed" : ""}
                      </text>
                      {(hidden > 0 || n.more_beyond_depth) && (
                        <text x={W - 8} y={16} fontSize={11} textAnchor="end" fill="var(--link)">{hidden > 0 ? `+${hidden}` : "+"}</text>
                      )}
                    </g>
                  );
                })}
              </svg>
            </div>
            <div className="card-body" style={{ minWidth: 0 }}>
              {!node && !edge && (
                <div className="small muted">
                  <p style={{ marginTop: 0 }}>Select a node or a line for details.</p>
                  <ul className="list small" style={{ margin: "0 -16px" }}>
                    {Object.entries(FRESHNESS).map(([k, v]) => (
                      <li key={k}><svg width={36} height={8}><line x1={0} y1={4} x2={36} y2={4} stroke={v.color} strokeWidth={1.5}
                        strokeDasharray={v.dash} opacity={v.opacity ?? 1} /></svg><span className="grow"><b>{label(k)}</b> — {v.text}</span></li>
                    ))}
                  </ul>
                </div>
              )}
              {node && (
                <div className="stack" style={{ gap: 8 }}>
                  <div className="cell-main" style={{ wordBreak: "break-all" }}>{node.label}</div>
                  <div className="row">
                    {node.kind === "finding" ? <><SeverityBadge value={node.severity ?? "info"} /><StatusBadge value={node.status} />
                      {node.unverified && <span className="badge neutral">unverified</span>}</>
                      : <><span className="badge accent">{ASSET_TYPE_LABELS[node.type] ?? node.type}</span><StatusBadge value={node.status} /><StatusBadge value={node.scope_status} /></>}
                  </div>
                  {node.third_party_only && <div className="small muted">Known only from a third-party database's record, not from your scans.</div>}
                  <dl className="kv small">
                    <dt>Risk</dt><dd>{node.risk_score ?? "—"}</dd>
                    <dt>First seen</dt><dd>{fmtDate(node.first_seen)}</dd>
                    <dt>Last seen</dt><dd>{timeAgo(node.last_seen)}</dd>
                  </dl>
                  {Object.entries(node.hidden ?? {}).length > 0 && (
                    <div className="small">Not shown: {Object.entries(node.hidden).map(([rel, n]) => `${n} × ${label(rel)}`).join(", ")}</div>
                  )}
                  <div className="row">
                    {node.kind === "asset" && (Object.keys(node.hidden ?? {}).length > 0 || node.more_beyond_depth) &&
                      <button className="btn sm" onClick={() => expand(node)}><Plus /> Expand</button>}
                    {node.kind === "asset" && onRecenter && <button className="btn sm ghost" onClick={() => onRecenter(node.id)}><Crosshair /> Start here</button>}
                    {node.kind === "asset" && <Link className="btn sm ghost" to={`/assets/${node.id}`}>Open asset</Link>}
                    {node.kind === "finding" && can("findings:read") && <Link className="btn sm ghost" to={`/findings/${node.finding_id}`}>Open finding</Link>}
                  </div>
                </div>
              )}
              {edge && (
                <div className="stack" style={{ gap: 8 }}>
                  <div className="cell-main">{label(edge.relation)}</div>
                  <div className="small"><span className="mono">{short(name(edge.source), 40)}</span> → <span className="mono">{short(name(edge.target), 40)}</span></div>
                  <p className="small" style={{ margin: 0 }}>{edge.meaning}</p>
                  <dl className="kv small">
                    <dt>Evidence</dt><dd>{edge.evidence === "derived" ? "derived by the platform" : edge.evidence}</dd>
                    <dt>Source</dt><dd>{edge.source_label}</dd>
                    <dt>First seen</dt><dd>{fmtDate(edge.first_seen)}</dd>
                    <dt>Last seen</dt><dd>{fmtDate(edge.last_seen)} ({edge.age_days} days ago)</dd>
                    <dt>Freshness</dt><dd>{label(edge.freshness)}</dd>
                  </dl>
                  <p className="small muted" style={{ margin: 0 }}>{(FRESHNESS[edge.freshness] ?? FRESHNESS.current).text}</p>
                </div>
              )}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
