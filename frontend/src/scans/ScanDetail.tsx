import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, CheckCircle2, Circle, CircleSlash, Loader2, Square, XCircle } from "lucide-react";
import { api } from "@/api/client";
import type { AssetEvent, Page, Scan, ScopeDecision, Stage } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Timeline } from "@/components/Timeline";
import { Card, Empty, ErrorBox, Kpi, Loading, PageHead, Pagination, StatusBadge, Tabs } from "@/components/ui";
import { fmtDate, fmtDuration } from "@/lib/format";

const ICON: Record<string, JSX.Element> = {
  completed: <CheckCircle2 size={18} color="var(--success)" />,
  partial: <CheckCircle2 size={18} color="var(--sev-high)" />,
  running: <Loader2 size={18} color="var(--brand)" className="spin" style={{ animation: "spin 1s linear infinite" }} />,
  failed: <XCircle size={18} color="var(--danger)" />,
  skipped: <CircleSlash size={18} color="var(--foreground-subtle)" />,
  cancelled: <CircleSlash size={18} color="var(--foreground-subtle)" />,
  pending: <Circle size={18} color="var(--foreground-subtle)" />,
};

export default function ScanDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const { orgName } = useOrg();
  const qc = useQueryClient();
  const [tab, setTab] = useState<"stages" | "changes" | "authorization">("stages");
  const q = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api<Scan>(`/scans/${id}`),
    refetchInterval: (query) => (["pending", "queued", "running"].includes(query.state.data?.status ?? "") ? 4000 : false),
  });
  const cancel = useMutation({
    mutationFn: () => api(`/scans/${id}/cancel`, { method: "POST" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scan", id] }),
  });
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const s = q.data!;
  const running = ["pending", "queued", "running"].includes(s.status);

  return (
    <>
      <div className="small" style={{ marginBottom: 8 }}><Link to="/scans"><ArrowLeft size={13} /> Scans</Link></div>
      <PageHead title={`${s.profile_name} — ${orgName(s.organization_id)}`}
        sub={<div className="row"><StatusBadge value={s.status} />{s.is_baseline && <span className="badge neutral">baseline</span>}
          <span className="muted small">Created {fmtDate(s.created_at)}{s.finished_at ? ` · finished ${fmtDate(s.finished_at)}` : ""}</span></div>}
        actions={running && can("scans:run") && <button className="btn danger" onClick={() => cancel.mutate()}><Square /> Cancel</button>} />
      {s.error && <div style={{ marginBottom: 12 }}><ErrorBox error={new Error(s.error)} /></div>}
      <div className="grid kpis" style={{ marginBottom: 14 }}>
        <Kpi label="New assets" value={s.stats.new_assets ?? 0} onClick={() => setTab("changes")} />
        <Kpi label="Changes recorded" value={s.stats.events ?? 0} onClick={() => setTab("changes")} />
        <Kpi label="New findings" value={s.stats.new_findings ?? 0} onClick={() => setTab("changes")} />
        <Kpi label="Resolved findings" value={s.stats.resolved_findings ?? 0} onClick={() => setTab("changes")} />
        <Kpi label="Gone / closed" value={s.stats.deactivated ?? 0} onClick={() => setTab("changes")} />
      </div>
      <Tabs tabs={[{ id: "stages", label: "Pipeline" }, { id: "changes", label: "Changes" }, { id: "authorization", label: "Authorization log" }]}
            value={tab} onChange={setTab} />
      {tab === "stages" && (
        <Card flush>
          {s.stages?.map((st) => (
            <div className="stage" key={st.id}>
              {ICON[st.status] ?? ICON.pending}
              <div>
                <div><strong>{st.label}</strong>{st.is_active && <span className="badge warn" style={{ marginInlineStart: 8 }}>active</span>}</div>
                <div className="cell-sub">
                  {st.target_count} authorized target(s){st.rejected_count ? ` · ${st.rejected_count} rejected by scope` : ""}
                  {st.observation_count ? ` · ${st.observation_count} observations` : ""}
                  {st.stats?.duration_seconds !== undefined ? ` · ${fmtDuration(st.stats.duration_seconds)}` : ""}
                  {st.status === "running" && st.started_at && <RunningFor stage={st} />}
                </div>
                {st.error && <div className="small" style={{ color: st.status === "failed" ? "var(--sev-critical-text)" : "var(--foreground-muted)" }}>{st.error}</div>}
              </div>
              <StatusBadge value={st.status} />
            </div>
          ))}
        </Card>
      )}
      {tab === "changes" && <ScanChanges scanId={s.id} baseline={s.is_baseline} />}
      {tab === "authorization" && <Decisions scanId={s.id} />}
    </>
  );
}

function ScanChanges({ scanId, baseline }: { scanId: string; baseline: boolean }) {
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["scan-events", scanId, page], queryFn: () => api<Page<AssetEvent>>("/events",
    { query: { scan_id: scanId, include_baseline: true, page, page_size: 50 } }) });
  if (q.isLoading) return <Loading />;
  if (!q.data?.items.length) return <Card><Empty>No changes recorded by this scan.</Empty></Card>;
  return (
    <Card flush hint={baseline ? "Baseline scan: these establish the initial inventory and were not alerted." : undefined}>
      <Timeline events={q.data.items} showAsset />
      <Pagination page={page} pageSize={50} total={q.data.total} onPage={setPage} />
    </Card>
  );
}

function Decisions({ scanId }: { scanId: string }) {
  const [page, setPage] = useState(1);
  const [decision, setDecision] = useState("");
  const q = useQuery({ queryKey: ["decisions", scanId, page, decision], queryFn: () => api<Page<ScopeDecision>>(
    `/scans/${scanId}/decisions`, { query: { page, page_size: 100, decision: decision || undefined } }) });
  return (
    <Card flush>
      <div className="filters">
        <select value={decision} onChange={(e) => { setDecision(e.target.value); setPage(1); }}>
          <option value="">All decisions</option><option value="allowed">Allowed</option><option value="rejected">Rejected</option>
        </select>
        <span className="muted small">Every target is authorized against the organization's scope before any sensor contacts it.</span>
      </div>
      {q.isLoading ? <Loading /> : !q.data?.items.length ? <Empty>No decisions recorded.</Empty> : (
        <>
          <table className="data">
            <thead><tr><th>Target</th><th>Decision</th><th>Mode</th><th>Reason</th></tr></thead>
            <tbody>{q.data.items.map((d) => (
              <tr key={d.id}><td className="mono small">{d.target}</td><td><StatusBadge value={d.decision} /></td>
                <td className="small">{d.active ? "active" : "passive"}</td><td className="small">{d.reason}</td></tr>
            ))}</tbody>
          </table>
          <Pagination page={page} pageSize={100} total={q.data.total} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

function RunningFor({ stage }: { stage: Stage }) {
  const elapsed = (Date.now() - new Date(stage.started_at!).getTime()) / 1000;
  const limit = stage.time_limit_seconds ?? null;
  const over = limit !== null && elapsed > limit + 900;
  return (
    <span title="Some sources (notably Amass) report nothing until they finish; the stage stops on its own at its time limit.">
      {` · running for ${fmtDuration(elapsed)}`}
      {limit !== null && (over
        ? <span style={{ color: "var(--sev-high-text)" }}>{` — past its ${fmtDuration(limit)} limit; the watchdog will mark it failed`}</span>
        : ` of up to ${fmtDuration(limit)}`)}
    </span>
  );
}
