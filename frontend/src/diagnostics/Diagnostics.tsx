import { Fragment, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Download, FileArchive, Trash2 } from "lucide-react";
import { api, download } from "@/api/client";
import { useAuth } from "@/auth/AuthContext";
import { Card, Confirm, Empty, ErrorBox, Field, Kpi, Loading, Modal, PageHead, Pagination, StatusBadge, Tabs } from "@/components/ui";
import { bytes, fmtDate, fmtDuration } from "@/lib/format";

// Diagnostics & Support. Two scopes that never mix:
//  * tenant   — /diagnostics: this tenant's scans, problems and support bundles (server: tenant session + RLS).
//  * platform — /platform/diagnostics: service/scanner/queue/host health and operational events
//               (server: platform:diagnostics only).
// Anything the server could not measure arrives as {status: "unavailable", reason} and is shown that way —
// never as zero or healthy.

type Scope = "tenant" | "platform";
interface Unavailable { status: "unavailable"; reason: string }
const isUnavailable = (v: unknown): v is Unavailable =>
  typeof v === "object" && v !== null && (v as Unavailable).status === "unavailable";

interface StageTiming { queue_wait_ms?: number | null; execution_ms?: number | null; ingestion_ms?: number | null; total_ms?: number | null }
interface StageRow {
  id: string; position: number; stage_type: string; label: string; status: string; coverage: string;
  target_count: number; rejected_count: number; observation_count: number; error: string | null;
  started_at: string | null; dispatched_at: string | null; finished_at: string | null;
  timing: StageTiming | null; timed_out: boolean | null; retries: number | null;
}
interface ScanRow {
  id: string; profile: string; status: string; trigger: string; created_at: string; started_at: string | null;
  finished_at: string | null; stages: StageRow[]; tenant_id?: string; tenant_name?: string;
  summary: { queue_wait_ms: number | null; execution_ms: number | null; partial_stages: number; failed_stages: number; timeouts: number };
}
interface ScanPage { items: ScanRow[]; total: number; page: number; page_size: number }
interface TenantEvent { ts: string | null; kind: string; level: string; title: string; detail: string | null; scan_id?: string | null }
interface OpsEvent {
  id: number; event_id: string; ts: string; level: string; service: string; event: string | null; error_code: string | null;
  message: string; tenant_id: string | null; request_id: string | null; scan_id: string | null; pool: string | null; data: unknown;
}
interface Bundle {
  id: string; scope: Scope; status: string; progress: number; error: string | null; window_start: string; window_end: string;
  scan_ids: string[]; size: number | null; sha256: string | null; filename: string | null; created_at: string | null;
  finished_at: string | null; expires_at: string;
  contents: { files: { name: string; bytes: number; sha256: string }[]; truncated: string[]; included: string[]; omitted: string[] } | null;
}
interface Preview {
  scope: Scope; window_start: string; window_end: string; included: string[]; excluded: string[];
  counts: Record<string, number>; limits: { max_mb: number; max_seconds: number; retention_days: number };
}

export function ms(v: number | null | undefined): string {
  if (v === null || v === undefined) return "—";
  return v < 1000 ? `${v} ms` : fmtDuration(v / 1000);
}

function Unavail({ value, children }: { value: unknown; children?: (v: never) => ReactNode }) {
  if (isUnavailable(value)) return <span className="badge neutral" title={value.reason}>Unavailable</span>;
  return <>{children ? children(value as never) : String(value)}</>;
}

function Reason({ value }: { value: unknown }) {
  return isUnavailable(value) ? <div className="small subtle">{value.reason}</div> : null;
}

// ------------------------------------------------------------------ page
export default function Diagnostics({ scope }: { scope: Scope }) {
  const { can } = useAuth();
  type Tab = "overview" | "health" | "scans" | "events" | "bundles";
  const tabs: { id: Tab; label: string }[] = scope === "platform"
    ? [{ id: "health", label: "Service health" }, { id: "events", label: "Operational events" },
       { id: "scans", label: "Scan timelines" }, { id: "bundles", label: "Support bundles" }]
    : [{ id: "overview", label: "Overview" }, { id: "scans", label: "Scan timelines" }, { id: "events", label: "Problems" },
       ...(can("support:bundles") ? [{ id: "bundles" as Tab, label: "Support bundles" }] : [])];
  const [tab, setTab] = useState<Tab>(tabs[0].id);
  return (
    <>
      <PageHead title={scope === "platform" ? "Platform diagnostics" : "Diagnostics & Support"}
                sub={scope === "platform"
                  ? "Health of every service, scanner pool and queue, operational errors across tenants, and platform support bundles."
                  : "How your scans are running, what went wrong recently, and support bundles you can hand to your platform operator."} />
      <Tabs tabs={tabs} value={tab} onChange={setTab} />
      <div style={{ marginTop: 14 }}>
        {tab === "overview" && <TenantOverview />}
        {tab === "health" && <PlatformHealth />}
        {tab === "scans" && <ScanTimelines scope={scope} />}
        {tab === "events" && (scope === "platform" ? <OpsEvents /> : <TenantEvents />)}
        {tab === "bundles" && <Bundles scope={scope} />}
      </div>
    </>
  );
}

// -------------------------------------------------------------- overview
interface TenantOverviewData {
  window_days: number; scans: Record<string, number>;
  stages: { finished: number; partial: number; failed: number; timeouts: number };
  queue_wait_ms_p50: number | Unavailable; execution_ms_p50: number | Unavailable; notification_failures: number;
  scanner: Unavailable | { status: string; instances: number; detection_content: string; dedicated: boolean };
}

function TenantOverview() {
  const q = useQuery({ queryKey: ["diag", "tenant-overview"], queryFn: () => api<TenantOverviewData>("/diagnostics/tenant/overview") });
  if (q.isLoading) return <Loading />;
  if (!q.data) return <ErrorBox error={q.error} />;
  const d = q.data;
  const total = Object.values(d.scans).reduce((a, b) => a + b, 0);
  return (
    <div className="stack">
      <div className="grid kpis">
        <Kpi label={`Scans (last ${d.window_days} days)`} value={total}
             delta={Object.entries(d.scans).map(([k, v]) => `${v} ${k}`).join(" · ") || "none"} />
        <Kpi label="Partial stages" value={d.stages.partial} tone={d.stages.partial ? "warn" : undefined}
             delta={`of ${d.stages.finished} finished`} />
        <Kpi label="Failed stages" value={d.stages.failed} tone={d.stages.failed ? "danger" : undefined}
             delta={`${d.stages.timeouts} timed out`} />
        <Kpi label="Typical queue wait" value={<Unavail value={d.queue_wait_ms_p50}>{(v: number) => ms(v)}</Unavail>}
             delta={isUnavailable(d.queue_wait_ms_p50) ? d.queue_wait_ms_p50.reason : "median per stage"} />
        <Kpi label="Typical stage run time" value={<Unavail value={d.execution_ms_p50}>{(v: number) => ms(v)}</Unavail>}
             delta={isUnavailable(d.execution_ms_p50) ? d.execution_ms_p50.reason : "median per stage"} />
        <Kpi label="Failed notifications" value={d.notification_failures} tone={d.notification_failures ? "warn" : undefined} />
      </div>
      <Card title="Scanner for your scans">
        {isUnavailable(d.scanner) ? (
          <div className="stack"><span><span className="badge bad">Unavailable</span></span>
            <div className="small">{d.scanner.reason}. New scans will wait in the queue until a scanner is back.</div></div>
        ) : (
          <dl className="kv">
            <dt>Status</dt><dd><span className={`badge ${d.scanner.status === "ok" ? "ok" : "warn"}`}>{d.scanner.status}</span></dd>
            <dt>Instances</dt><dd>{d.scanner.instances}</dd>
            <dt>Detection content</dt><dd>{d.scanner.detection_content}</dd>
            <dt>Scanner pool</dt><dd>{d.scanner.dedicated ? "Dedicated to your organization" : "Shared"}</dd>
          </dl>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------- scan timelines
function ScanTimelines({ scope }: { scope: Scope }) {
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const q = useQuery({ queryKey: ["diag", scope, "scans", page, status],
    queryFn: () => api<ScanPage>(`/diagnostics/${scope}/scans`, { query: { page, status: status || undefined } }) });
  return (
    <Card flush>
      <div className="filters">
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }} aria-label="Scan status">
          <option value="">All statuses</option>
          {["queued", "running", "completed", "partial", "failed", "cancelled"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <span className="small subtle">Last 30 days. Queue wait, run time and ingestion are measured per stage.</span>
      </div>
      {q.isLoading ? <Loading /> : !q.data?.items.length ? <Empty>No scans in the last 30 days.</Empty> : (
        <>
          <table className="data">
            <thead><tr><th /><th>Scan</th>{scope === "platform" && <th>Tenant</th>}<th>Status</th><th>Started</th>
              <th>Queue wait</th><th>Run time</th><th>Problems</th></tr></thead>
            <tbody>{q.data.items.map((s) => (
              <Fragment key={s.id}>
                <tr className="clickable" onClick={() => setOpen(open === s.id ? null : s.id)}>
                  <td><button className="btn ghost sm" aria-label={open === s.id ? "Hide stages" : "Show stages"} aria-expanded={open === s.id}>{open === s.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</button></td>
                  <td>{scope === "tenant" ? <Link to={`/scans/${s.id}`} onClick={(e) => e.stopPropagation()}>{s.profile}</Link> : s.profile}
                    <div className="cell-sub mono">{s.id.slice(0, 8)}</div></td>
                  {scope === "platform" && <td className="small">{s.tenant_name}<div className="cell-sub mono">{s.tenant_id?.slice(0, 8)}</div></td>}
                  <td><StatusBadge value={s.status} /></td>
                  <td className="small">{fmtDate(s.started_at ?? s.created_at)}</td>
                  <td className="small">{ms(s.summary.queue_wait_ms)}</td>
                  <td className="small">{ms(s.summary.execution_ms)}</td>
                  <td className="small">
                    {s.summary.failed_stages > 0 && <span className="badge bad">{s.summary.failed_stages} failed</span>}{" "}
                    {s.summary.partial_stages > 0 && <span className="badge warn">{s.summary.partial_stages} partial</span>}{" "}
                    {s.summary.timeouts > 0 && <span className="badge warn">{s.summary.timeouts} timed out</span>}
                  </td>
                </tr>
                {open === s.id && (
                  <tr><td colSpan={scope === "platform" ? 8 : 7} style={{ background: "var(--bg-subtle, transparent)" }}>
                    <StageTable stages={s.stages} />
                  </td></tr>
                )}
              </Fragment>
            ))}</tbody>
          </table>
          <Pagination page={page} pageSize={q.data.page_size} total={q.data.total} onPage={setPage} />
        </>
      )}
    </Card>
  );
}

function StageTable({ stages }: { stages: StageRow[] }) {
  if (!stages.length) return <Empty>No stages.</Empty>;
  return (
    <table className="data compact">
      <thead><tr><th>#</th><th>Stage</th><th>Status</th><th>Coverage</th><th>Targets</th><th>Queue wait</th>
        <th>Run time</th><th>Ingestion</th><th>Retries</th><th>Detail</th></tr></thead>
      <tbody>{stages.map((st) => (
        <tr key={st.id}>
          <td className="mono small">{st.position}</td>
          <td className="small">{st.label}</td>
          <td><StatusBadge value={st.status} />{st.timed_out && <> <span className="badge warn">timed out</span></>}</td>
          <td className="small">{st.coverage}</td>
          <td className="small">{st.target_count}{st.rejected_count ? <span className="subtle"> ({st.rejected_count} rejected)</span> : null}</td>
          {st.timing ? (<>
            <td className="small">{ms(st.timing.queue_wait_ms)}</td>
            <td className="small">{ms(st.timing.execution_ms)}</td>
            <td className="small">{ms(st.timing.ingestion_ms)}</td>
            <td className="small">{st.retries ?? "—"}</td>
          </>) : <td colSpan={4} className="small subtle" title="Timing is recorded for stages finished since diagnostics were added">Timing unavailable</td>}
          <td className="small truncate" style={{ maxWidth: 360 }} title={st.error ?? undefined}>{st.error ?? ""}</td>
        </tr>
      ))}</tbody>
    </table>
  );
}

// ----------------------------------------------------------------- events
function TenantEvents() {
  const [page, setPage] = useState(1);
  const q = useQuery({ queryKey: ["diag", "tenant-events", page],
    queryFn: () => api<{ items: TenantEvent[]; page: number; page_size: number; has_more: boolean }>("/diagnostics/tenant/events", { query: { page } }) });
  if (q.isLoading) return <Loading />;
  if (!q.data) return <ErrorBox error={q.error} />;
  return (
    <Card flush title="Problems in the last 30 days" hint="Failed or partial scan stages, failed notifications, screenshots and Threat Center checks.">
      {!q.data.items.length ? <Empty>Nothing went wrong in the last 30 days.</Empty> : (
        <table className="data">
          <thead><tr><th>Time</th><th>Level</th><th>What</th><th>Detail</th><th /></tr></thead>
          <tbody>{q.data.items.map((e, i) => (
            <tr key={`${e.ts}-${i}`}>
              <td className="small">{fmtDate(e.ts)}</td>
              <td><span className={`badge ${e.level === "error" ? "bad" : "warn"}`}>{e.level}</span></td>
              <td className="small">{e.title}</td>
              <td className="small truncate" style={{ maxWidth: 480 }} title={e.detail ?? undefined}>{e.detail ?? ""}</td>
              <td className="small">{e.scan_id && <Link to={`/scans/${e.scan_id}`}>Scan</Link>}</td>
            </tr>
          ))}</tbody>
        </table>
      )}
      <div className="row" style={{ padding: 10 }}>
        <button className="btn sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>Newer</button>
        <button className="btn sm" disabled={!q.data.has_more} onClick={() => setPage(page + 1)}>Older</button>
      </div>
    </Card>
  );
}

function OpsEvents() {
  const [page, setPage] = useState(1);
  const [level, setLevel] = useState("");
  const [service, setService] = useState("");
  const [code, setCode] = useState("");
  const [open, setOpen] = useState<OpsEvent | null>(null);
  const q = useQuery({ queryKey: ["diag", "ops-events", page, level, service, code],
    queryFn: () => api<{ items: OpsEvent[]; total: number; page_size: number }>("/diagnostics/platform/events",
      { query: { page, level: level || undefined, service: service || undefined, error_code: code || undefined } }) });
  return (
    <Card flush>
      <div className="filters">
        <select value={level} onChange={(e) => { setLevel(e.target.value); setPage(1); }} aria-label="Level">
          <option value="">Warnings and errors</option><option value="WARNING">Warnings</option>
          <option value="ERROR">Errors</option><option value="CRITICAL">Critical</option>
        </select>
        <select value={service} onChange={(e) => { setService(e.target.value); setPage(1); }} aria-label="Service">
          <option value="">All services</option>
          {["api", "worker", "ingest", "scheduler"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <input placeholder="Error code (ASM-…)" value={code} onChange={(e) => { setCode(e.target.value.trim()); setPage(1); }} />
        <span className="small subtle">Last 14 days, redacted. Scanner errors are under Service health.</span>
      </div>
      {q.isLoading ? <Loading /> : !q.data?.items.length ? <Empty>No operational warnings or errors.</Empty> : (
        <>
          <table className="data">
            <thead><tr><th>Time</th><th>Level</th><th>Service</th><th>Code</th><th>Message</th><th>Tenant</th></tr></thead>
            <tbody>{q.data.items.map((e) => (
              <tr key={e.id} className="clickable" onClick={() => setOpen(e)}>
                <td className="small">{fmtDate(e.ts)}</td>
                <td><span className={`badge ${e.level === "WARNING" ? "warn" : "bad"}`}>{e.level}</span></td>
                <td className="small">{e.service}</td>
                <td className="mono small">{e.error_code ?? ""}</td>
                <td className="small truncate" style={{ maxWidth: 520 }}>{e.message}</td>
                <td className="mono small">{e.tenant_id?.slice(0, 8) ?? ""}</td>
              </tr>
            ))}</tbody>
          </table>
          <Pagination page={page} pageSize={q.data.page_size} total={q.data.total} onPage={setPage} />
        </>
      )}
      {open && (
        <Modal wide title={<>Event {open.error_code ?? open.event ?? ""}</>} onClose={() => setOpen(null)}
               footer={<button className="btn" onClick={() => setOpen(null)}>Close</button>}>
          <dl className="kv">
            <dt>Time</dt><dd>{fmtDate(open.ts)}</dd>
            <dt>Event ID</dt><dd className="mono small">{open.event_id}</dd>
            <dt>Service</dt><dd>{open.service}</dd>
            {open.event && (<><dt>Event</dt><dd className="mono small">{open.event}</dd></>)}
            {open.request_id && (<><dt>Request ID</dt><dd className="mono small">{open.request_id}</dd></>)}
            {open.scan_id && (<><dt>Scan</dt><dd className="mono small">{open.scan_id}</dd></>)}
            {open.pool && (<><dt>Pool</dt><dd>{open.pool}</dd></>)}
            <dt>Message</dt><dd><pre className="json">{open.message}</pre></dd>
          </dl>
          {open.data != null && <pre className="json">{JSON.stringify(open.data, null, 2)}</pre>}
        </Modal>
      )}
    </Card>
  );
}

// ---------------------------------------------------------- platform health
type Health = Record<string, unknown> & {
  collected_at: string; version: string; broker: unknown;
  database: Unavailable | { status: string; server_version: string; schema_version: string; expected_schema: string; size_bytes: number; connections: number };
  host: { hostname: string; cpus: number; load: number[] | Unavailable; memory: Unavailable | { total_bytes: number; available_bytes: number };
    disks: Record<string, Unavailable | { total_bytes: number; free_bytes: number }>; cgroup_oom_kills: number | Unavailable };
  units: Unavailable | Record<string, Unavailable | { active: string; sub: string; restarts: number; last_result: string; oom_killed: boolean; since: string; memory_bytes: number | null }>;
  services: Record<string, Unavailable | { status: string; instances: number; versions: string[]; last_seen_seconds: number }>;
  scanners: Record<string, Unavailable | { status: string; instances: Record<string, unknown>[]; recent_errors: { ts: string; msg: string; error_code?: string | null }[] }>;
  queues: Unavailable | Record<string, { depth: number; oldest_age_seconds: number | null; age_note: string | null }>;
};

function Status({ value }: { value: unknown }) {
  if (isUnavailable(value)) return <span className="badge neutral" title={value.reason}>Unavailable</span>;
  const s = (value as { status?: string })?.status ?? "unknown";
  return <span className={`badge ${s === "ok" ? "ok" : s === "degraded" ? "warn" : "bad"}`}>{s}</span>;
}

function PlatformHealth() {
  const q = useQuery({ queryKey: ["diag", "platform-health"], queryFn: () => api<Health>("/diagnostics/platform/health"),
    refetchInterval: 30_000 });
  if (q.isLoading) return <Loading />;
  if (!q.data) return <ErrorBox error={q.error} />;
  const h = q.data;
  const mem = h.host.memory;
  return (
    <div className="stack">
      <div className="small subtle">Version {h.version} · collected {fmtDate(h.collected_at)} · refreshes every 30 seconds.</div>
      <div className="grid kpis">
        <Kpi label="Database" value={<Status value={h.database} />}
             delta={isUnavailable(h.database) ? h.database.reason
               : `PostgreSQL ${h.database.server_version} · schema ${h.database.schema_version}${h.database.schema_version !== h.database.expected_schema ? ` (expected ${h.database.expected_schema})` : ""}`} />
        <Kpi label="Message broker" value={<Status value={h.broker} />} delta={isUnavailable(h.broker) ? h.broker.reason : undefined} />
        <Kpi label="Load (1/5/15 min)" value={<Unavail value={h.host.load}>{(v: number[]) => v.join(" / ")}</Unavail>} delta={`${h.host.cpus} CPUs · ${h.host.hostname}`} />
        <Kpi label="Memory available" value={<Unavail value={mem}>{(v: { available_bytes: number }) => bytes(v.available_bytes)}</Unavail>}
             delta={isUnavailable(mem) ? mem.reason : `of ${bytes(mem.total_bytes)}`} />
        {Object.entries(h.host.disks).map(([k, d]) => (
          <Kpi key={k} label={`Disk free (${k})`} value={<Unavail value={d}>{(v: { free_bytes: number }) => bytes(v.free_bytes)}</Unavail>}
               delta={isUnavailable(d) ? d.reason : `of ${bytes(d.total_bytes)}`}
               tone={!isUnavailable(d) && d.free_bytes / d.total_bytes < 0.1 ? "danger" : undefined} />
        ))}
        <Kpi label="OOM kills (this service)" value={<Unavail value={h.host.cgroup_oom_kills} />} />
      </div>
      <Card flush title="Services" hint="From heartbeats every 30 seconds; missing for 90 seconds means unavailable.">
        <table className="data">
          <thead><tr><th>Service</th><th>Status</th><th>Instances</th><th>Versions</th><th>Last seen</th></tr></thead>
          <tbody>{Object.entries(h.services).map(([name, s]) => (
            <tr key={name}><td>{name}</td><td><Status value={s} /><Reason value={s} /></td>
              {isUnavailable(s) ? <td colSpan={3} /> : (<>
                <td>{s.instances}</td><td className="small">{s.versions.join(", ")}</td><td className="small">{Math.round(s.last_seen_seconds)}s ago</td></>)}
            </tr>
          ))}</tbody>
        </table>
      </Card>
      <Card flush title="Scanner pools">
        <table className="data">
          <thead><tr><th>Pool</th><th>Status</th><th>Instances</th><th>Detection content</th><th>Last job</th><th>Recent errors</th></tr></thead>
          <tbody>{Object.entries(h.scanners).map(([pool, s]) => (
            <tr key={pool}><td>{pool}</td><td><Status value={s} /><Reason value={s} /></td>
              {isUnavailable(s) ? <td colSpan={4} /> : (<>
                <td>{s.instances.length}</td>
                <td className="small">{s.instances.map((i, n) => {
                  const r = (i.detection_rules ?? {}) as { available?: boolean; count?: number; reason?: string };
                  return <div key={n}>{r.available ? `${r.count ?? "?"} rules` : <span className="badge warn" title={r.reason}>missing</span>}</div>;
                })}</td>
                <td className="small">{s.instances.map((i, n) => {
                  const j = i.last_job as { status?: string; ts?: string } | null;
                  return <div key={n}>{j?.status ? `${j.status} · ${fmtDate(j.ts)}` : "none yet"}</div>;
                })}</td>
                <td className="small">{s.recent_errors.length
                  ? <details><summary>{s.recent_errors.length}</summary>{s.recent_errors.map((e, n) => <div key={n} className="mono small">{fmtDate(e.ts)} {e.error_code ?? ""} {e.msg}</div>)}</details>
                  : "none"}</td></>)}
            </tr>
          ))}</tbody>
        </table>
      </Card>
      <Card flush title="Queues" hint="Depth and age of the oldest waiting message.">
        {isUnavailable(h.queues) ? <div className="small" style={{ padding: 12 }}><Status value={h.queues} /> {h.queues.reason}</div> : (
          <table className="data">
            <thead><tr><th>Queue</th><th>Waiting</th><th>Oldest</th></tr></thead>
            <tbody>{Object.entries(h.queues).map(([name, v]) => (
              <tr key={name}><td className="mono small">{name}</td><td>{v.depth}</td>
                <td className="small">{v.oldest_age_seconds != null ? fmtDuration(v.oldest_age_seconds) : v.age_note ?? "—"}</td></tr>
            ))}</tbody>
          </table>
        )}
      </Card>
      <Card flush title="System services" hint="Restarts, last result and memory per systemd unit (native installs).">
        {isUnavailable(h.units) ? <div className="small" style={{ padding: 12 }}><Status value={h.units} /> {h.units.reason}</div> : (
          <table className="data">
            <thead><tr><th>Unit</th><th>State</th><th>Restarts</th><th>Last result</th><th>Memory</th><th>Since</th></tr></thead>
            <tbody>{Object.entries(h.units).map(([name, u]) => (
              <tr key={name}><td className="mono small">{name}</td>
                {isUnavailable(u) ? <td colSpan={5}><Status value={u} /> <span className="small subtle">{u.reason}</span></td> : (<>
                  <td><span className={`badge ${u.active === "active" ? "ok" : "bad"}`}>{u.active}/{u.sub}</span></td>
                  <td>{u.restarts}</td>
                  <td>{u.oom_killed ? <span className="badge bad">OOM killed</span> : u.last_result}</td>
                  <td className="small">{bytes(u.memory_bytes)}</td><td className="small">{u.since}</td></>)}
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

// --------------------------------------------------------------- bundles
const toLocal = (d: Date) => new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

function Bundles({ scope }: { scope: Scope }) {
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [reviewing, setReviewing] = useState<Bundle | null>(null);
  const [deleting, setDeleting] = useState<Bundle | null>(null);
  const list = useQuery({ queryKey: ["diag", scope, "bundles"], queryFn: () => api<Bundle[]>("/diagnostics/bundles", { query: { scope } }),
    refetchInterval: (q) => (q.state.data ?? []).some((b) => b.status === "queued" || b.status === "running") ? 2000 : false });
  const del = useMutation({
    mutationFn: (b: Bundle) => api(`/diagnostics/bundles/${b.id}`, { method: "DELETE", query: { scope } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["diag", scope, "bundles"] }),
  });
  return (
    <div className="stack">
      <Card title="Support bundles"
            hint={`A zip of diagnostic information for troubleshooting. Nothing is sent anywhere — you download it and decide who gets it. Bundles are deleted automatically after 7 days.`}
            right={<button className="btn primary" onClick={() => setCreating(true)}><FileArchive /> Generate support bundle</button>}>
        <ErrorBox error={del.error} />
        {list.isLoading ? <Loading /> : !list.data?.length ? <Empty>No support bundles.</Empty> : (
          <table className="data">
            <thead><tr><th>Requested</th><th>Window</th><th>Scans</th><th>Status</th><th>Size</th><th>Expires</th><th /></tr></thead>
            <tbody>{list.data.map((b) => (
              <tr key={b.id}>
                <td className="small">{fmtDate(b.created_at)}</td>
                <td className="small">{fmtDate(b.window_start)} → {fmtDate(b.window_end)}</td>
                <td>{b.scan_ids.length || "—"}</td>
                <td>{b.status === "running" || b.status === "queued"
                  ? <span className="badge accent">{b.status} · {b.progress}%</span>
                  : <StatusBadge value={b.status} />}
                  {b.error && <div className="small subtle">{b.error}</div>}</td>
                <td className="small">{bytes(b.size)}</td>
                <td className="small">{fmtDate(b.expires_at)}</td>
                <td className="row">
                  {b.status === "ready" && <button className="btn sm" onClick={() => setReviewing(b)}><Download /> Review &amp; download</button>}
                  {b.status !== "queued" && b.status !== "running" &&
                    <button className="btn sm ghost" aria-label="Delete bundle" onClick={() => setDeleting(b)}><Trash2 /></button>}
                </td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
      {creating && <NewBundle scope={scope} onClose={() => setCreating(false)}
                              onCreated={() => { setCreating(false); qc.invalidateQueries({ queryKey: ["diag", scope, "bundles"] }); }} />}
      {reviewing && <ReviewBundle bundle={reviewing} scope={scope} onClose={() => setReviewing(null)} />}
      {deleting && <Confirm danger text="Delete this support bundle? The file is removed and the link stops working."
                            onConfirm={() => del.mutate(deleting)} onClose={() => setDeleting(null)} />}
    </div>
  );
}

function NewBundle({ scope, onClose, onCreated }: { scope: Scope; onClose: () => void; onCreated: () => void }) {
  const now = new Date();
  const [start, setStart] = useState(toLocal(new Date(now.getTime() - 24 * 3600_000)));
  const [end, setEnd] = useState(toLocal(now));
  const [scanIds, setScanIds] = useState<string[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const scans = useQuery({ queryKey: ["diag", scope, "scans", 1, ""], enabled: scope === "tenant",
    queryFn: () => api<ScanPage>(`/diagnostics/${scope}/scans`, { query: { page: 1 } }) });
  const body = () => ({ scope, window_start: new Date(start).toISOString(), window_end: new Date(end).toISOString(), scan_ids: scanIds });
  const doPreview = useMutation({ mutationFn: () => api<Preview>("/diagnostics/bundles/preview", { method: "POST", body: body() }),
    onSuccess: setPreview });
  const create = useMutation({ mutationFn: () => api<Bundle>("/diagnostics/bundles", { method: "POST", body: body() }), onSuccess: onCreated });
  const toggle = (id: string) => { setPreview(null); setScanIds((xs) => xs.includes(id) ? xs.filter((x) => x !== id) : xs.length >= 20 ? xs : [...xs, id]); };
  return (
    <Modal wide title="Generate support bundle" onClose={onClose}
           footer={<>
             <button className="btn" onClick={onClose}>Cancel</button>
             {!preview
               ? <button className="btn primary" disabled={doPreview.isPending} onClick={() => doPreview.mutate()}>Preview contents</button>
               : <button className="btn primary" disabled={create.isPending} onClick={() => create.mutate()}>Generate</button>}
           </>}>
      <div className="stack">
        <ErrorBox error={doPreview.error ?? create.error} />
        <div className="row">
          <Field label="From"><input type="datetime-local" value={start} onChange={(e) => { setStart(e.target.value); setPreview(null); }} /></Field>
          <Field label="To"><input type="datetime-local" value={end} onChange={(e) => { setEnd(e.target.value); setPreview(null); }} /></Field>
          <span className="small subtle">Up to 30 days.</span>
        </div>
        {scope === "tenant" && (
          <div>
            <div className="small" style={{ marginBottom: 6 }}>Include stage output for these scans (optional, up to 20):</div>
            {scans.isLoading ? <Loading /> : !scans.data?.items.length ? <div className="small subtle">No scans in the last 30 days.</div> : (
              <div style={{ maxHeight: 200, overflow: "auto" }}>
                {scans.data.items.map((s) => (
                  <label key={s.id} className="row small" style={{ gap: 6 }}>
                    <input type="checkbox" checked={scanIds.includes(s.id)} onChange={() => toggle(s.id)} />
                    {s.profile} · {fmtDate(s.created_at)} · <StatusBadge value={s.status} />
                  </label>
                ))}
              </div>
            )}
          </div>
        )}
        {preview && (
          <div className="grid" style={{ gridTemplateColumns: "1fr 1fr", gap: 14 }}>
            <div>
              <h3>Included</h3>
              <ul className="small">{preview.included.map((x) => <li key={x}>{x}</li>)}</ul>
              <div className="small subtle">{Object.entries(preview.counts).map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`).join(" · ")}</div>
            </div>
            <div>
              <h3>Never included</h3>
              <ul className="small">{preview.excluded.map((x) => <li key={x}>{x}</li>)}</ul>
              <div className="small subtle">Limits: {preview.limits.max_mb} MB, {preview.limits.max_seconds} s to build; kept {preview.limits.retention_days} days.</div>
            </div>
          </div>
        )}
      </div>
    </Modal>
  );
}

function ReviewBundle({ bundle: b, scope, onClose }: { bundle: Bundle; scope: Scope; onClose: () => void }) {
  const [error, setError] = useState<unknown>(null);
  const c = b.contents;
  return (
    <Modal wide title="Support bundle contents" onClose={onClose}
           footer={<>
             <button className="btn" onClick={onClose}>Close</button>
             <button className="btn primary" onClick={() => download(`/diagnostics/bundles/${b.id}/download`, { scope }, b.filename ?? undefined)
               .then(onClose, setError)}><Download /> Download ({bytes(b.size)})</button>
           </>}>
      <div className="stack">
        <ErrorBox error={error} />
        <div className="small">Review what is inside before you download it. SHA-256 <span className="mono">{b.sha256}</span></div>
        {c && (<>
          <table className="data compact">
            <thead><tr><th>File</th><th>Size</th></tr></thead>
            <tbody>{c.files.map((f) => <tr key={f.name}><td className="mono small">{f.name}</td><td className="small">{bytes(f.bytes)}</td></tr>)}</tbody>
          </table>
          {c.truncated.length > 0 && <div className="small">Shortened to fit the limits: {c.truncated.join(", ")}</div>}
          <div className="small subtle">Never included: {c.omitted.join("; ")}.</div>
        </>)}
      </div>
    </Modal>
  );
}
