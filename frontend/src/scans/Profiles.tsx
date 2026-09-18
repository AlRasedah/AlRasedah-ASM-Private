import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CalendarClock, Copy, Plus, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { ScanProfile, Schedule } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Card, Confirm, Empty, ErrorBox, Field, Loading, Modal, PageHead, StatusBadge } from "@/components/ui";
import { fmtDate } from "@/lib/format";

export default function Profiles() {
  const { can } = useAuth();
  const qc = useQueryClient();
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api<ScanProfile[]>("/scan-profiles") });
  const [editing, setEditing] = useState<{ base?: ScanProfile; existing?: ScanProfile } | null>(null);
  const [scheduleFor, setScheduleFor] = useState<ScanProfile | null>(null);
  const [deleting, setDeleting] = useState<ScanProfile | null>(null);
  const del = useMutation({
    mutationFn: (id: string) => api(`/scan-profiles/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["profiles"] }),
  });

  return (
    <>
      <PageHead title="Scan profiles & schedules"
                sub="Reusable pipelines. Built-in profiles cover passive discovery, standard monitoring and deep assessment." />
      {profiles.isLoading ? <Loading /> : (
        <div className="grid cols-2">
          {profiles.data?.map((p) => (
            <Card key={p.id} title={p.name}
                  hint={<>{p.is_builtin ? "built-in" : "custom"}{p.is_active_scanning ? " · active" : " · passive"}</>}
                  right={<div className="btn-group">
                    {can("schedules:write") && <button className="btn sm" onClick={() => setScheduleFor(p)}><CalendarClock /> Schedule</button>}
                    {can("profiles:write") && <button className="btn sm" onClick={() => setEditing({ base: p })}><Copy /> Duplicate</button>}
                    {can("profiles:write") && !p.is_builtin && <button className="btn sm" onClick={() => setEditing({ existing: p })}>Edit</button>}
                    {can("profiles:write") && !p.is_builtin && <button className="btn sm danger" onClick={() => setDeleting(p)}><Trash2 /></button>}
                  </div>}>
              <p className="muted" style={{ marginTop: 0 }}>{p.description}</p>
              <ol style={{ margin: 0, paddingInlineStart: 20 }}>
                {p.stages.map((s, i) => (
                  <li key={i} style={{ opacity: s.enabled ? 1 : 0.5 }}>
                    {s.label} {s.active && <span className="badge warn">active</span>} {s.optional && <span className="badge neutral">optional</span>}
                    <span className="muted small"> · engine: {s.engine}</span>
                  </li>
                ))}
              </ol>
            </Card>
          ))}
        </div>
      )}
      <Schedules />
      {editing && <ProfileEditor base={editing.base} existing={editing.existing} onClose={() => setEditing(null)} />}
      {scheduleFor && <ScheduleEditor profile={scheduleFor} onClose={() => setScheduleFor(null)} />}
      {deleting && <Confirm danger text={`Delete profile "${deleting.name}"?`} onClose={() => setDeleting(null)} onConfirm={() => del.mutate(deleting.id)} />}
    </>
  );
}

function ProfileEditor({ base, existing, onClose }: { base?: ScanProfile; existing?: ScanProfile; onClose: () => void }) {
  const qc = useQueryClient();
  const src = existing ?? base!;
  const [name, setName] = useState(existing ? existing.name : `${src.name} (copy)`);
  const [description, setDescription] = useState(src.description ?? "");
  const [retain, setRetain] = useState(src.retain_raw_output);
  const [stages, setStages] = useState(JSON.stringify(src.stages.map(({ stage, engine, config, enabled, optional }) =>
    ({ stage, engine, config, enabled, optional })), null, 2));
  const m = useMutation({
    mutationFn: () => {
      const body = { name, description, retain_raw_output: retain, stages: JSON.parse(stages) };
      return existing ? api(`/scan-profiles/${existing.id}`, { method: "PATCH", body }) : api("/scan-profiles", { method: "POST", body });
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["profiles"] }); onClose(); },
  });
  return (
    <Modal wide title={existing ? `Edit ${existing.name}` : "New scan profile"} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={() => m.mutate()}>Save</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <div className="form-row">
          <Field label="Name"><input value={name} onChange={(e) => setName(e.target.value)} /></Field>
          <label className="check" style={{ alignSelf: "end" }}><input type="checkbox" checked={retain} onChange={(e) => setRetain(e.target.checked)} />
            Retain raw sensor output (troubleshooting)</label>
        </div>
        <Field label="Description"><input value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        <Field label="Stages (validated server-side; unknown options are rejected)">
          <textarea style={{ minHeight: 320 }} value={stages} onChange={(e) => setStages(e.target.value)} />
        </Field>
        <div className="small muted">Stages always run in pipeline order: discovery → OSINT → DNS → network ownership → ports → web → detection.
          Engine options are strictly validated; free-form command-line arguments are not supported by design.</div>
      </div>
    </Modal>
  );
}

function ScheduleEditor({ profile, onClose }: { profile: ScanProfile; onClose: () => void }) {
  const { orgs, orgId } = useOrg();
  const qc = useQueryClient();
  const [org, setOrg] = useState(orgId ?? orgs[0]?.id ?? "");
  const [cron, setCron] = useState("0 2 * * *");
  const [tz, setTz] = useState("Asia/Riyadh");
  const m = useMutation({
    mutationFn: () => api("/schedules", { method: "POST", body: { organization_id: org, profile_id: profile.id,
      name: `${profile.name} (${cron})`, cron, timezone: tz } }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["schedules"] }); onClose(); },
  });
  return (
    <Modal title={`Schedule: ${profile.name}`} onClose={onClose} footer={
      <><button className="btn" onClick={onClose}>Cancel</button><button className="btn primary" onClick={() => m.mutate()}>Create schedule</button></>}>
      <div className="form">
        <ErrorBox error={m.error} />
        <Field label="Organization"><select value={org} onChange={(e) => setOrg(e.target.value)}>
          {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></Field>
        <div className="form-row">
          <Field label="Cron (minute hour day month weekday)"><input className="mono" value={cron} onChange={(e) => setCron(e.target.value)} /></Field>
          <Field label="Timezone"><input value={tz} onChange={(e) => setTz(e.target.value)} /></Field>
        </div>
        <div className="small muted">Examples: <code>0 2 * * *</code> daily at 02:00 · <code>0 */6 * * *</code> every 6 hours · <code>0 3 * * 0</code> weekly.</div>
      </div>
    </Modal>
  );
}

function Schedules() {
  const { can } = useAuth();
  const { orgName } = useOrg();
  const qc = useQueryClient();
  const schedules = useQuery({ queryKey: ["schedules"], queryFn: () => api<Schedule[]>("/schedules") });
  const [deleting, setDeleting] = useState<Schedule | null>(null);
  const toggle = useMutation({
    mutationFn: (s: Schedule) => api(`/schedules/${s.id}`, { method: "PATCH", body: { enabled: !s.enabled } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules"] }),
  });
  const del = useMutation({
    mutationFn: (id: string) => api(`/schedules/${id}`, { method: "DELETE" }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["schedules"] }),
  });
  return (
    <div style={{ marginTop: 14 }}>
      <Card title="Schedules" flush right={<span className="muted small"><Plus size={12} /> use "Schedule" on a profile</span>}>
        {!schedules.data?.length ? <Empty>No recurring scans. Continuous monitoring needs at least one schedule.</Empty> : (
          <table className="data">
            <thead><tr><th>Name</th><th>Organization</th><th>Cron</th><th>Next run</th><th>Last run</th><th>State</th><th /></tr></thead>
            <tbody>{schedules.data.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td><td>{orgName(s.organization_id)}</td>
                <td className="mono small">{s.cron} <span className="muted">({s.timezone})</span></td>
                <td className="small">{fmtDate(s.next_run_at)}</td><td className="small">{fmtDate(s.last_run_at)}</td>
                <td><StatusBadge value={s.enabled ? "active" : "inactive"} /></td>
                <td>{can("schedules:write") && <div className="btn-group">
                  <button className="btn sm" onClick={() => toggle.mutate(s)}>{s.enabled ? "Pause" : "Resume"}</button>
                  <button className="btn sm danger" onClick={() => setDeleting(s)} aria-label="Delete schedule" title="Delete"><Trash2 /></button></div>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Card>
      {deleting && <Confirm danger text={<>Delete schedule <strong>{deleting.name}</strong>? Recurring scans for {orgName(deleting.organization_id)} stop; past scans are kept. To stop it temporarily, use Pause instead.</>}
                            onClose={() => setDeleting(null)} onConfirm={() => del.mutate(deleting.id)} />}
    </div>
  );
}
