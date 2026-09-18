import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, ExternalLink, MessageSquare } from "lucide-react";
import { api } from "@/api/client";
import type { Activity, FindingDetail as TFinding, Member } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { Card, ErrorBox, Field, JsonView, Loading, PageHead, RiskScore, SeverityBadge, StatusBadge } from "@/components/ui";
import { fmtDate, label } from "@/lib/format";

const TRANSITIONS: Record<string, string[]> = {
  new: ["investigating", "remediated", "false_positive", "accepted_risk"],
  investigating: ["remediated", "false_positive", "accepted_risk", "new"],
  reopened: ["investigating", "remediated", "false_positive", "accepted_risk"],
  accepted_risk: ["reopened", "investigating"],
  false_positive: ["reopened", "investigating"],
  remediated: ["reopened"],
};

export default function FindingDetail() {
  const { id } = useParams();
  const { can } = useAuth();
  const qc = useQueryClient();
  const f = useQuery({ queryKey: ["finding", id], queryFn: () => api<TFinding>(`/findings/${id}`) });
  const activity = useQuery({ queryKey: ["finding-activity", id], queryFn: () => api<Activity[]>(`/findings/${id}/activity`) });
  const users = useQuery({ queryKey: ["users"], queryFn: () => api<Member[]>("/users"), enabled: can("users:read") });
  const [comment, setComment] = useState("");
  const [status, setStatus] = useState("");
  const [until, setUntil] = useState("");

  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["finding", id] });
    qc.invalidateQueries({ queryKey: ["finding-activity", id] });
    qc.invalidateQueries({ queryKey: ["findings"] });
  };
  const update = useMutation({
    mutationFn: (body: Record<string, unknown>) => api(`/findings/${id}`, { method: "PATCH", body }),
    onSuccess: () => { setComment(""); setStatus(""); refresh(); },
  });
  const addComment = useMutation({
    mutationFn: () => api(`/findings/${id}/comments`, { method: "POST", body: { comment } }),
    onSuccess: () => { setComment(""); refresh(); },
  });

  if (f.isLoading) return <Loading />;
  if (f.error) return <ErrorBox error={f.error} />;
  const x = f.data!;
  const options = TRANSITIONS[x.status] ?? [];

  return (
    <>
      <div className="small" style={{ marginBottom: 8 }}><Link to="/findings"><ArrowLeft size={13} /> Findings</Link></div>
      <PageHead title={x.title}
        sub={<div className="row">
          <SeverityBadge value={x.severity} /><StatusBadge value={x.status} />
          <span className="badge neutral">{label(x.category)}</span>
          {x.kev && <span className="badge bad">Known exploited (CISA KEV)</span>}
          <span className="muted small">{x.source_label} · seen {x.occurrence_count}× · first {fmtDate(x.first_seen)}</span>
        </div>}
        actions={<div className="row"><span className="muted small">Risk</span><RiskScore score={x.risk_score} /></div>} />
      <div className="grid cols-3">
        <div className="stack span-2">
          <Card title="Details">
            <dl className="kv">
              <dt>Asset</dt><dd>{x.asset ? <Link to={`/assets/${x.asset.id}`}>{x.asset.value}</Link> : "—"}</dd>
              {x.location && (<><dt>Location</dt><dd className="mono small">{x.location}</dd></>)}
              {x.cve.length > 0 && (<><dt>CVE</dt><dd>{x.cve.map((c) => (
                <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer noopener" style={{ marginInlineEnd: 8 }}>
                  {c} <ExternalLink size={11} /></a>))}</dd></>)}
              {x.cvss_score !== null && (<><dt>CVSS</dt><dd>{x.cvss_score} <span className="muted small mono">{x.cvss_vector}</span></dd></>)}
              {x.epss_score !== null && (<><dt>EPSS</dt><dd>{(x.epss_score * 100).toFixed(1)}% probability of exploitation (30 days)
                {x.epss_percentile ? ` · ${(x.epss_percentile * 100).toFixed(0)}th percentile` : ""}</dd></>)}
              {x.kev_due_date && (<><dt>KEV due date</dt><dd>{fmtDate(x.kev_due_date)}</dd></>)}
              {x.cwe.length > 0 && (<><dt>CWE</dt><dd>{x.cwe.join(", ")}</dd></>)}
              <dt>Rule</dt><dd className="mono small">{x.source_finding_id}</dd>
              <dt>Last seen</dt><dd>{fmtDate(x.last_seen)}</dd>
              {x.resolved_at && (<><dt>Resolved</dt><dd>{fmtDate(x.resolved_at)}</dd></>)}
              {x.accepted_until && (<><dt>Risk accepted until</dt><dd>{fmtDate(x.accepted_until)}</dd></>)}
            </dl>
            {x.description && (<><hr /><p style={{ whiteSpace: "pre-wrap", margin: 0 }}>{x.description}</p></>)}
          </Card>
          {x.remediation && <Card title="Remediation"><p style={{ whiteSpace: "pre-wrap", margin: 0 }}>{x.remediation}</p></Card>}
          <Card title="Evidence"><JsonView value={x.evidence} /></Card>
          {x.references.length > 0 && (
            <Card title="References">
              <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                {x.references.map((r) => <li key={r}><a href={r} target="_blank" rel="noreferrer noopener">{r}</a></li>)}
              </ul>
            </Card>
          )}
        </div>
        <div className="stack">
          <Card title="Why this risk score" hint={`${x.risk_score}/100`}>
            <ul className="list" style={{ margin: "-6px -16px" }}>
              {[...x.risk_factors].sort((a, b) => Math.abs(b.points) - Math.abs(a.points)).map((r, i) => (
                <li key={i}><span className="grow">{r.label}</span><span className="mono small">{r.points > 0 ? "+" : ""}{r.points}</span></li>
              ))}
            </ul>
          </Card>
          {can("findings:write") && (
            <Card title="Workflow">
              <div className="form">
                <ErrorBox error={update.error ?? addComment.error} />
                <Field label="Assignee">
                  <select value={x.assigned_to ?? ""} onChange={(e) => update.mutate({ assigned_to: e.target.value || null })}>
                    <option value="">Unassigned</option>
                    {users.data?.filter((u) => u.is_active).map((u) => <option key={u.user_id} value={u.user_id}>{u.full_name || u.email}</option>)}
                  </select>
                </Field>
                <Field label="Change status">
                  <select value={status} onChange={(e) => setStatus(e.target.value)}>
                    <option value="">(keep {label(x.status)})</option>
                    {options.filter((o) => o !== "accepted_risk" || can("findings:accept_risk")).map((o) => (
                      <option key={o} value={o}>{label(o)}</option>
                    ))}
                  </select>
                </Field>
                {status === "accepted_risk" && (
                  <Field label="Accept until (optional)"><input type="date" value={until} onChange={(e) => setUntil(e.target.value)} /></Field>
                )}
                <Field label={status === "accepted_risk" ? "Justification (required)" : "Comment"}>
                  <textarea value={comment} onChange={(e) => setComment(e.target.value)} style={{ fontFamily: "var(--font-sans)" }} />
                </Field>
                <div className="row">
                  {status && (
                    <button className="btn primary" disabled={update.isPending} onClick={() => update.mutate({
                      status, comment: comment || undefined, accepted_until: until ? `${until}T23:59:59Z` : undefined })}>
                      Update status
                    </button>
                  )}
                  {!status && (
                    <button className="btn" disabled={!comment || addComment.isPending} onClick={() => addComment.mutate()}>
                      <MessageSquare /> Add comment
                    </button>
                  )}
                </div>
              </div>
            </Card>
          )}
          <Card title="Activity" flush>
            <ul className="list">
              {activity.data?.map((a) => (
                <li key={a.id} style={{ alignItems: "flex-start" }}>
                  <div className="grow">
                    <div className="small"><strong>{label(a.activity_type)}</strong>
                      {a.summary ? <span className="muted"> → {a.summary}</span>
                        : a.new && a.activity_type !== "comment" && <span className="muted"> → {Object.values(a.new).map((v) => label(String(v))).join(", ")}</span>}</div>
                    {a.comment && <div style={{ whiteSpace: "pre-wrap" }}>{a.comment}</div>}
                    <div className="cell-sub">{a.user_email ?? "Exteriq ASM"} · {fmtDate(a.created_at)}</div>
                  </div>
                </li>
              ))}
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}
