import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Camera, ExternalLink, Trash2, X } from "lucide-react";
import { api, openBlob } from "@/api/client";
import type { ScreenshotCapture, ScreenshotStatus } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { Card, Confirm, Empty, ErrorBox, Loading, StatusBadge } from "@/components/ui";
import { bytes, fmtDate, timeAgo } from "@/lib/format";

interface Listing {
  status: ScreenshotStatus;
  latest: ScreenshotCapture | null;
  captures: ScreenshotCapture[];
}

const STATE_TEXT: Record<string, string> = {
  queued: "Waiting for a free capture slot…",
  running: "Capturing the page…",
};

/** The image arrives through the authenticated API as a blob; there is no public image URL. */
function Image({ assetId, capture }: { assetId: string; capture: ScreenshotCapture }) {
  const [src, setSrc] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    let url: string | null = null;
    let live = true;
    api<Blob>(`/assets/${assetId}/screenshots/${capture.id}/image`, { raw: true })
      .then((b) => { if (live) { url = URL.createObjectURL(b); setSrc(url); } })
      .catch((e) => live && setError(e));
    return () => { live = false; if (url) URL.revokeObjectURL(url); };
  }, [assetId, capture.id]);
  if (error) return <ErrorBox error={error} />;
  if (!src) return <Loading text="Loading image…" />;
  return (
    <img src={src} alt={`Screenshot of ${capture.final_url ?? "the page"} taken ${fmtDate(capture.captured_at)}`}
         style={{ width: "100%", height: "auto", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)" }} />
  );
}

export default function Screenshots({ assetId }: { assetId: string }) {
  const { can } = useAuth();
  const qc = useQueryClient();
  const [removing, setRemoving] = useState<ScreenshotCapture | null>(null);
  const q = useQuery({
    queryKey: ["screenshots", assetId],
    queryFn: () => api<Listing>(`/assets/${assetId}/screenshots`),
    refetchInterval: (query) => (query.state.data?.captures.some((c) => c.status === "queued" || c.status === "running") ? 3000 : false),
  });
  const refresh = () => qc.invalidateQueries({ queryKey: ["screenshots", assetId] });
  const capture = useMutation({ mutationFn: () => api(`/assets/${assetId}/screenshots`, { method: "POST" }), onSuccess: refresh });
  const cancel = useMutation({ mutationFn: (id: string) => api(`/assets/${assetId}/screenshots/${id}/cancel`, { method: "POST" }), onSuccess: refresh });
  const remove = useMutation({ mutationFn: (id: string) => api(`/assets/${assetId}/screenshots/${id}`, { method: "DELETE" }), onSuccess: refresh });

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorBox error={q.error} />;
  const { status, latest, captures } = q.data!;
  const active = captures.find((c) => c.status === "queued" || c.status === "running");
  const usable = status.available && status.enabled;
  const last = captures[0];

  return (
    <div className="grid cols-3">
      <Card title="Latest screenshot" className="span-2" hint={latest ? `captured ${timeAgo(latest.captured_at)}` : undefined}
            right={can("scans:run") && usable && (
              <button className="btn primary sm" disabled={!!active || capture.isPending} onClick={() => capture.mutate()}
                      title="Visits this page once from your scanner and records what it shows">
                <Camera /> {active ? "Capture in progress" : "Capture screenshot"}
              </button>
            )}>
        <ErrorBox error={capture.error ?? cancel.error ?? remove.error} />
        {!usable && <div className="info-box" style={{ marginBottom: 10 }}>{status.reason}</div>}
        {active && <div className="info-box" style={{ marginBottom: 10 }}>{STATE_TEXT[active.status]}</div>}
        {last && (last.status === "failed" || last.status === "blocked") && (
          <div className="error-box" style={{ marginBottom: 10 }}>
            The last capture {last.status === "blocked" ? "was not allowed" : "did not succeed"} ({timeAgo(last.finished_at)}): {last.error}
            {latest ? " The previous screenshot is still shown." : ""}
          </div>
        )}
        {latest ? (
          <>
            <Image assetId={assetId} capture={latest} />
            <dl className="kv" style={{ marginTop: 10 }}>
              <dt>Captured</dt><dd>{fmtDate(latest.captured_at)}</dd>
              {latest.page_title && (<><dt>Page title</dt><dd>{latest.page_title}</dd></>)}
              <dt>Loaded</dt><dd className="mono small" style={{ wordBreak: "break-all" }}>{latest.final_url ?? "—"}{latest.http_status ? ` (HTTP ${latest.http_status})` : ""}</dd>
              <dt>Image</dt><dd className="small">{latest.width}×{latest.height} · {bytes(latest.size)}</dd>
            </dl>
            <p className="small muted">A screenshot shows what the page looked like to an anonymous visitor. It is not evidence of a vulnerability.</p>
          </>
        ) : !active && <Empty>{usable ? "No screenshot yet." : "No screenshots."}</Empty>}
      </Card>
      <Card title="History" flush hint={`last ${captures.length}`}>
        {!captures.length ? <Empty>Nothing captured yet.</Empty> : (
          <ul className="list">
            {captures.map((c) => (
              <li key={c.id}>
                <div className="grow">
                  <StatusBadge value={c.status} /> <span className="small muted" title={fmtDate(c.created_at)}>{timeAgo(c.created_at)}{c.trigger === "scheduled" ? " · weekly" : ""}</span>
                  {c.error && <div className="cell-sub">{c.error}</div>}
                </div>
                {c.has_image && <button className="btn ghost sm" title="Open full size" aria-label="Open full size"
                  onClick={() => openBlob(`/assets/${assetId}/screenshots/${c.id}/image`)}><ExternalLink /></button>}
                {can("scans:run") && (c.status === "queued" || c.status === "running") &&
                  <button className="btn ghost sm" aria-label="Cancel capture" onClick={() => cancel.mutate(c.id)}><X /></button>}
                {can("assets:write") && c.status !== "queued" && c.status !== "running" &&
                  <button className="btn ghost sm" aria-label="Delete screenshot" onClick={() => setRemoving(c)}><Trash2 /></button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
      {removing && <Confirm danger onClose={() => setRemoving(null)} onConfirm={() => remove.mutate(removing.id)}
                            text="Delete this screenshot record and its image? This cannot be undone." />}
    </div>
  );
}
