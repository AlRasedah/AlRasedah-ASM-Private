import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCheck, FilterX } from "lucide-react";
import { api } from "@/api/client";
import type { AssetEvent, Page } from "@/api/types";
import { useAuth } from "@/auth/AuthContext";
import { useOrg } from "@/auth/OrgContext";
import { Timeline } from "@/components/Timeline";
import { Card, Empty, ErrorBox, Loading, PageHead, Pagination } from "@/components/ui";
import { EVENT_LABELS, SEVERITIES } from "@/lib/format";
import { useFilters } from "@/lib/useFilters";

type Key = "event_type" | "min_severity" | "acknowledged" | "include_baseline" | "since" | "page";

export default function Changes() {
  const f = useFilters<Key>(["event_type"]);
  const { orgId } = useOrg();
  const { can } = useAuth();
  const qc = useQueryClient();
  const query = { ...f.query, organization_id: orgId, page: f.page, page_size: 50 };
  const q = useQuery({ queryKey: ["events", query], queryFn: () => api<Page<AssetEvent>>("/events", { query }), refetchInterval: 30_000 });
  const ack = useMutation({
    mutationFn: (ids: string[]) => api("/events/acknowledge", { method: "POST", body: { event_ids: ids } }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["events"] }),
  });
  const unacked = q.data?.items.filter((e) => !e.acknowledged).map((e) => e.id) ?? [];

  return (
    <>
      <PageHead title="Attack surface changes"
                sub="Chronological, security-relevant changes detected by comparing each scan with previous observations."
                actions={can("events:ack") && unacked.length > 0 && (
                  <button className="btn" onClick={() => ack.mutate(unacked)}><CheckCheck /> Acknowledge {unacked.length} on page</button>
                )} />
      <Card flush>
        <div className="filters">
          <select value={f.getAll("event_type")[0] ?? ""} onChange={(e) => f.set("event_type", e.target.value ? [e.target.value] : undefined)}>
            <option value="">All change types</option>
            {Object.entries(EVENT_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          <select value={f.get("min_severity") ?? ""} onChange={(e) => f.set("min_severity", e.target.value || undefined)}>
            <option value="">Any severity</option>
            {[...SEVERITIES].reverse().map((s) => <option key={s} value={s}>{s} and above</option>)}
          </select>
          <select value={f.get("acknowledged") ?? ""} onChange={(e) => f.set("acknowledged", e.target.value || undefined)}>
            <option value="">Acknowledged & open</option>
            <option value="false">Not acknowledged</option>
            <option value="true">Acknowledged</option>
          </select>
          <label className="small muted row">Since
            <input type="date" defaultValue={f.get("since")?.slice(0, 10)}
                   onChange={(e) => f.set("since", e.target.value ? `${e.target.value}T00:00:00Z` : undefined)} />
          </label>
          <label className="check small"><input type="checkbox" checked={f.get("include_baseline") === "true"}
                 onChange={(e) => f.set("include_baseline", e.target.checked ? "true" : undefined)} /> Include baseline</label>
          <button className="btn ghost sm" onClick={f.clear}><FilterX /> Reset</button>
        </div>
        <ErrorBox error={ack.error} />
        {q.isLoading ? <Loading /> : q.error ? <div className="card-body"><ErrorBox error={q.error} /></div> :
          !q.data!.items.length ? <Empty>No changes match. The first scan of an organization is recorded as a baseline and hidden by default.</Empty> : (
            <>
              <Timeline events={q.data!.items} showAsset onAck={can("events:ack") ? (id) => ack.mutate([id]) : undefined} />
              <Pagination page={f.page} pageSize={50} total={q.data!.total} onPage={f.setPage} />
            </>
          )}
      </Card>
    </>
  );
}
