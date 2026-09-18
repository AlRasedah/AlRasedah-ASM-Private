import { Link } from "react-router-dom";
import type { AssetEvent } from "@/api/types";
import { EVENT_LABELS, SEV_COLOR, compactDiff, fmtDate } from "@/lib/format";
import { SeverityBadge } from "./ui";

export function Timeline({ events, showAsset, currentAssetId, onAck }: {
  /** currentAssetId: the asset whose page this is — its own events are not linked back to it. */
  events: AssetEvent[]; showAsset?: boolean; currentAssetId?: string; onAck?: (id: string) => void;
}) {
  return (
    <ul className="timeline">
      {events.map((e) => (
        <li key={e.id}>
          <div className="when">{fmtDate(e.occurred_at)}</div>
          <div className="mark"><i style={{ background: SEV_COLOR[e.severity] }} /></div>
          <div>
            <div className="row">
              <SeverityBadge value={e.severity} />
              <span className="badge neutral">{EVENT_LABELS[e.event_type] ?? e.event_type}</span>
              {e.is_baseline && <span className="badge neutral" title="Recorded during the first (baseline) scan">baseline</span>}
              {e.acknowledged && <span className="badge ok">acknowledged</span>}
              {onAck && !e.acknowledged && <button className="btn sm ghost right" onClick={() => onAck(e.id)}>Acknowledge</button>}
            </div>
            <div className="title" style={{ marginTop: 4 }}>
              {e.finding_id ? <Link to={`/findings/${e.finding_id}`}>{e.title}</Link>
                : showAsset && e.asset_id && e.asset_id !== currentAssetId ? <Link to={`/assets/${e.asset_id}`}>{e.title}</Link> : e.title}
            </div>
            {e.summary && <div className="muted small">{e.summary}</div>}
            {(e.previous_state || e.new_state) && <div className="diff">{compactDiff(e.previous_state, e.new_state)}</div>}
          </div>
        </li>
      ))}
    </ul>
  );
}
