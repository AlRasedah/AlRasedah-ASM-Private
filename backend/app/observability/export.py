"""Export committed finding-lifecycle events (``alerts``) and audit records (``audit``).

Both are exported from rows that already exist in the database — nothing is emitted at
the moment of the change, so a change that is rolled back never produces an event.

**Alerts** use ``finding_activities`` as the transactional outbox: every detection,
resolution, reopening, status/assignment/tag change and comment is written in the same
transaction as the finding change. The exporter writes one event per unexported row
(``event_id`` = the activity id) and marks the row exported only *after* stdout accepted
the line. A crash between the two re-exports the row with the same ``event_id``:
delivery is at least once and consumers deduplicate on ``event_id``.

**Audit** rows are append-only (a trigger forbids updating them), so they cannot be
marked. The exporter keeps a cursor (the highest exported ``audit_logs.id``) plus the ids
*below* it that were missing when it passed — a transaction that had taken an id but not
committed yet. Those are re-checked on every run and given up after an hour (a rolled-back
transaction never fills its id). The audit rows themselves and their hash chain are never
modified; ``entry_hash`` is exported so the file can be checked against the database.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from asm_sensors import eventlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.observability import codes

log = logging.getLogger(__name__)
BATCH = 500
GAP_PATIENCE = timedelta(hours=1)


def _now() -> datetime:
    return datetime.now(UTC)


def export_alerts(db: Session, limit: int = BATCH) -> dict[str, int]:
    """System session. One batch; returns counts."""
    from app.models import Finding, FindingActivity

    rows = db.execute(select(FindingActivity, Finding).join(Finding, Finding.id == FindingActivity.finding_id)
                      .where(FindingActivity.exported_at.is_(None))
                      .order_by(FindingActivity.created_at, FindingActivity.id).limit(limit)
                      .with_for_update(of=FindingActivity, skip_locked=True)).all()
    done = failed = 0
    now = _now()
    for act, f in rows:
        fields: dict[str, Any] = {
            "event_id": act.id.hex, "event": f"finding.{act.activity_type}", "stream": "alerts",
            "tenant_id": str(act.tenant_id), "organization_id": str(f.organization_id), "finding_id": str(f.id),
            "asset_id": str(f.asset_id), "scan_id": str(act.scan_id) if act.scan_id else None,
            "user_id": str(act.user_id) if act.user_id else None,
            "severity": getattr(f.severity, "value", f.severity), "status": getattr(f.status, "value", f.status),
            "activity": act.activity_type, "title": f.title[:300],
        }
        if act.activity_type != "comment":  # a comment's text is never exported
            fields["previous"], fields["new"] = act.previous, act.new
        if eventlog.write_sync("exteriq.alerts", logging.INFO, f"{act.activity_type}: {f.title[:200]}", **fields):
            act.exported_at = now
            done += 1
        else:
            failed += 1
            break  # stdout refused: stop, keep the rest for the next run
    db.commit()
    if failed:
        log.warning("alert export stopped: the log writer refused an event", extra={
            "event": "export.alerts.failed", "error_code": codes.EXPORT_FAILED, "count": len(rows) - done})
    return {"exported": done, "pending": max(0, len(rows) - done)}


def export_audit(db: Session, limit: int = BATCH) -> dict[str, int]:
    """System session. One batch of audit rows past the cursor, plus late rows below it."""
    from app.models import AuditLog, EventExportState

    state = db.get(EventExportState, "audit", with_for_update=True)
    if state is None:
        state = EventExportState(name="audit", cursor=0, gaps={})
        db.add(state)
        db.flush()
    gaps: dict[str, str] = dict(state.gaps or {})
    now = _now()
    late = list(db.execute(select(AuditLog).where(AuditLog.id.in_([int(g) for g in gaps])).order_by(AuditLog.id))
                .scalars()) if gaps else []
    fresh = list(db.execute(select(AuditLog).where(AuditLog.id > state.cursor).order_by(AuditLog.id).limit(limit))
                 .scalars())
    done = failed = 0
    for row in late + fresh:
        if not eventlog.write_sync("exteriq.audit", logging.INFO, f"audit {row.action}", **_audit_fields(row)):
            failed += 1
            break
        done += 1
        gaps.pop(str(row.id), None)
    else:
        if fresh:
            expected = state.cursor + 1
            for row in fresh:
                for missing in range(expected, row.id):
                    gaps.setdefault(str(missing), now.isoformat())
                expected = row.id + 1
            state.cursor = fresh[-1].id
    if failed:
        # Nothing moved past a failure: the batch is exported again next time (same event ids).
        db.rollback()
        log.warning("audit export stopped: the log writer refused an event", extra={
            "event": "export.audit.failed", "error_code": codes.EXPORT_FAILED})
        return {"exported": done, "pending": len(late) + len(fresh) - done}
    cutoff = now - GAP_PATIENCE
    state.gaps = {k: v for k, v in gaps.items() if datetime.fromisoformat(v) > cutoff}
    state.updated_at = now
    db.commit()
    return {"exported": done, "gaps": len(state.gaps)}


def _audit_fields(row: Any) -> dict[str, Any]:
    return {
        "event_id": f"audit-{row.id}", "event": f"audit.{row.action}", "stream": "audit",
        "tenant_id": str(row.tenant_id) if row.tenant_id else None, "user_id": str(row.user_id) if row.user_id else None,
        "actor": row.actor, "action": row.action, "object_type": row.object_type, "object_id": row.object_id,
        "previous": row.previous, "new": row.new, "success": row.success, "chain_seq": row.chain_seq,
        "entry_hash": row.hash, "request_id": row.request_id,
        "data": {"ip": row.ip_address, "recorded_at": row.created_at.isoformat() if row.created_at else None},
    }


def run() -> dict[str, Any]:
    """Beat task body: drain both exports in bounded batches."""
    from app.db.session import system_session

    out: dict[str, Any] = {}
    with system_session() as db:
        out["alerts"] = export_alerts(db)
    with system_session() as db:
        out["audit"] = export_audit(db)
    return out
