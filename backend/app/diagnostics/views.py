"""What the Diagnostics page shows. Two strictly separate views:

* **tenant** — computed in the caller's tenant session from records the tenant owns
  (scans, stages, deliveries, captures, checks): RLS decides what exists. No queues, no
  host data, no other tenant's activity, no engine names (stage *capabilities* only).
* **platform** — platform administrators only, in a system session: service and scanner
  health, queues, host resources, recent operational errors, scan timelines across tenants
  (identified by tenant id and name).

Missing telemetry is reported as unavailable, never as zero or healthy.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (
    NotificationDelivery,
    OpsEvent,
    Scan,
    ScanStage,
    ScreenshotCapture,
    Tenant,
    ThreatCheckRun,
)
from app.models.enums import StageStatus
from app.observability import health
from app.scans import engines
from app.scans.profiles import STAGE_LABELS

PAGE = 50
MAX_PAGE = 20
EVENT_WINDOW = timedelta(days=30)
OPS_WINDOW = timedelta(days=14)


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def stage_view(st: ScanStage) -> dict[str, Any]:
    timing = (st.stats or {}).get("timing") or {}
    return {
        "id": str(st.id), "position": st.position, "stage_type": st.stage_type.value,
        "label": engines.label_for(st.engine, STAGE_LABELS.get(st.stage_type, "")), "status": st.status.value,
        "coverage": {"completed": "complete", "partial": "partial"}.get(st.status.value, "none"),
        "target_count": st.target_count, "rejected_count": st.rejected_count,
        "observation_count": st.observation_count, "error": st.error,
        "started_at": _iso(st.started_at), "dispatched_at": _iso(st.dispatched_at), "finished_at": _iso(st.finished_at),
        # Recorded only by stages finished since this release; older stages show "unavailable".
        "timing": timing or None,
        "timed_out": bool(timing.get("timed_out")) if timing else None,
        "retries": timing.get("retries") if timing else None,
    }


def scan_view(scan: Scan, tenant_name: str | None = None) -> dict[str, Any]:
    out = {"id": str(scan.id), "organization_id": str(scan.organization_id), "profile": scan.profile_name,
           "status": scan.status.value, "trigger": scan.trigger.value, "created_at": _iso(scan.created_at),
           "started_at": _iso(scan.started_at), "finished_at": _iso(scan.finished_at),
           "stages": [stage_view(s) for s in sorted(scan.stages, key=lambda s: s.position)]}
    waits = [s["timing"]["queue_wait_ms"] for s in out["stages"] if s["timing"] and
             s["timing"].get("queue_wait_ms") is not None]
    execs = [s["timing"]["execution_ms"] for s in out["stages"] if s["timing"] and
             s["timing"].get("execution_ms") is not None]
    out["summary"] = {"queue_wait_ms": sum(waits) if waits else None, "execution_ms": sum(execs) if execs else None,
                      "partial_stages": sum(s["status"] == "partial" for s in out["stages"]),
                      "failed_stages": sum(s["status"] == "failed" for s in out["stages"]),
                      "timeouts": sum(bool(s["timed_out"]) for s in out["stages"])}
    if tenant_name is not None:
        out["tenant_id"], out["tenant_name"] = str(scan.tenant_id), tenant_name
    return out


def _page(page: int) -> int:
    return max(1, min(int(page or 1), MAX_PAGE))


def scans(db: Session, page: int = 1, status: str | None = None, tenant_id: uuid.UUID | None = None,
          platform: bool = False) -> dict[str, Any]:
    page = _page(page)
    stmt = select(Scan).where(Scan.created_at >= _now() - EVENT_WINDOW)
    if status:
        stmt = stmt.where(Scan.status == status)
    if tenant_id:
        stmt = stmt.where(Scan.tenant_id == tenant_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = list(db.execute(stmt.order_by(Scan.created_at.desc()).offset((page - 1) * PAGE).limit(PAGE)).scalars())
    names = ({t.id: t.name for t in db.execute(select(Tenant).where(Tenant.id.in_({r.tenant_id for r in rows})))
              .scalars()} if platform and rows else {})
    return {"items": [scan_view(r, names.get(r.tenant_id, "?") if platform else None) for r in rows],
            "total": total, "page": page, "page_size": PAGE}


# ------------------------------------------------------------------ tenant
def tenant_overview(db: Session, tenant: Tenant) -> dict[str, Any]:
    from app.core.config import get_settings

    since = _now() - timedelta(days=7)
    by_status = dict(db.execute(select(Scan.status, func.count()).where(Scan.created_at >= since)
                                .group_by(Scan.status)).all())
    stages = list(db.execute(select(ScanStage).join(Scan, Scan.id == ScanStage.scan_id)
                             .where(Scan.created_at >= since, ScanStage.finished_at.is_not(None))).scalars())
    timed = [(s.stats or {}).get("timing") for s in stages if (s.stats or {}).get("timing")]
    waits = sorted(t["queue_wait_ms"] for t in timed if t.get("queue_wait_ms") is not None)
    execs = sorted(t["execution_ms"] for t in timed if t.get("execution_ms") is not None)

    def p50(xs: list[int]) -> Any:
        return xs[len(xs) // 2] if xs else health.unavailable("no stage timing recorded in the last 7 days")

    pool = tenant.worker_pool or "default"
    # Under per-tenant isolation a pool never serves two tenants (the platform refuses to
    # dispatch otherwise). Whether a shared-mode pool has other tenants is not this
    # tenant's business, and a tenant session could not see them anyway (RLS).
    shared = get_settings().scanner_isolation == "shared"
    failed_deliveries = db.scalar(select(func.count()).select_from(NotificationDelivery).where(
        NotificationDelivery.created_at >= since, NotificationDelivery.status == "failed")) or 0
    return {
        "window_days": 7,
        "scans": {k.value if hasattr(k, "value") else str(k): v for k, v in by_status.items()},
        "stages": {"finished": len(stages), "partial": sum(s.status == StageStatus.PARTIAL for s in stages),
                   "failed": sum(s.status == StageStatus.FAILED for s in stages),
                   "timeouts": sum(bool(t.get("timed_out")) for t in timed)},
        "queue_wait_ms_p50": p50(waits), "execution_ms_p50": p50(execs),
        "notification_failures": failed_deliveries,
        **health.tenant_view(pool, shared),
    }


def tenant_events(db: Session, page: int = 1) -> dict[str, Any]:
    """Things that went wrong for this tenant, newest first (last 30 days), from tenant-owned rows."""
    page = _page(page)
    since = _now() - EVENT_WINDOW
    want = page * PAGE
    items: list[dict[str, Any]] = []
    for st, scan in db.execute(select(ScanStage, Scan).join(Scan, Scan.id == ScanStage.scan_id).where(
            ScanStage.finished_at >= since, ScanStage.status.in_(["failed", "partial", "skipped"]),
            ScanStage.error.is_not(None)).order_by(ScanStage.finished_at.desc()).limit(want)).all():
        items.append({"ts": _iso(st.finished_at), "kind": "scan_stage", "level": "error" if st.status.value == "failed"
                      else "warning", "title": f"{engines.label_for(st.engine, STAGE_LABELS.get(st.stage_type, ''))}: "
                      f"{st.status.value}", "detail": st.error, "scan_id": str(scan.id)})
    for d in db.execute(select(NotificationDelivery).where(NotificationDelivery.created_at >= since,
                                                           NotificationDelivery.status == "failed")
                        .order_by(NotificationDelivery.created_at.desc()).limit(want)).scalars():
        items.append({"ts": _iso(d.created_at), "kind": "notification", "level": "warning",
                      "title": f"Notification delivery failed after {d.attempts} attempt(s)",
                      "detail": (d.last_error or "")[:500], "integration_id": str(d.integration_id)
                      if d.integration_id else None})
    for c in db.execute(select(ScreenshotCapture).where(ScreenshotCapture.created_at >= since,
                                                        ScreenshotCapture.status.in_(["failed", "blocked"]))
                        .order_by(ScreenshotCapture.created_at.desc()).limit(want)).scalars():
        items.append({"ts": _iso(c.finished_at or c.created_at), "kind": "screenshot", "level": "warning",
                      "title": f"Website screenshot {c.status.value}", "detail": c.error, "asset_id": str(c.asset_id)})
    for r in db.execute(select(ThreatCheckRun).where(ThreatCheckRun.created_at >= since,
                                                     ThreatCheckRun.status.in_(["inconclusive", "cancelled"]))
                        .order_by(ThreatCheckRun.created_at.desc()).limit(want)).scalars():
        items.append({"ts": _iso(r.finished_at or r.created_at), "kind": "threat_check", "level": "warning",
                      "title": f"Threat Center check {r.status.value}", "detail": (r.summary or {}).get("reason"),
                      "scan_id": str(r.scan_id) if r.scan_id else None})
    items.sort(key=lambda i: i["ts"] or "", reverse=True)
    return {"items": items[(page - 1) * PAGE: page * PAGE], "page": page, "page_size": PAGE,
            "has_more": len(items) > page * PAGE}


# ---------------------------------------------------------------- platform
def platform_events(db: Session, page: int = 1, level: str | None = None, service: str | None = None,
                    error_code: str | None = None, tenant_id: uuid.UUID | None = None, since: datetime | None = None,
                    until: datetime | None = None) -> dict[str, Any]:
    page = _page(page)
    lower = max(since or _now() - OPS_WINDOW, _now() - OPS_WINDOW)
    stmt = select(OpsEvent).where(OpsEvent.ts >= lower)
    if until:
        stmt = stmt.where(OpsEvent.ts <= until)
    if level:
        stmt = stmt.where(OpsEvent.level == level.upper())
    if service:
        stmt = stmt.where(OpsEvent.service == service)
    if error_code:
        stmt = stmt.where(OpsEvent.error_code == error_code)
    if tenant_id:
        stmt = stmt.where(OpsEvent.tenant_id == tenant_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(stmt.order_by(OpsEvent.ts.desc()).offset((page - 1) * PAGE).limit(PAGE)).scalars()
    return {"items": [{"id": r.id, "event_id": r.event_id, "ts": _iso(r.ts), "level": r.level, "service": r.service,
                       "event": r.event, "error_code": r.error_code, "message": r.message,
                       "tenant_id": str(r.tenant_id) if r.tenant_id else None, "request_id": r.request_id,
                       "scan_id": str(r.scan_id) if r.scan_id else None, "pool": r.pool, "data": r.data}
                      for r in rows], "total": total, "page": page, "page_size": PAGE}
