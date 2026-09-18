"""Facade for background work. Celery in production; synchronous in inline mode
(development and tests), so API code never branches on the execution mode."""

from __future__ import annotations

import logging
import uuid

from app.core.config import get_settings

log = logging.getLogger(__name__)


def _inline() -> bool:
    return get_settings().sensor_mode == "inline"


def _send(name: str, *args: str) -> None:
    from app.workers.celery_app import celery_app

    celery_app.send_task(name, args=list(args), queue="core")


def start_scan(tenant_id: uuid.UUID, scan_id: uuid.UUID) -> None:
    if _inline():
        from app.db.session import new_session
        from app.scans.orchestrator import run_inline

        with new_session(tenant_id) as db:
            run_inline(db, scan_id)
        dispatch_notifications()
        return
    _send("asm.core.start_scan", str(scan_id))


def recompute_risk(tenant_id: uuid.UUID, organization_id: uuid.UUID) -> None:
    if _inline():
        from app.db.session import new_session
        from app.models import Organization
        from app.risk.service import recompute_organization

        with new_session(tenant_id) as db:
            org = db.get(Organization, organization_id)
            if org:
                recompute_organization(db, org)
                db.commit()
        return
    _send("asm.core.recompute_org_risk", str(tenant_id), str(organization_id))


def generate_report(tenant_id: uuid.UUID, report_id: uuid.UUID) -> None:
    if _inline():
        from app.reporting.service import run_report

        run_report(tenant_id, report_id)
        return
    _send("asm.core.generate_report", str(tenant_id), str(report_id))


def dispatch_notifications() -> None:
    if _inline():
        from app.db.session import system_session
        from app.integrations.notifications import dispatch_pending

        with system_session() as db:
            dispatch_pending(db)
        return
    _send("asm.core.dispatch_notifications")


def refresh_intel() -> None:
    if _inline():
        from app.intel.service import refresh_all

        refresh_all()
        return
    _send("asm.core.refresh_intel")


def revoke(task_ids: list[str]) -> None:
    if not task_ids or _inline():
        return
    from app.workers.celery_app import celery_app

    for tid in task_ids:
        try:
            celery_app.control.revoke(tid, terminate=True, signal="SIGTERM")
        except Exception:  # noqa: BLE001
            log.warning("could not revoke task %s", tid)
