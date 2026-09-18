"""Core Celery tasks. The scan pipeline is a small state machine:

    start_scan -> advance_scan -> [sensor job on scanners.<pool>] -> ingest_stage -> advance_scan -> ...
                                                   \\-- on error --> stage_failed -> advance_scan
    ... -> finalize (risk, metrics) -> notifications

Every task opens a *tenant-scoped* session (RLS applies) once the scan's
tenant is known.
"""

from __future__ import annotations

import logging
import uuid

from asm_sensors.jobs import TASK_NAME
from asm_sensors.observations import SensorResult
from celery import chain, signature
from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import new_session, system_session
from app.models import Organization, Scan, ScanStage, Tenant
from app.models.enums import ScanStatus, StageStatus
from app.scans import orchestrator
from app.services import maintenance
from app.workers.celery_app import celery_app

log = logging.getLogger(__name__)


def _scan_tenant(scan_id: uuid.UUID) -> uuid.UUID | None:
    with system_session() as db:
        return db.execute(select(Scan.tenant_id).where(Scan.id == scan_id)).scalar_one_or_none()


@celery_app.task(name="asm.core.start_scan")
def start_scan(scan_id: str) -> None:
    sid = uuid.UUID(scan_id)
    tid = _scan_tenant(sid)
    if tid is None:
        return
    with new_session(tid) as db:
        scan = db.get(Scan, sid)
        started = scan is not None and orchestrator.try_start(db, scan)
        db.commit()
    if started:
        advance_scan.delay(scan_id)


@celery_app.task(name="asm.core.advance_scan")
def advance_scan(scan_id: str) -> None:
    sid = uuid.UUID(scan_id)
    tid = _scan_tenant(sid)
    if tid is None:
        return
    with new_session(tid) as db:
        scan = db.get(Scan, sid)
        if scan is None or scan.status != ScanStatus.RUNNING:
            return
        if any(st.status == StageStatus.RUNNING for st in scan.stages):
            return  # a stage is in flight; its callback will advance the scan
        nxt = orchestrator.prepare_next_stage(db, scan)
        if nxt is None:
            orchestrator.finalize_scan(db, scan)
            db.commit()
            dispatch_notifications.delay()
            dispatch_queued_scans.delay()
            return
        stage, job = nxt
        tenant = db.get(Tenant, tid)
        queue = f"{get_settings().sensor_queue_prefix}.{tenant.worker_pool if tenant else 'default'}"
        sensor = signature(TASK_NAME, args=[job.model_dump(mode="json")], queue=queue,
                           time_limit=job.timeout_seconds + 300, soft_time_limit=job.timeout_seconds + 60,
                           app=celery_app)
        flow = chain(sensor, ingest_stage.s(scan_id, str(stage.id)).set(queue="core"))
        result = flow.apply_async(link_error=stage_failed.si(scan_id, str(stage.id)).set(queue="core"))
        stage.task_id = result.parent.id if result.parent is not None else result.id
        db.commit()


@celery_app.task(name="asm.core.ingest_stage")
def ingest_stage(result: dict, scan_id: str, stage_id: str) -> None:
    sid = uuid.UUID(scan_id)
    tid = _scan_tenant(sid)
    if tid is None:
        return
    with new_session(tid) as db:
        scan = db.get(Scan, sid)
        stage = db.get(ScanStage, uuid.UUID(stage_id))
        if scan is None or stage is None:
            return
        orchestrator.complete_stage(db, scan, stage, SensorResult.model_validate(result))
        db.commit()
    advance_scan.delay(scan_id)


@celery_app.task(name="asm.core.stage_failed")
def stage_failed(scan_id: str, stage_id: str) -> None:
    sid = uuid.UUID(scan_id)
    tid = _scan_tenant(sid)
    if tid is None:
        return
    with new_session(tid) as db:
        scan = db.get(Scan, sid)
        stage = db.get(ScanStage, uuid.UUID(stage_id))
        if scan is None or stage is None:
            return
        orchestrator.fail_stage(db, scan, stage, "Sensor task failed, timed out or was lost")
        db.commit()
    advance_scan.delay(scan_id)


@celery_app.task(name="asm.core.dispatch_queued_scans")
def dispatch_queued_scans() -> None:
    with system_session() as db:
        rows = db.execute(select(Scan.id).where(Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED]))
                          .order_by(Scan.created_at).limit(100)).scalars().all()
    for sid in rows:
        start_scan.delay(str(sid))


@celery_app.task(name="asm.core.dispatch_schedules")
def dispatch_schedules() -> None:
    for tid, sched_id in maintenance.due_schedules():
        scan_id = maintenance.fire_schedule(tid, sched_id)
        if scan_id:
            start_scan.delay(str(scan_id))


@celery_app.task(name="asm.core.watchdog")
def watchdog() -> None:
    """Fail stages whose sensor never reported back (lost worker, broker restart)."""
    from datetime import UTC, datetime, timedelta

    limit = datetime.now(UTC) - timedelta(seconds=get_settings().stage_timeout_seconds + 900)
    with system_session() as db:
        stuck = db.execute(select(ScanStage.scan_id, ScanStage.id).where(
            ScanStage.status == StageStatus.RUNNING, ScanStage.started_at < limit)).all()
    for scan_id, stage_id in stuck:
        stage_failed.delay(str(scan_id), str(stage_id))


@celery_app.task(name="asm.core.dispatch_notifications")
def dispatch_notifications() -> None:
    from app.integrations.notifications import dispatch_pending, retry_failed

    with system_session() as db:
        dispatch_pending(db)
        retry_failed(db)


@celery_app.task(name="asm.core.maintenance")
def maintenance_task() -> dict:
    stats = maintenance.run_tenant_maintenance()
    stats.update(maintenance.purge_retention())
    dispatch_notifications.delay()
    return stats


@celery_app.task(name="asm.core.refresh_intel")
def refresh_intel() -> dict:
    from app.intel.service import refresh_all

    return refresh_all()


@celery_app.task(name="asm.core.recompute_org_risk")
def recompute_org_risk(tenant_id: str, organization_id: str) -> None:
    from app.risk.service import recompute_organization

    with new_session(uuid.UUID(tenant_id)) as db:
        org = db.get(Organization, uuid.UUID(organization_id))
        if org:
            recompute_organization(db, org)
            db.commit()


@celery_app.task(name="asm.core.recompute_all_risk")
def recompute_all_risk() -> None:
    for tid in maintenance.active_tenants():
        with new_session(tid) as db:
            for (org_id,) in db.execute(select(Organization.id)):
                recompute_org_risk.delay(str(tid), str(org_id))


@celery_app.task(name="asm.core.snapshot_metrics")
def snapshot_metrics() -> None:
    from app.services.metrics import snapshot_organization

    for tid in maintenance.active_tenants():
        with new_session(tid) as db:
            for org in db.execute(select(Organization)).scalars():
                snapshot_organization(db, org)
            db.commit()


@celery_app.task(name="asm.core.generate_report")
def generate_report(tenant_id: str, report_id: str) -> None:
    from app.reporting.service import run_report

    run_report(uuid.UUID(tenant_id), uuid.UUID(report_id))
