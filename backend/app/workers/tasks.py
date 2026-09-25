"""Core Celery tasks. The scan pipeline is a small state machine:

    start_scan -> advance_scan -> [sensor job on scanners.<pool>]
                        ^                        |
                        |                        v  (authenticated envelope on results.<pool>)
                        +---- asm-ingest: results.submit_result (verify, bind, ingest)
    ... -> finalize (risk, metrics) -> notifications

    watchdog: fails stages whose job never reached the broker or never reported
    back, and re-advances running scans left without an in-flight stage.

Sensor workers never publish to ``core``: results arrive on the pool's result
queue and are handled by a separate app (``app.workers.results``).

Every task opens a *tenant-scoped* session (RLS applies) once the scan's
tenant is known. State transitions take the scan's row lock, so duplicate or
concurrent deliveries of the same task (or a result arriving meanwhile) are
serialized and idempotent.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from asm_sensors import eventlog
from asm_sensors.jobs import JOB_HARD_LIMIT_GRACE, TASK_NAME, SensorJob, job_queue
from sqlalchemy import exists, or_, select

from app.core.config import get_settings
from app.db.session import new_session, system_session
from app.models import Organization, Scan, ScanStage
from app.observability import codes
from app.models.enums import ScanStatus, StageStatus
from app.scans import orchestrator
from app.services import maintenance
from app.workers.celery_app import celery_app

log = logging.getLogger(__name__)

# A running stage whose job was not on the broker after this long was never dispatched.
UNDISPATCHED_GRACE = timedelta(minutes=10)
# A running scan without an in-flight stage that has not changed for this long is stranded.
STRANDED_GRACE = timedelta(minutes=5)


def _scan_tenant(scan_id: uuid.UUID) -> uuid.UUID | None:
    """The scan's tenant, from the database — the only source of tenant identity for a task."""
    with system_session() as db:
        tid = db.execute(select(Scan.tenant_id).where(Scan.id == scan_id)).scalar_one_or_none()
    if tid is not None:
        eventlog.annotate(tenant_id=tid, scan_id=scan_id)
    return tid


@celery_app.task(shared=False, name="asm.core.start_scan")
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


def publish_job(job: SensorJob, pool: str) -> None:
    """Put a sensor job on its pool's queue (task id = job id, so it can be revoked)."""
    celery_app.send_task(TASK_NAME, args=[job.model_dump(mode="json")], task_id=job.job_id,
                         queue=job_queue(get_settings().sensor_queue_prefix, pool),
                         time_limit=job.timeout_seconds + JOB_HARD_LIMIT_GRACE,
                         soft_time_limit=job.timeout_seconds + 60,
                         # A second guard: the worker discards it unstarted after this.
                         expires=job.not_after)


@celery_app.task(shared=False, name="asm.core.advance_scan")
def advance_scan(scan_id: str) -> None:
    sid = uuid.UUID(scan_id)
    tid = _scan_tenant(sid)
    if tid is None:
        return
    with new_session(tid) as db:
        scan = db.get(Scan, sid, with_for_update=True)
        if scan is None or scan.status != ScanStatus.RUNNING:
            return
        if any(st.status == StageStatus.RUNNING for st in scan.stages):
            return  # a stage is in flight; its result will advance the scan
        nxt = orchestrator.prepare_next_stage(db, scan)
        if nxt is None:
            orchestrator.finalize_scan(db, scan)
            db.commit()
            dispatch_notifications.delay()
            dispatch_queued_scans.delay()
            return
        stage, job = nxt
        stage_id, pool = stage.id, stage.worker_pool or "default"
        eventlog.annotate(stage_id=stage_id, job_id=job.job_id, pool=pool)
        # The RUNNING state and the job binding are durable *before* the job exists on
        # the broker, so even an immediate result finds the stage ready to accept it.
        db.commit()
    try:
        publish_job(job, pool)
    except Exception:  # noqa: BLE001 - broker unavailable: fail the stage, don't strand it
        log.exception("could not dispatch sensor job %s for scan %s", job.job_id, scan_id)
        with new_session(tid) as db:
            scan = db.get(Scan, sid, with_for_update=True)
            stage = db.get(ScanStage, stage_id)
            if scan is not None and stage is not None and stage.task_id == job.job_id:
                orchestrator.fail_stage(db, scan, stage, "The sensor job could not be dispatched",
                                        codes.SCAN_DISPATCH_FAILED)
            db.commit()
        advance_scan.delay(scan_id)
        return
    with new_session(tid) as db:
        stage = db.get(ScanStage, stage_id)
        if stage is not None and stage.task_id == job.job_id and stage.dispatched_at is None:
            stage.dispatched_at = datetime.now(UTC)
            db.commit()
            logging.getLogger("exteriq.scans").info("stage %s dispatched", stage.stage_type.value, extra={
                "event": "scan.stage.dispatched", "stream": "scans", "queue": f"scanners.{pool}",
                "stage_type": stage.stage_type.value, "target_count": len(job.targets)})


@celery_app.task(shared=False, name="asm.core.stage_failed")
def stage_failed(scan_id: str, stage_id: str, reason: str = "Sensor task failed, timed out or was lost") -> None:
    sid = uuid.UUID(scan_id)
    tid = _scan_tenant(sid)
    if tid is None:
        return
    with new_session(tid) as db:
        scan = db.get(Scan, sid, with_for_update=True)
        stage = db.get(ScanStage, uuid.UUID(stage_id))
        if scan is None or stage is None:
            return
        orchestrator.fail_stage(db, scan, stage, reason)
        db.commit()
    advance_scan.delay(scan_id)


@celery_app.task(shared=False, name="asm.core.export_events")
def export_events() -> dict:
    """Finding-lifecycle (alerts) and audit records to the log streams (at least once, deduplicated by id)."""
    from app.observability import export

    return export.run()


@celery_app.task(shared=False, name="asm.core.dispatch_queued_scans")
def dispatch_queued_scans() -> None:
    with system_session() as db:
        rows = db.execute(select(Scan.id).where(Scan.status.in_([ScanStatus.PENDING, ScanStatus.QUEUED]))
                          .order_by(Scan.created_at).limit(100)).scalars().all()
    for sid in rows:
        start_scan.delay(str(sid))


@celery_app.task(shared=False, name="asm.core.dispatch_schedules")
def dispatch_schedules() -> None:
    for tid, sched_id in maintenance.due_schedules():
        scan_id = maintenance.fire_schedule(tid, sched_id)
        if scan_id:
            start_scan.delay(str(scan_id))


@celery_app.task(shared=False, name="asm.core.watchdog")
def watchdog() -> None:
    """Recover work lost to crashes and broker restarts.

    * running stages whose sensor never reported back, or whose job never
      reached the broker, are failed (which advances their scan);
    * running scans with no stage in flight (e.g. a crash between starting the
      scan and advancing it) are advanced again — advance_scan is idempotent.
    """
    now = datetime.now(UTC)
    lost = now - timedelta(seconds=get_settings().stage_timeout_seconds + 900)
    with system_session() as db:
        stuck = db.execute(select(ScanStage.scan_id, ScanStage.id, ScanStage.dispatched_at).where(
            ScanStage.status == StageStatus.RUNNING,
            or_(ScanStage.started_at < lost,
                ScanStage.dispatched_at.is_(None) & (ScanStage.started_at < now - UNDISPATCHED_GRACE)))).all()
        in_flight = exists().where(ScanStage.scan_id == Scan.id, ScanStage.status == StageStatus.RUNNING)
        stranded = db.execute(select(Scan.id).where(
            Scan.status == ScanStatus.RUNNING, Scan.updated_at < now - STRANDED_GRACE, ~in_flight)).scalars().all()
    for scan_id, stage_id, dispatched_at in stuck:
        reason = ("The sensor job was never dispatched" if dispatched_at is None
                  else "Sensor task failed, timed out or was lost")
        stage_failed.delay(str(scan_id), str(stage_id), reason)
    for scan_id in stranded:
        advance_scan.delay(str(scan_id))


@celery_app.task(shared=False, name="asm.core.dispatch_notifications")
def dispatch_notifications() -> None:
    from app.integrations.notifications import dispatch_pending, retry_failed

    with system_session() as db:
        dispatch_pending(db)
        retry_failed(db)


@celery_app.task(shared=False, name="asm.core.maintenance")
def maintenance_task() -> dict:
    stats = maintenance.run_tenant_maintenance()
    stats.update(maintenance.purge_retention())
    dispatch_notifications.delay()
    return stats


@celery_app.task(shared=False, name="asm.core.refresh_intel")
def refresh_intel() -> dict:
    from app.intel.service import refresh_all

    return refresh_all()


@celery_app.task(shared=False, name="asm.core.recompute_org_risk")
def recompute_org_risk(tenant_id: str, organization_id: str) -> None:
    from app.risk.service import recompute_organization

    with new_session(uuid.UUID(tenant_id)) as db:
        org = db.get(Organization, uuid.UUID(organization_id))
        if org:
            recompute_organization(db, org)
            db.commit()


@celery_app.task(shared=False, name="asm.core.recompute_all_risk")
def recompute_all_risk() -> None:
    for tid in maintenance.active_tenants():
        with new_session(tid) as db:
            for (org_id,) in db.execute(select(Organization.id)):
                recompute_org_risk.delay(str(tid), str(org_id))


@celery_app.task(shared=False, name="asm.core.snapshot_metrics")
def snapshot_metrics() -> None:
    from app.services.metrics import snapshot_organization

    for tid in maintenance.active_tenants():
        with new_session(tid) as db:
            for org in db.execute(select(Organization)).scalars():
                snapshot_organization(db, org)
            db.commit()


@celery_app.task(shared=False, name="asm.core.threat_evaluate")
def threat_evaluate(advisory_id: str = "") -> dict:
    """Match one advisory (or, with no id, every published one) against every tenant.

    Runs on publish and daily as a safety net; per-organization evaluation after each
    scan happens inside the scan's own finalization."""
    from app.threats.jobs import evaluate_everywhere

    stats = evaluate_everywhere(uuid.UUID(advisory_id) if advisory_id else None)
    if stats.get("events"):
        dispatch_notifications.delay()
    return stats


@celery_app.task(shared=False, name="asm.core.threat_evaluate_org")
def threat_evaluate_org(tenant_id: str, organization_id: str) -> dict:
    """After a scan: the organization's inventory against every published advisory."""
    from app.threats.jobs import evaluate_organization

    stats = evaluate_organization(uuid.UUID(tenant_id), uuid.UUID(organization_id))
    if stats.get("events"):
        dispatch_notifications.delay()
    return stats


@celery_app.task(shared=False, name="asm.core.threat_feed")
def threat_feed() -> dict:
    """Write advisories from CISA KEV / NVD, then match what changed against every tenant."""
    from app.threats import feed
    from app.threats.jobs import evaluate_everywhere

    out = feed.run()
    if out.pop("evaluate", False):
        out["evaluation"] = evaluate_everywhere(None)
        if out["evaluation"].get("events"):
            dispatch_notifications.delay()
    return out


@celery_app.task(shared=False, name="asm.core.screenshot_dispatch")
def screenshot_dispatch() -> int:
    """Start queued website captures while the deployment-wide limit allows (also the watchdog)."""
    from app.screenshots.jobs import dispatch

    return dispatch()


@celery_app.task(shared=False, name="asm.core.screenshot_schedule")
def screenshot_schedule() -> int:
    """Weekly cadence: queue captures for endpoints not captured in the last seven days."""
    from app.models import Tenant
    from app.screenshots.service import schedule_weekly

    queued = 0
    for tid in maintenance.active_tenants():
        with new_session(tid) as db:
            tenant = db.get(Tenant, tid)
            if tenant is not None:
                queued += schedule_weekly(db, tenant)
                db.commit()
    if queued:
        screenshot_dispatch.delay()
    return queued


@celery_app.task(shared=False, name="asm.core.generate_report")
def generate_report(tenant_id: str, report_id: str) -> None:
    from app.reporting.service import run_report

    run_report(uuid.UUID(tenant_id), uuid.UUID(report_id))
