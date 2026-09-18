"""Scan orchestration: creation, authorization, stage sequencing, ingestion hand-off,
finalization.

The orchestrator is transport-agnostic. The Celery tasks in
``app.workers.tasks`` drive it asynchronously (sensor jobs execute on
dedicated sensor workers); ``run_inline`` drives it synchronously for
development and tests.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import uuid
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from asm_sensors.jobs import SensorJob, seal_credentials
from asm_sensors.observations import SensorResult
from asm_sensors.registry import get_adapter
from asm_sensors.targets import Target, TargetKind
from sqlalchemy import insert, select
from sqlalchemy.orm import Session

from app.assets.ingest import IngestContext, Ingestor
from app.core import crypto
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound, ScopeViolation, ValidationFailed
from app.db.session import system_session
from app.findings import rules
from app.models import AssetEvent, Organization, Scan, ScanArtifact, ScanProfile, ScanStage, ScopeDecision, Tenant
from app.models.enums import (
    ACTIVE_SCAN_STATES,
    DecisionResult,
    EventType,
    ScanStatus,
    ScanTrigger,
    Severity,
    StageStatus,
    StageType,
)
from app.risk.service import recompute_organization
from app.scans.targets import build_targets
from app.scope.service import load_checker
from app.services import audit
from app.services.audit import Action
from app.services.metrics import snapshot_organization
from app.services.secrets import scanner_credentials
from app.services.storage import get_store
from app.tenants import service as tenants
from app.tenants.settings import tenant_settings

log = logging.getLogger(__name__)
_DONE = (StageStatus.COMPLETED, StageStatus.PARTIAL, StageStatus.FAILED, StageStatus.SKIPPED, StageStatus.CANCELLED)


def _now() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------ creation
def create_scan(db: Session, *, tenant_id: uuid.UUID, organization_id: uuid.UUID, profile_id: uuid.UUID,
                trigger: ScanTrigger = ScanTrigger.MANUAL, requested_by: uuid.UUID | None = None,
                schedule_id: uuid.UUID | None = None, target_override: list[str] | None = None) -> Scan:
    org = db.get(Organization, organization_id)
    if org is None or not org.is_active:
        raise NotFound("Organization not found")
    profile = db.get(ScanProfile, profile_id)
    if profile is None or (profile.tenant_id is not None and profile.tenant_id != tenant_id):
        raise NotFound("Scan profile not found")
    stages = [s for s in profile.stages if s.get("enabled", True)]
    if not stages:
        raise ValidationFailed("The selected profile has no enabled stages")

    checker = load_checker(db, org)
    if not checker.rules or not any(not r.is_exclusion for r in checker.rules):
        raise ScopeViolation("Define the organization's authorized scope before scanning")
    active = any(s.get("active") for s in stages)
    tenant = db.get(Tenant, tenant_id)
    if active:
        if tenant and tenant.plan and not tenant.plan.allow_active_scanning:
            raise ValidationFailed("Your plan does not include active scanning")
        if not any(r.allow_active_scanning and not r.is_exclusion for r in checker.rules):
            raise ScopeViolation("No scope entry authorizes active scanning for this organization")

    override = None
    if target_override:
        override = []
        for raw in target_override:
            value = raw.strip().lower()
            kind = TargetKind.IP if value.replace(".", "").isdigit() or ":" in value else TargetKind.HOSTNAME
            try:
                t = Target(kind=kind, value=value)
            except ValueError as exc:
                raise ValidationFailed(f"Invalid target: {raw}") from exc
            decision = checker.check(t, active=False)
            if not decision.allowed:
                raise ScopeViolation(f"{raw} is outside the authorized scope: {decision.reason}")
            override.append(t.value)

    if db.execute(select(Scan.id).where(Scan.organization_id == organization_id, Scan.profile_id == profile_id,
                                        Scan.status.in_(ACTIVE_SCAN_STATES)).limit(1)).first():
        raise Conflict("A scan with this profile is already queued or running for this organization")
    tenants.check_can_start_scan(db, tenant_id)

    scan = Scan(tenant_id=tenant_id, organization_id=organization_id, profile_id=profile.id, profile_name=profile.name,
                profile_snapshot={"stages": stages, "retain_raw_output": profile.retain_raw_output,
                                  "slug": profile.slug},
                status=ScanStatus.PENDING, trigger=trigger, requested_by=requested_by, schedule_id=schedule_id,
                target_override=override, stats={}, is_baseline=org.baseline_completed_at is None)
    db.add(scan)
    db.flush()
    for i, s in enumerate(stages):
        db.add(ScanStage(tenant_id=tenant_id, scan_id=scan.id, position=i, stage_type=StageType(s["stage"]),
                         engine=s["engine"], config={**(s.get("config") or {}), "_optional": bool(s.get("optional"))},
                         is_active=bool(s.get("active")), status=StageStatus.PENDING, stats={}))
    audit.record(db, Action.SCAN_CREATED, tenant_id=tenant_id, object_type="scan", object_id=scan.id,
                 new={"organization_id": str(organization_id), "profile": profile.name, "trigger": trigger.value,
                      "targets": override})
    tenants.record_usage(db, tenant_id, "scans", 1, scan.id, profile=profile.slug)
    db.flush()
    db.refresh(scan)
    return scan


def cancel_scan(db: Session, scan_id: uuid.UUID) -> tuple[Scan, list[str]]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFound("Scan not found")
    if scan.status not in ACTIVE_SCAN_STATES:
        raise Conflict(f"Scan is already {scan.status.value}")
    task_ids = []
    for st in scan.stages:
        if st.status == StageStatus.RUNNING and st.task_id:
            task_ids.append(st.task_id)
        if st.status in (StageStatus.PENDING, StageStatus.RUNNING):
            st.status = StageStatus.CANCELLED
            st.finished_at = _now()
    scan.status = ScanStatus.CANCELLED
    scan.finished_at = _now()
    audit.record(db, Action.SCAN_CANCELLED, tenant_id=scan.tenant_id, object_type="scan", object_id=scan.id)
    db.flush()
    return scan, task_ids


# ------------------------------------------------------------------ running
def try_start(db: Session, scan: Scan) -> bool:
    """Move a pending/queued scan to running if concurrency limits allow."""
    if scan.status not in (ScanStatus.PENDING, ScanStatus.QUEUED):
        return False
    s = get_settings()
    # The platform-wide count must span tenants; `db` is tenant-scoped (RLS would hide
    # other tenants' scans), so it is taken from a short-lived system session.
    with system_session() as sdb:
        running_everywhere = tenants.running_scans(sdb)
    if tenants.running_scans(db, scan.tenant_id) >= tenants.scan_concurrency_limit(db, scan.tenant_id) \
            or running_everywhere >= s.max_concurrent_scans_global:
        scan.status = ScanStatus.QUEUED
        db.flush()
        return False
    scan.status = ScanStatus.RUNNING
    scan.started_at = _now()
    db.flush()
    return True


def _log_decisions(db: Session, scan: Scan, stage: ScanStage, rows: list[dict[str, Any]]) -> None:
    for i in range(0, len(rows), 5000):
        db.execute(insert(ScopeDecision), rows[i:i + 5000])


def prepare_next_stage(db: Session, scan: Scan) -> tuple[ScanStage, SensorJob] | None:
    """Pick the next runnable stage, authorize its targets and build the sensor job.

    Stages with no authorized targets are skipped. Returns None when no stage
    remains (the caller then finalizes the scan)."""
    if scan.status != ScanStatus.RUNNING:
        return None
    org = db.get(Organization, scan.organization_id)
    assert org is not None
    s = get_settings()
    for stage in sorted(scan.stages, key=lambda st: st.position):
        if stage.status != StageStatus.PENDING:
            continue
        checker = load_checker(db, org)
        built = build_targets(db, org, scan, stage.stage_type, s.max_targets_per_stage)
        adapter = get_adapter(stage.engine)
        cfg = {k: v for k, v in stage.config.items() if not k.startswith("_")}
        active = adapter.is_active(adapter.parse_config(cfg))
        allowed: list[Target] = []
        decisions: list[dict[str, Any]] = []
        for t in built.targets:
            d = checker.check(t, active=active, derived_from=built.derived_from)
            decisions.append({"tenant_id": scan.tenant_id, "scan_id": scan.id, "stage_id": stage.id,
                              "target": t.value[:2048], "decision": DecisionResult.ALLOWED if d.allowed
                              else DecisionResult.REJECTED, "reason": d.reason[:255],
                              "matched_entry_id": d.rule_id, "active": active})
            if d.allowed:
                allowed.append(t)
        for bad in built.invalid:
            decisions.append({"tenant_id": scan.tenant_id, "scan_id": scan.id, "stage_id": stage.id,
                              "target": bad[:2048], "decision": DecisionResult.REJECTED,
                              "reason": "invalid target syntax", "matched_entry_id": None, "active": active})
        _log_decisions(db, scan, stage, decisions)
        stage.target_count = len(allowed)
        stage.rejected_count = len(decisions) - len(allowed)
        stage.is_active = active
        if not allowed:
            stage.status = StageStatus.SKIPPED
            stage.error = "No authorized targets for this stage"
            stage.finished_at = _now()
            db.flush()
            continue
        creds = scanner_credentials(db, scan.tenant_id, adapter.credential_providers)
        job_id = uuid.uuid4().hex
        job = SensorJob(
            job_id=job_id, tenant_id=str(scan.tenant_id), scan_id=str(scan.id), stage_id=str(stage.id),
            adapter=stage.engine, targets=allowed, config=cfg,
            sealed_credentials=seal_credentials(creds, job_id, crypto.transport_key()) if creds else None,
            timeout_seconds=s.stage_timeout_seconds,
            retain_raw_output=bool(scan.profile_snapshot.get("retain_raw_output")),
        )
        stage.status = StageStatus.RUNNING
        stage.started_at = _now()
        db.flush()
        return stage, job
    return None


def _store_artifacts(db: Session, scan: Scan, stage: ScanStage, result: SensorResult) -> None:
    if not result.artifacts:
        return
    store = get_store()
    expires = _now() + timedelta(days=get_settings().raw_output_retention_days)
    for art in result.artifacts:
        key = f"tenants/{scan.tenant_id}/scans/{scan.id}/{stage.id}/{uuid.uuid4().hex}.gz"
        try:
            store.put(key, base64.b64decode(art.data), "application/gzip")
        except (OSError, ValueError) as exc:
            log.warning("could not store raw output for stage %s: %s", stage.id, exc)
            continue
        db.add(ScanArtifact(tenant_id=scan.tenant_id, scan_id=scan.id, stage_id=stage.id, name=art.name,
                            storage_key=key, size=art.size, sha256=art.sha256, truncated=art.truncated,
                            expires_at=expires))


def _merge_stats(scan: Scan, stats: Counter | dict[str, int]) -> None:
    merged = Counter(scan.stats or {})
    merged.update({k: v for k, v in dict(stats).items() if isinstance(v, int)})
    scan.stats = dict(merged)


def complete_stage(db: Session, scan: Scan, stage: ScanStage, result: SensorResult) -> None:
    if stage.status != StageStatus.RUNNING or scan.status != ScanStatus.RUNNING:
        log.info("discarding result for stage %s (scan %s is %s)", stage.id, scan.id, scan.status)
        return
    org = db.get(Organization, scan.organization_id)
    tenant = db.get(Tenant, scan.tenant_id)
    assert org is not None
    ts = tenant_settings(tenant)
    now = _now()
    optional = bool(stage.config.get("_optional"))
    stage.tool_version = result.tool_version
    stage.finished_at = now

    if result.status == "failed":
        stage.status = StageStatus.SKIPPED if optional else StageStatus.FAILED
        stage.error = "; ".join(result.errors)[:4000] or "sensor failed"
        stage.stats = {"errors": result.errors[:20]}
        db.flush()
        return

    checker = load_checker(db, org)
    ingest = Ingestor(db, IngestContext(
        tenant_id=scan.tenant_id, organization=org, source=result.adapter, checker=checker, now=now, settings=ts,
        discovery_method=stage.stage_type.value, scan_id=scan.id, stage_id=stage.id, baseline=scan.is_baseline,
    )).ingest(result)
    rules_result = rules.evaluate(db, ingest.touched, ts["detection_rules"])
    if rules_result.coverage:
        rules_ingest = Ingestor(db, IngestContext(
            tenant_id=scan.tenant_id, organization=org, source=rules.SOURCE, checker=checker, now=now, settings=ts,
            discovery_method="detection_rules", scan_id=scan.id, stage_id=stage.id, baseline=scan.is_baseline,
        )).ingest(rules_result)
        ingest.stats.update({f"rules_{k}": v for k, v in rules_ingest.stats.items()})
    _store_artifacts(db, scan, stage, result)

    stage.status = StageStatus.COMPLETED if result.status == "completed" else StageStatus.PARTIAL
    stage.observation_count = len(result.observations)
    stage.stats = {**dict(ingest.stats), "sensor": result.stats, "duration_seconds":
                   round((result.finished_at - result.started_at).total_seconds(), 1)}
    if result.errors:
        stage.error = "; ".join(result.errors)[:4000]
    _merge_stats(scan, ingest.stats)
    tenants.record_usage(db, scan.tenant_id, "sensor_seconds",
                         int((result.finished_at - result.started_at).total_seconds()), scan.id, engine=stage.engine)
    db.flush()


def fail_stage(db: Session, scan: Scan, stage: ScanStage, error: str) -> None:
    if stage.status != StageStatus.RUNNING:
        return
    stage.status = StageStatus.SKIPPED if stage.config.get("_optional") else StageStatus.FAILED
    stage.error = error[:4000]
    stage.finished_at = _now()
    db.flush()


def finalize_scan(db: Session, scan: Scan) -> None:
    if scan.status == ScanStatus.CANCELLED:
        return
    org = db.get(Organization, scan.organization_id)
    assert org is not None
    now = _now()
    stages = scan.stages
    failed = [s for s in stages if s.status == StageStatus.FAILED]
    succeeded = [s for s in stages if s.status in (StageStatus.COMPLETED, StageStatus.PARTIAL)]
    if not succeeded and failed:
        scan.status = ScanStatus.FAILED
        scan.error = "; ".join(f"{s.stage_type.value}: {s.error}" for s in failed)[:4000]
    elif failed or any(s.status == StageStatus.PARTIAL for s in stages):
        scan.status = ScanStatus.PARTIAL
    else:
        scan.status = ScanStatus.COMPLETED
    scan.finished_at = now

    if succeeded:
        risk = recompute_organization(db, org, scan_id=scan.id, baseline=scan.is_baseline)
        _merge_stats(scan, {"risk_changes": risk["changed"], "risk_events": risk["events"]})
    if scan.is_baseline and scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL):
        org.baseline_completed_at = now

    if scan.status == ScanStatus.FAILED:
        db.add(AssetEvent(tenant_id=scan.tenant_id, organization_id=org.id, scan_id=scan.id,
                          event_type=EventType.SCAN_FAILED, severity=Severity.MEDIUM,
                          title=f"Scan failed: {scan.profile_name} for {org.name}", summary=scan.error,
                          details={}, occurred_at=now, is_baseline=False))
    else:
        st = scan.stats or {}
        db.add(AssetEvent(tenant_id=scan.tenant_id, organization_id=org.id, scan_id=scan.id,
                          event_type=EventType.SCAN_COMPLETED, severity=Severity.INFO,
                          title=f"Scan {scan.status.value}: {scan.profile_name} for {org.name}",
                          summary=f"{st.get('new_assets', 0)} new assets, {st.get('new_findings', 0)} new findings, "
                                  f"{st.get('events', 0)} changes",
                          new_state={k: st.get(k, 0) for k in ("new_assets", "new_findings", "events", "deactivated")},
                          details={}, occurred_at=now, is_baseline=scan.is_baseline))
    snapshot_organization(db, org)
    db.flush()


def run_inline(db: Session, scan_id: uuid.UUID, settings: dict[str, Any] | None = None) -> Scan:
    """Synchronous pipeline for development and tests: sensors run in-process."""
    from asm_sensors.runner import execute_job

    scan = db.get(Scan, scan_id)
    if scan is None:
        raise NotFound("Scan not found")
    if not try_start(db, scan):
        db.commit()
        return scan
    db.commit()
    while True:
        nxt = prepare_next_stage(db, scan)
        db.commit()
        if nxt is None:
            break
        stage, job = nxt
        result = asyncio.run(execute_job(job, settings=settings, transport_key=crypto.transport_key()))
        complete_stage(db, scan, stage, result)
        db.commit()
    finalize_scan(db, scan)
    db.commit()
    return scan
