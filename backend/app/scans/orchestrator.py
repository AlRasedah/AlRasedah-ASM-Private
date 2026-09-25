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

from asm_sensors.jobs import ResultEnvelope, SensorJob, seal_credentials
from asm_sensors.observations import SensorResult
from asm_sensors.registry import get_adapter
from asm_sensors.targets import InvalidTarget, Target, TargetKind
from sqlalchemy import func, insert, select
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
    ScopeEntryType,
    Severity,
    StageStatus,
    StageType,
    TenantStatus,
)
from app.observability import codes
from app.risk.service import recompute_organization
from app.scans import engines, messages
from app.scans.profiles import INTERNAL_SLUGS, validate_stages
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
AUTH_PROVIDER = "zap_auth"  # the credential slot the web application scanner reads


def parse_target(raw: str) -> Target:
    """One line the user typed into "limit to specific targets" → a Target.

    Order matters. An IPv6 address is full of colons, so it must be tried before
    ``host:port``; a hostname is the fallback. Applications on a non-default port
    are the common case here (``app.example.com:8580``) — a web application scan
    should not depend on the port sweep happening to cover that port.
    """
    value = raw.strip().lower()
    if not value:
        raise InvalidTarget("empty target")
    if "://" in value:
        return Target(kind=TargetKind.URL, value=value)
    for kind in (TargetKind.IP, TargetKind.HOST_PORT, TargetKind.CIDR, TargetKind.HOSTNAME):
        try:
            return Target(kind=kind, value=value)
        except ValueError:
            continue
    raise InvalidTarget(f"not a hostname, IP, host:port or URL: {raw!r}")


def create_scan(db: Session, *, tenant_id: uuid.UUID, organization_id: uuid.UUID, profile_id: uuid.UUID,
                trigger: ScanTrigger = ScanTrigger.MANUAL, requested_by: uuid.UUID | None = None,
                schedule_id: uuid.UUID | None = None, target_override: list[str] | None = None,
                auth_secret: str | None = None, auth_header_name: str = "Cookie",
                stages: list[dict[str, Any]] | None = None) -> Scan:
    """Create a scan. ``stages`` replaces the profile's stages and is accepted only
    for an internal profile (a Threat Center check builds its one stage from an
    approved check); internal profiles cannot be started any other way."""
    org = db.get(Organization, organization_id)
    if org is None or not org.is_active:
        raise NotFound("Organization not found")
    profile = db.get(ScanProfile, profile_id)
    if profile is None or (profile.tenant_id is not None and profile.tenant_id != tenant_id):
        raise NotFound("Scan profile not found")
    internal = profile.tenant_id is None and profile.slug in INTERNAL_SLUGS
    if internal != (stages is not None):
        raise NotFound("Scan profile not found")
    stages = [s for s in (validate_stages(stages) if stages is not None else profile.stages)
              if s.get("enabled", True)]
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
            try:
                t = parse_target(raw)
            except ValueError as exc:
                raise ValidationFailed(
                    f"Invalid target: {raw}. Use a hostname, an IP address, host:port (example.com:8580) "
                    "or a full URL."
                ) from exc
            decision = checker.check(t, active=False)
            if not decision.allowed:
                raise ScopeViolation(f"{raw} is outside the authorized scope: {decision.reason}")
            override.append(t.value)

    # Internal scans de-duplicate themselves (one active check per advisory and organization).
    if not internal and db.execute(select(Scan.id).where(
            Scan.organization_id == organization_id, Scan.profile_id == profile_id,
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
    if auth_secret:
        if any(c in auth_secret for c in "\r\n"):
            raise ValidationFailed("The sign-in value must be a single line")
        if not any(AUTH_PROVIDER in get_adapter(s["engine"]).credential_providers for s in stages):
            raise ValidationFailed("This profile has no web application scanning stage, so a sign-in value would "
                                   "not be used. Choose a profile with web crawling or web vulnerability scanning.")
        # Bound to this scan: the ciphertext is useless on any other row.
        scan.auth_secret_encrypted = crypto.encrypt(auth_secret.encode(), f"scan:{scan.id}:auth")
        scan.auth_header_name = auth_header_name
    for i, s in enumerate(stages):
        db.add(ScanStage(tenant_id=tenant_id, scan_id=scan.id, position=i, stage_type=StageType(s["stage"]),
                         engine=s["engine"], config={**(s.get("config") or {}), "_optional": bool(s.get("optional"))},
                         is_active=bool(s.get("active")), status=StageStatus.PENDING, stats={}))
    audit.record(db, Action.SCAN_CREATED, tenant_id=tenant_id, object_type="scan", object_id=scan.id,
                 new={"organization_id": str(organization_id), "profile": profile.name, "trigger": trigger.value,
                      "targets": override,
                      # Records *that* a sign-in value was supplied, never the value itself.
                      "authenticated": bool(auth_secret)})
    tenants.record_usage(db, tenant_id, "scans", 1, scan.id, profile=profile.slug)
    db.flush()
    db.refresh(scan)
    return scan


RunningTask = tuple[str, str]  # (sensor task id, worker pool) — what a revocation needs


def _cancel(db: Session, scan: Scan, reason: str | None = None) -> list[RunningTask]:
    tasks: list[RunningTask] = []
    for st in scan.stages:
        if st.status == StageStatus.RUNNING and st.task_id:
            tasks.append((st.task_id, st.worker_pool or "default"))
        if st.status in (StageStatus.PENDING, StageStatus.RUNNING):
            st.status = StageStatus.CANCELLED
            st.finished_at = _now()
    scan.status = ScanStatus.CANCELLED
    scan.finished_at = _now()
    scan.auth_secret_encrypted = None  # the sign-in value lives only while the scan runs
    if reason:
        scan.error = reason
    audit.record(db, Action.SCAN_CANCELLED, tenant_id=scan.tenant_id, object_type="scan", object_id=scan.id,
                 new={"reason": reason} if reason else None)
    db.flush()
    _after_scan(db, scan, None)
    return tasks


def _after_scan(db: Session, scan: Scan, org: Organization | None) -> None:
    """Let the Threat Center react to a finished or cancelled scan.

    Runs in a savepoint and swallows its own errors: an assessment problem must never
    fail a scan, lose its results or block cancellation."""
    from app.threats import service as threats

    try:
        with db.begin_nested():
            threats.on_scan_finished(db, scan, org)
    except Exception:  # noqa: BLE001
        log.exception("Threat Center update failed after scan %s", scan.id)


def cancel_scan(db: Session, scan_id: uuid.UUID) -> tuple[Scan, list[RunningTask]]:
    scan = db.get(Scan, scan_id, with_for_update=True)
    if scan is None:
        raise NotFound("Scan not found")
    if scan.status not in ACTIVE_SCAN_STATES:
        raise Conflict(f"Scan is already {scan.status.value}")
    return scan, _cancel(db, scan)


def cancel_tenant_scans(db: Session, tenant_id: uuid.UUID, reason: str) -> list[RunningTask]:
    """Cancel every queued or running scan of a tenant (suspension). Returns tasks to revoke."""
    tasks: list[RunningTask] = []
    for scan in db.execute(select(Scan).where(Scan.tenant_id == tenant_id, Scan.status.in_(ACTIVE_SCAN_STATES))
                           .with_for_update()).scalars():
        tasks += _cancel(db, scan, reason)
    return tasks


def _inactive_reason(db: Session, scan: Scan) -> str | None:
    """Why the scan's tenant/organization may no longer scan, if so.

    Policy: a suspended tenant (or deactivated organization) runs nothing further.
    Queued scans are cancelled when they would start, running scans at their next
    stage boundary; suspending a tenant through the API cancels them immediately.
    """
    tenant = db.get(Tenant, scan.tenant_id)
    if tenant is None or tenant.status != TenantStatus.ACTIVE:
        return "Cancelled: the tenant is suspended"
    org = db.get(Organization, scan.organization_id)
    if org is None or not org.is_active:
        return "Cancelled: the organization is inactive"
    return scanner_pool_error(tenant)


def scanner_pool_error(tenant: Tenant) -> str | None:
    """Why this tenant's scans must not be dispatched, if so.

    A worker pool is a trust domain, not a queue name: its containers hold the pool's
    broker credentials and transport key, so a compromised scanner can read every job
    in the pool, open those tenants' sealed credentials and sign results for their
    pending stages. Tenants who do not trust each other therefore may not share one,
    and the platform refuses the dispatch rather than relying on an operator having
    read the deployment guide.
    """
    s = get_settings()
    pool = tenant.worker_pool or "default"
    if pool not in s.worker_pools:
        return (f"Cancelled: no scanner is running for this tenant's pool ({pool!r}). A platform administrator "
                f"provisions one with `cli scanner-pool {pool}` and adds it to ASM_WORKER_POOLS.")
    if s.scanner_isolation != "per_tenant":
        return None
    # Cross-tenant question: RLS hides other tenants from `db`, so ask outside it.
    with system_session() as sys_db:
        others = list(sys_db.execute(
            select(Tenant.name).where(Tenant.worker_pool == pool, Tenant.id != tenant.id).limit(3)).scalars())
    if others:
        return (f"Cancelled: the scanner pool {pool!r} is shared with another tenant, and this deployment isolates "
                "tenants at the scanner. A platform administrator must give this tenant a pool of its own.")
    return None


# ------------------------------------------------------------------ running
# Advisory lock serializing scan-slot reservation platform-wide ("ASMSTART").
_START_LOCK = 0x41534D5354415254


def try_start(db: Session, scan: Scan) -> bool:
    """Move a pending/queued scan to running if concurrency limits allow.

    Reservations are serialized with a transaction-level advisory lock held until
    the caller commits, so two workers can never both see (and take) the last free
    slot, and a redelivered start of the same scan finds it already running.
    """
    db.execute(select(func.pg_advisory_xact_lock(_START_LOCK)))
    db.refresh(scan)  # re-read under the lock
    if scan.status not in (ScanStatus.PENDING, ScanStatus.QUEUED):
        return False
    reason = _inactive_reason(db, scan)
    if reason:
        _cancel(db, scan, reason)
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
    reason = _inactive_reason(db, scan)
    if reason:
        _cancel(db, scan, reason)
        return None
    org = db.get(Organization, scan.organization_id)
    tenant = db.get(Tenant, scan.tenant_id)
    assert org is not None and tenant is not None
    pool = tenant.worker_pool or "default"
    s = get_settings()
    for stage in sorted(scan.stages, key=lambda st: st.position):
        if stage.status != StageStatus.PENDING:
            continue
        checker = load_checker(db, org)
        adapter = get_adapter(stage.engine)
        built = build_targets(db, org, scan, stage.stage_type, s.max_targets_per_stage,
                              crawled_pages=adapter.wants_crawled_pages)
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
        if scan.auth_secret_encrypted and AUTH_PROVIDER in adapter.credential_providers:
            # A sign-in value given for this scan wins over the tenant's stored one.
            creds[AUTH_PROVIDER] = [crypto.decrypt(scan.auth_secret_encrypted, f"scan:{scan.id}:auth").decode()]
            if scan.auth_header_name and "auth_header_name" in adapter.config_model.model_fields:
                cfg["auth_header_name"] = scan.auth_header_name
        job_id = uuid.uuid4().hex
        job = SensorJob(
            job_id=job_id, tenant_id=str(scan.tenant_id), scan_id=str(scan.id), stage_id=str(stage.id),
            adapter=stage.engine, targets=allowed, config=cfg,
            # Sealed with the pool's key: only the pool the job is sent to can open it.
            sealed_credentials=seal_credentials(creds, job_id, crypto.pool_transport_key(pool)) if creds else None,
            timeout_seconds=s.stage_timeout_seconds,
            retain_raw_output=bool(scan.profile_snapshot.get("retain_raw_output")),
            excluded_networks=[r.value for r in checker.rules if r.is_exclusion
                               and r.entry_type in (ScopeEntryType.IP, ScopeEntryType.CIDR)],
        )
        stage.status = StageStatus.RUNNING
        stage.started_at = _now()
        # The binding a submitted result must match (see result_binding_error).
        stage.task_id = job_id
        stage.worker_pool = pool
        stage.dispatched_at = None
        db.flush()
        return stage, job
    return None


def result_binding_error(scan: Scan | None, stage: ScanStage | None, env: ResultEnvelope,
                         result: SensorResult) -> str | None:
    """Why a submitted result does not answer the job dispatched for this stage (None = it does)."""
    if scan is None or stage is None or stage.scan_id != scan.id or str(scan.tenant_id) != env.tenant_id:
        return "no such stage for this tenant and scan"
    if not stage.task_id or stage.task_id != env.job_id:
        return "job id does not match the job dispatched for the stage"
    if (stage.worker_pool or "default") != env.pool:
        return f"submitted by pool {env.pool!r}, but the job was dispatched to {stage.worker_pool!r}"
    if result.adapter != stage.engine:
        return f"result is from engine {result.adapter!r}, the stage runs {stage.engine!r}"
    if stage.status != StageStatus.RUNNING or scan.status != ScanStatus.RUNNING:
        return f"stage is {stage.status.value} (scan {scan.status.value}); result is stale"
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


scans_log = logging.getLogger("exteriq.scans")
_TIMEOUT_WORDS = ("timed out", "time limit", "deadline", "did not finish before")


def _ms(later: datetime | None, earlier: datetime | None) -> int | None:
    if later is None or earlier is None:
        return None
    return max(0, round((later - earlier).total_seconds() * 1000))


def stage_timing(stage: ScanStage, result: SensorResult | None, now: datetime) -> dict[str, Any]:
    """Queue wait (published → the scanner started), execution (on the scanner) and ingestion
    (the scanner finished → recorded here). Scanner and platform clocks may differ slightly."""
    queued_from = stage.dispatched_at or stage.started_at
    out: dict[str, Any] = {"queue_wait_ms": _ms(result.started_at, queued_from) if result else None,
                           "execution_ms": _ms(result.finished_at, result.started_at) if result else None,
                           "ingestion_ms": _ms(now, result.finished_at) if result else None,
                           "total_ms": _ms(now, stage.started_at)}
    if result is not None:
        text = " ".join(result.errors).lower()
        out["timed_out"] = any(w in text for w in _TIMEOUT_WORDS)
        out["retries"] = int(result.stats.get("retries", 0) or 0) if isinstance(result.stats, dict) else 0
    return out


def stage_event(scan: Scan, stage: ScanStage, timing: dict[str, Any] | None = None, result: SensorResult | None = None,
                error_code: str | None = None) -> None:
    """One ``scans`` stream event per finished stage (docs/LOGGING.md)."""
    status = stage.status.value
    coverage = ("complete" if status == "completed" else "partial" if status == "partial" else "none")
    level = logging.INFO if status in ("completed", "skipped") else logging.WARNING
    code = error_code or (codes.SCAN_STAGE_TIMEOUT if (timing or {}).get("timed_out")
                          else codes.SCAN_STAGE_FAILED if status == "failed"
                          else codes.SCAN_STAGE_PARTIAL if status == "partial"
                          else codes.SCAN_SKIPPED_OPTIONAL if status == "skipped" and stage.error else None)
    t = timing or {}
    scans_log.log(level, "stage %s %s", stage.stage_type.value, status, extra={
        "event": "scan.stage.finished", "stream": "scans", "tenant_id": str(scan.tenant_id), "scan_id": str(scan.id),
        "stage_id": str(stage.id), "job_id": stage.task_id, "pool": stage.worker_pool, "stage_type":
        stage.stage_type.value, "adapter": stage.engine, "status": status, "coverage": coverage,
        "error_code": code, "target_count": stage.target_count, "rejected_count": stage.rejected_count,
        "observation_count": stage.observation_count, "duration_ms": t.get("total_ms"),
        "queue_wait_ms": t.get("queue_wait_ms"), "execution_ms": t.get("execution_ms"),
        "ingestion_ms": t.get("ingestion_ms"), "retries": t.get("retries", 0),
        "component_version": (result.tool_version if result else None)})


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

    capability = engines.label_for(stage.engine)
    if result.status == "failed":
        stage.status = StageStatus.SKIPPED if optional else StageStatus.FAILED
        # The raw tool output stays in the worker log; users get something actionable
        # that does not name the engine (see app/scans/messages.py).
        log.info("stage %s (%s) failed: %s", stage.id, stage.engine, "; ".join(result.errors)[:1000])
        stage.error = messages.friendly(result.errors, capability) or f"{capability} did not finish successfully."
        timing = stage_timing(stage, result, now)
        stage.stats = {"timing": timing}
        db.flush()
        stage_event(scan, stage, timing, result)
        return
    if result.status != "completed" and result.coverage:
        # Only a run that proved it finished may vouch for absence (port closed,
        # host gone, finding resolved). Enforced here too, not just in the sensor.
        result = result.model_copy(update={"coverage": []})

    checker = load_checker(db, org)
    ingest = Ingestor(db, IngestContext(
        tenant_id=scan.tenant_id, organization=org, source=result.adapter, checker=checker, now=now, settings=ts,
        discovery_method=stage.stage_type.value, scan_id=scan.id, stage_id=stage.id, baseline=scan.is_baseline,
        historical=result.historical,
    )).ingest(result)
    # Detection rules assert what is exposed *now* ("RDP reachable", "admin interface
    # open"), so they may only read evidence a sensor actually observed. A historical
    # result is another database's record of unknown age: running the rules over it
    # would turn a third-party sighting into an ordinary verified finding with alerts
    # and a risk score, which is exactly the separation ADR-020 exists to keep.
    rules_result = (rules.evaluate(db, ingest.touched, ts["detection_rules"])
                    if not result.historical else None)
    if rules_result and rules_result.coverage:
        rules_ingest = Ingestor(db, IngestContext(
            tenant_id=scan.tenant_id, organization=org, source=rules.SOURCE, checker=checker, now=now, settings=ts,
            discovery_method="detection_rules", scan_id=scan.id, stage_id=stage.id, baseline=scan.is_baseline,
        )).ingest(rules_result)
        ingest.stats.update({f"rules_{k}": v for k, v in rules_ingest.stats.items()})
    _store_artifacts(db, scan, stage, result)

    stage.status = StageStatus.COMPLETED if result.status == "completed" else StageStatus.PARTIAL
    stage.observation_count = len(result.observations)
    timing = stage_timing(stage, result, now)
    stage.stats = {**dict(ingest.stats), "sensor": result.stats, "duration_seconds":
                   round((result.finished_at - result.started_at).total_seconds(), 1), "timing": timing}
    if result.errors:
        log.info("stage %s (%s) reported: %s", stage.id, stage.engine, "; ".join(result.errors)[:1000])
        stage.error = messages.friendly(result.errors, capability)
    _merge_stats(scan, ingest.stats)
    tenants.record_usage(db, scan.tenant_id, "sensor_seconds",
                         int((result.finished_at - result.started_at).total_seconds()), scan.id, engine=stage.engine)
    db.flush()
    stage_event(scan, stage, timing, result)


def fail_stage(db: Session, scan: Scan, stage: ScanStage, error: str, error_code: str | None = None) -> None:
    if stage.status != StageStatus.RUNNING:
        return
    stage.status = StageStatus.SKIPPED if stage.config.get("_optional") else StageStatus.FAILED
    stage.error = error[:4000]
    stage.finished_at = _now()
    timing = stage_timing(stage, None, stage.finished_at)
    stage.stats = {**(stage.stats or {}), "timing": timing}
    db.flush()
    stage_event(scan, stage, timing, None, error_code or codes.SCAN_STAGE_LOST)


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
    scan.auth_secret_encrypted = None  # erased as soon as the scan is over

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
    st = scan.stats or {}
    scans_log.log(logging.INFO if scan.status == ScanStatus.COMPLETED else logging.WARNING,
                  "scan %s", scan.status.value, extra={
                      "event": "scan.finished", "stream": "scans", "tenant_id": str(scan.tenant_id),
                      "organization_id": str(scan.organization_id), "scan_id": str(scan.id),
                      "status": scan.status.value, "duration_ms": _ms(now, scan.started_at),
                      "coverage": "complete" if scan.status == ScanStatus.COMPLETED else "partial",
                      "count": len(stages), "data": {k: st.get(k, 0) for k in ("new_assets", "new_findings", "events")}})
    _after_scan(db, scan, org)


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
    sensor_settings = {"allow_non_public_targets": get_settings().allow_non_public_scope, **(settings or {})}
    while True:
        nxt = prepare_next_stage(db, scan)
        if nxt is not None:
            nxt[0].dispatched_at = _now()
        db.commit()
        if nxt is None:
            break
        stage, job = nxt
        pool = stage.worker_pool or "default"
        key = crypto.pool_transport_key(pool)

        def send_output(chunk: dict, job: SensorJob = job, pool: str = pool, key: bytes = key) -> None:
            from asm_sensors.jobs import seal_log

            from app.scans import output

            output.receive(seal_log(job, chunk, pool, key))

        result = asyncio.run(execute_job(job, settings=sensor_settings, transport_key=key, log_sink=send_output))
        complete_stage(db, scan, stage, result)
        db.commit()
    finalize_scan(db, scan)
    db.commit()
    return scan
