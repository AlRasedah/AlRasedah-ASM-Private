"""Website screenshots: requests, the deployment-wide dispatcher, results, storage, retention.

Life of a capture::

    request_capture (tenant session)   scope + feature + quota checks  -> queued
    dispatch_pending (system session)  advisory lock, count running,
                                       reserve up to the free slots     -> running
    _launch (tenant session)           re-authorize (scope, pool, feature), build the
                                       sealed SensorJob, publish on scanners.<pool>
    [tenant's scanner pool]            ScreenshotAdapter: fresh browser, egress proxy
    receive_result (asm-ingest)        MAC + job binding, validate image, quota,
                                       store object, retention       -> succeeded / failed / blocked

The concurrency limit (default 1 active capture per deployment) lives in
PostgreSQL, not in any process's memory: every dispatcher, in every container,
takes the same advisory lock and counts ``running`` rows before reserving one.
A capture that never reports back is failed by the watchdog, which frees its slot.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from asm_sensors.adapters.screenshot import png_dimensions
from asm_sensors.jobs import ResultEnvelope, SensorJob
from asm_sensors.observations import SensorResult
from asm_sensors.targets import Target, TargetKind
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.errors import NotFound, QuotaExceeded, ScopeViolation, ValidationFailed
from app.db.session import new_session, system_session
from app.models import Asset, Organization, PlatformSetting, ScopeEntry, ScreenshotCapture, Tenant
from app.models.enums import (
    ACTIVE_SCREENSHOT_STATES,
    AssetStatus,
    AssetType,
    ScopeEntryType,
    ScopeStatus,
    ScreenshotStatus,
    TenantStatus,
)
from app.scope.service import load_checker
from app.services import audit
from app.services.audit import Action
from app.services.storage import get_store
from app.tenants.settings import tenant_settings

log = logging.getLogger(__name__)

ADAPTER = "screenshot"
_DISPATCH_LOCK = 0x41534D53484F5453  # "ASMSHOTS"
DISPATCH_GRACE = timedelta(minutes=10)  # a reserved capture must reach the broker within this

DEFAULT_POLICY: dict[str, Any] = {
    # The deployment's scanner image has the pinned browser and its sandbox prerequisites.
    # Off until a platform administrator says so (docs/SCREENSHOTS.md, DEPLOYMENT.md §5b).
    "available": False,
    "max_concurrent": 1,  # active captures across the whole deployment
    "per_tenant_daily": 50,  # captures a tenant may request per rolling 24 hours
    "per_tenant_queued": 10,  # captures a tenant may have waiting at once
    "retention_per_endpoint": 2,  # successful captures kept per endpoint
    "storage_quota_mb": 200,  # per tenant
    "failed_retention_days": 30,  # failed/blocked/cancelled records
    "timeout_seconds": 20,
    "viewport_width": 1280,
    "viewport_height": 800,
    "max_image_kb": 2048,
}
POLICY_BOUNDS: dict[str, tuple[int, int]] = {
    "max_concurrent": (1, 8), "per_tenant_daily": (1, 5000), "per_tenant_queued": (1, 500),
    "retention_per_endpoint": (1, 10), "storage_quota_mb": (10, 100_000), "failed_retention_days": (1, 365),
    "timeout_seconds": (5, 90), "viewport_width": (320, 1920), "viewport_height": (240, 1200),
    "max_image_kb": (64, 5120),
}
WEB_TYPES = (AssetType.HTTP_ENDPOINT, AssetType.WEB_APPLICATION)


def _now() -> datetime:
    return datetime.now(UTC)


# ======================================================================== policy
def policy() -> dict[str, Any]:
    """The effective platform policy. Read in a short system session (the row is platform-only)."""
    with system_session() as sdb:
        row = sdb.get(PlatformSetting, 1)
        stored = dict(row.screenshots or {}) if row is not None else {}
    out = dict(DEFAULT_POLICY)
    out.update({k: v for k, v in stored.items() if k in DEFAULT_POLICY})
    return out


def set_policy(db: Session, values: dict[str, Any], user_id: uuid.UUID | None) -> dict[str, Any]:
    """Platform administrators only (system session)."""
    row = db.get(PlatformSetting, 1)
    if row is None:
        row = PlatformSetting(id=1, smtp={}, screenshots={})
        db.add(row)
        db.flush()
    before = dict(row.screenshots or {})
    merged = {**before}
    for k, v in values.items():
        if k not in DEFAULT_POLICY or v is None:
            continue
        if k in POLICY_BOUNDS:
            lo, hi = POLICY_BOUNDS[k]
            if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
                raise ValidationFailed(f"{k} must be between {lo} and {hi}")
        merged[k] = v
    row.screenshots = merged
    row.updated_by = user_id
    prev, new = audit.diff(before, merged)
    audit.record(db, Action.SCREENSHOT_POLICY_CHANGED, platform=True, object_type="screenshot_policy",
                 previous=prev, new=new)
    db.flush()
    return {**DEFAULT_POLICY, **merged}


def usage(db: Session, tenant_id: uuid.UUID) -> dict[str, int]:
    since = _now() - timedelta(days=1)
    stored = db.scalar(select(func.coalesce(func.sum(ScreenshotCapture.size), 0)).where(
        ScreenshotCapture.tenant_id == tenant_id, ScreenshotCapture.storage_key.is_not(None))) or 0
    today = db.scalar(select(func.count()).select_from(ScreenshotCapture).where(
        ScreenshotCapture.tenant_id == tenant_id, ScreenshotCapture.created_at >= since,
        ScreenshotCapture.status != ScreenshotStatus.CANCELLED)) or 0
    waiting = db.scalar(select(func.count()).select_from(ScreenshotCapture).where(
        ScreenshotCapture.tenant_id == tenant_id,
        ScreenshotCapture.status.in_([s.value for s in ACTIVE_SCREENSHOT_STATES]))) or 0
    return {"stored_bytes": int(stored), "captures_today": int(today), "active": int(waiting)}


def status_for(db: Session, tenant: Tenant) -> dict[str, Any]:
    """What the UI needs to decide what to show and what to explain."""
    pol = policy()
    ts = tenant_settings(tenant)["screenshots"]
    reason = None
    if not pol["available"]:
        reason = ("Website screenshots are not enabled in this deployment. A platform administrator enables them "
                  "in Settings once the scanners have the screenshot browser installed.")
    elif not ts.get("enabled"):
        reason = "Website screenshots are turned off for this tenant. A tenant administrator can turn them on in Settings."
    return {"available": bool(pol["available"]), "enabled": bool(ts.get("enabled")), "cadence": ts.get("cadence"),
            "reason": reason, "usage": usage(db, tenant.id),
            "limits": {k: pol[k] for k in ("per_tenant_daily", "per_tenant_queued", "retention_per_endpoint",
                                            "storage_quota_mb", "timeout_seconds", "viewport_width", "viewport_height")}}


# ======================================================================= requests
def _authorize(db: Session, org: Organization, asset: Asset, tenant: Tenant) -> str | None:
    """Why this endpoint may not be captured now (None = it may). A capture is an active visit."""
    if tenant.status != TenantStatus.ACTIVE:
        return "the tenant is suspended"
    if not org.is_active:
        return "the organization is inactive"
    if asset.status != AssetStatus.ACTIVE:
        return "the endpoint is no longer observed"
    if asset.scope_status == ScopeStatus.OUT_OF_SCOPE:
        return "the endpoint is outside the authorized scope"
    if tenant.plan is not None and not tenant.plan.allow_active_scanning:
        return "the tenant's plan does not include active scanning"
    try:
        target = Target(kind=TargetKind.URL, value=asset.normalized_value)
    except ValueError:
        return "the endpoint is not a valid web address"
    decision = load_checker(db, org).check(target, active=True)
    return None if decision.allowed else f"not authorized by scope: {decision.reason}"


def request_capture(db: Session, *, tenant_id: uuid.UUID, asset_id: uuid.UUID, user_id: uuid.UUID | None,
                    trigger: str = "manual") -> tuple[ScreenshotCapture, bool]:
    """Queue a capture. Returns ``(capture, created)``; an active capture for the endpoint is reused."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise NotFound("Asset not found")
    if asset.asset_type not in WEB_TYPES or "://" not in asset.normalized_value:
        raise ValidationFailed("Screenshots are taken of web endpoints only")
    tenant = db.get(Tenant, tenant_id)
    org = db.get(Organization, asset.organization_id)
    assert tenant is not None and org is not None
    st = status_for(db, tenant)
    if st["reason"]:
        raise ValidationFailed(st["reason"], code="feature_unavailable")
    existing = db.execute(select(ScreenshotCapture).where(
        ScreenshotCapture.asset_id == asset.id,
        ScreenshotCapture.status.in_([s.value for s in ACTIVE_SCREENSHOT_STATES]))
        .order_by(ScreenshotCapture.created_at.desc()).limit(1)).scalar_one_or_none()
    if existing is not None:
        return existing, False
    lim, used = st["limits"], st["usage"]
    if used["active"] >= lim["per_tenant_queued"]:
        raise QuotaExceeded(f"{used['active']} captures are already waiting; try again when they finish")
    if used["captures_today"] >= lim["per_tenant_daily"]:
        raise QuotaExceeded(f"This tenant may request {lim['per_tenant_daily']} captures per day")
    reason = _authorize(db, org, asset, tenant)
    if reason:
        raise ScopeViolation(f"This endpoint cannot be captured: {reason}")
    c = ScreenshotCapture(tenant_id=tenant_id, organization_id=org.id, asset_id=asset.id, url=asset.normalized_value,
                          trigger=trigger, requested_by=user_id, status=ScreenshotStatus.QUEUED)
    db.add(c)
    db.flush()
    audit.record(db, Action.SCREENSHOT_REQUESTED, tenant_id=tenant_id, object_type="screenshot", object_id=c.id,
                 new={"asset_id": str(asset.id), "trigger": trigger})
    return c, True


def cancel_capture(db: Session, asset_id: uuid.UUID, capture_id: uuid.UUID) -> tuple[ScreenshotCapture, tuple | None]:
    c = db.get(ScreenshotCapture, capture_id, with_for_update=True)
    if c is None or c.asset_id != asset_id:
        raise NotFound("Screenshot not found")
    if c.status not in ACTIVE_SCREENSHOT_STATES:
        return c, None
    task = (c.task_id, c.worker_pool or "default") if c.status == ScreenshotStatus.RUNNING and c.task_id else None
    c.status, c.finished_at, c.error = ScreenshotStatus.CANCELLED, _now(), "cancelled by a user"
    db.flush()
    return c, task


# ===================================================================== dispatching
def _watchdog(sdb: Session, pol: dict[str, Any], now: datetime) -> int:
    """Fail captures that were never dispatched or never reported back (frees their slot)."""
    lost = now - timedelta(seconds=int(pol["timeout_seconds"]) * 3 + 600)
    rows = sdb.execute(select(ScreenshotCapture).where(
        ScreenshotCapture.status == ScreenshotStatus.RUNNING,
        ((ScreenshotCapture.dispatched_at.is_(None)) & (ScreenshotCapture.started_at < now - DISPATCH_GRACE))
        | (ScreenshotCapture.started_at < lost)).with_for_update(skip_locked=True)).scalars().all()
    for c in rows:
        c.status, c.finished_at = ScreenshotStatus.FAILED, now
        c.error = ("the capture was never handed to a scanner" if c.dispatched_at is None
                   else "no result came back in time (the scanner may have stopped)")
    return len(rows)


def reserve(now: datetime | None = None) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Move queued captures to running while the deployment-wide limit allows.

    Serialized by a PostgreSQL advisory lock held until commit, so parallel
    dispatchers in different processes can never reserve the same free slot."""
    now = now or _now()
    pol = policy()
    with system_session() as sdb:
        sdb.execute(select(func.pg_advisory_xact_lock(_DISPATCH_LOCK)))
        _watchdog(sdb, pol, now)
        sdb.flush()
        running = sdb.scalar(select(func.count()).select_from(ScreenshotCapture).where(
            ScreenshotCapture.status == ScreenshotStatus.RUNNING)) or 0
        free = int(pol["max_concurrent"]) - running
        reserved: list[tuple[uuid.UUID, uuid.UUID]] = []
        if free > 0:
            candidates = sdb.execute(select(ScreenshotCapture).where(
                ScreenshotCapture.status == ScreenshotStatus.QUEUED).order_by(ScreenshotCapture.created_at)
                .limit(free * 5).with_for_update(skip_locked=True)).scalars().all()
            # One per tenant first, so a tenant with a long queue cannot starve the others.
            picked, tenants = [], set()
            for c in candidates:
                if c.tenant_id not in tenants:
                    picked.append(c)
                    tenants.add(c.tenant_id)
            picked += [c for c in candidates if c not in picked]
            for c in picked[:free]:
                c.status, c.started_at, c.task_id = ScreenshotStatus.RUNNING, now, uuid.uuid4().hex
                reserved.append((c.tenant_id, c.id))
        sdb.commit()
    return reserved


def _job_config(db: Session, org: Organization, pol: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    excl = db.execute(select(ScopeEntry.entry_type, ScopeEntry.value).where(
        ScopeEntry.organization_id == org.id, ScopeEntry.is_exclusion.is_(True))).all()
    domains = [v for t, v in excl if t == ScopeEntryType.DOMAIN]
    networks = [v for t, v in excl if t in (ScopeEntryType.IP, ScopeEntryType.CIDR)]
    cfg = {"viewport_width": pol["viewport_width"], "viewport_height": pol["viewport_height"],
           "timeout_seconds": pol["timeout_seconds"], "max_image_bytes": int(pol["max_image_kb"]) * 1024,
           "excluded_domains": domains, "excluded_networks": networks}
    return cfg, networks


def _finish(db: Session, c: ScreenshotCapture, status: ScreenshotStatus, error: str | None) -> None:
    c.status, c.error, c.finished_at = status, (error or None) and error[:500], _now()


def launch(tenant_id: uuid.UUID, capture_id: uuid.UUID) -> tuple[SensorJob, str] | None:
    """Re-authorize a reserved capture in its tenant's session and build its sealed job."""
    from app.scans.orchestrator import scanner_pool_error

    pol = policy()
    with new_session(tenant_id) as db:
        c = db.get(ScreenshotCapture, capture_id, with_for_update=True)
        if c is None or c.status != ScreenshotStatus.RUNNING or not c.task_id:
            return None
        tenant = db.get(Tenant, tenant_id)
        org = db.get(Organization, c.organization_id)
        asset = db.get(Asset, c.asset_id)
        reason: str | None = None
        if tenant is None or org is None or asset is None:
            reason = "the endpoint no longer exists"
        elif not pol["available"] or not tenant_settings(tenant)["screenshots"].get("enabled"):
            reason = "website screenshots were turned off"
        else:
            reason = _authorize(db, org, asset, tenant) or scanner_pool_error(tenant)
        if reason:
            _finish(db, c, ScreenshotStatus.BLOCKED, reason.removeprefix("Cancelled: "))
            db.commit()
            return None
        assert tenant is not None and org is not None
        cfg, networks = _job_config(db, org, pol)
        pool = tenant.worker_pool or "default"
        job = SensorJob(job_id=c.task_id, tenant_id=str(tenant_id), scan_id=str(c.id), stage_id=str(c.id),
                        adapter=ADAPTER, targets=[Target(kind=TargetKind.URL, value=c.url)], config=cfg,
                        timeout_seconds=max(60, int(pol["timeout_seconds"]) * 3 + 60), excluded_networks=networks)
        c.worker_pool = pool
        db.commit()
        return job, pool


def mark_dispatched(tenant_id: uuid.UUID, capture_id: uuid.UUID, job_id: str, ok: bool) -> None:
    with new_session(tenant_id) as db:
        c = db.get(ScreenshotCapture, capture_id, with_for_update=True)
        if c is None or c.task_id != job_id or c.status != ScreenshotStatus.RUNNING:
            return
        if ok:
            c.dispatched_at = _now()
        else:
            _finish(db, c, ScreenshotStatus.FAILED, "the capture could not be handed to a scanner")
        db.commit()


def run_inline(job: SensorJob, pool: str) -> None:
    """Development/tests: execute the job in-process and feed the result straight back."""
    import asyncio

    from asm_sensors.jobs import seal_result
    from asm_sensors.runner import execute_job

    from app.core import crypto
    from app.core.config import get_settings

    key = crypto.pool_transport_key(pool)
    result = asyncio.run(execute_job(job, settings={"allow_non_public_targets": get_settings().allow_non_public_scope},
                                     transport_key=key))
    from asm_sensors.jobs import open_result

    env, res = open_result(seal_result(job, result, pool, key), crypto.pool_transport_key)
    receive_result(env, res)


# ========================================================================= results
def binding_error(c: ScreenshotCapture | None, env: ResultEnvelope, result: SensorResult) -> str | None:
    if c is None or str(c.tenant_id) != env.tenant_id or env.scan_id != str(c.id) or env.stage_id != str(c.id):
        return "no such capture for this tenant"
    if result.adapter != ADAPTER:
        return f"result is from {result.adapter!r}, not a screenshot job"
    if not c.task_id or c.task_id != env.job_id:
        return "job id does not match the job dispatched for the capture"
    if (c.worker_pool or "default") != env.pool:
        return f"submitted by pool {env.pool!r}, but the job was dispatched to {c.worker_pool!r}"
    if c.status != ScreenshotStatus.RUNNING:
        return f"capture is {c.status.value}; result is stale"
    return None


def _decode(img: Any, pol: dict[str, Any]) -> bytes:
    """Re-validate the image here: the scanner is not trusted to have done it."""
    try:
        data = base64.b64decode(img.data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("the image data is not valid") from exc
    if len(data) != img.size or len(data) > int(pol["max_image_kb"]) * 1024:
        raise ValueError(f"the image is larger than the {pol['max_image_kb']} KB limit")
    if hashlib.sha256(data).hexdigest() != img.sha256:
        raise ValueError("the image does not match its checksum")
    width, height = png_dimensions(data)
    if width > int(pol["viewport_width"]) * 2 or height > int(pol["viewport_height"]) * 2:
        raise ValueError("the image is larger than the configured viewport")
    return data


_FRIENDLY = (("sandbox", "The screenshot browser cannot start safely on this scanner (its sandbox is unavailable). "
                         "A platform administrator must fix the scanner deployment."),
             ("ConfigurationError", "The screenshot browser is not installed on this tenant's scanner."),
             ("another capture is still running", "The scanner was busy with another capture; try again."))


def _friendly(result: SensorResult) -> str:
    text = "; ".join(result.errors)[:1000]
    for needle, message in _FRIENDLY:
        if needle in text:
            return message
    return text[:500] or "The capture did not finish."


def receive_result(env: ResultEnvelope, result: SensorResult) -> bool:
    """Apply a submitted screenshot result (called by the result consumer after MAC verification)."""
    try:
        tenant_id, capture_id = uuid.UUID(env.tenant_id), uuid.UUID(env.stage_id)
    except ValueError:
        log.warning("rejected screenshot result: malformed ids")
        return False
    pol = policy()
    with new_session(tenant_id) as db:
        c = db.get(ScreenshotCapture, capture_id, with_for_update=True)
        problem = binding_error(c, env, result)
        if problem:
            log.warning("rejected screenshot result for job %s: %s", env.job_id, problem)
            return False
        assert c is not None
        outcome = str(result.stats.get("outcome") or "")
        if result.status != "completed" or not result.screenshots:
            egress = outcome == "blocked" or any("egress policy" in e for e in result.errors)
            _finish(db, c, ScreenshotStatus.BLOCKED if egress else ScreenshotStatus.FAILED, _friendly(result))
            db.commit()
            return True
        img = result.screenshots[0]
        try:
            data = _decode(img, pol)
        except ValueError as exc:
            _finish(db, c, ScreenshotStatus.FAILED, str(exc))
            db.commit()
            return True
        keep = int(pol["retention_per_endpoint"])
        older = list(db.execute(select(ScreenshotCapture).where(
            ScreenshotCapture.asset_id == c.asset_id, ScreenshotCapture.status == ScreenshotStatus.SUCCEEDED,
            ScreenshotCapture.id != c.id).order_by(ScreenshotCapture.captured_at.desc())).scalars())
        drop = older[keep - 1:] if keep >= 1 else older
        stored = usage(db, tenant_id)["stored_bytes"]
        quota = int(pol["storage_quota_mb"]) * 1024 * 1024
        if stored - sum(o.size or 0 for o in drop) + len(data) > quota:
            # The previous captures stay; only the new one is refused.
            _finish(db, c, ScreenshotStatus.FAILED, f"the tenant's screenshot storage quota "
                                                    f"({pol['storage_quota_mb']} MB) is full")
            db.commit()
            return True
        key = f"tenants/{tenant_id}/screenshots/{c.id}.png"
        store = get_store()
        store.put(key, data, "image/png")
        try:
            c.storage_key, c.content_type, c.size, c.sha256 = key, "image/png", len(data), img.sha256
            c.width, c.height, c.captured_at = img.width, img.height, img.captured_at
            c.final_url, c.page_title, c.http_status = img.final_url, img.title, img.status_code
            _finish(db, c, ScreenshotStatus.SUCCEEDED, None)
            db.commit()
        except Exception:
            db.rollback()
            store.delete(key)  # never leave an object without its record
            raise
        for o in drop:
            _delete(db, o)
        db.commit()
    return True


# ====================================================================== retention
def _delete(db: Session, c: ScreenshotCapture) -> bool:
    """Object first, then the record: a record never points at an object that was deleted
    without it, and a failed object delete leaves the record for the next retention run."""
    if c.storage_key:
        try:
            get_store().delete(c.storage_key)
        except Exception:  # noqa: BLE001 - retried by the next retention run
            log.warning("could not delete screenshot object for capture %s; will retry", c.id)
            return False
    db.delete(c)
    return True


def delete_capture(db: Session, asset_id: uuid.UUID, capture_id: uuid.UUID) -> None:
    c = db.get(ScreenshotCapture, capture_id)
    if c is None or c.asset_id != asset_id:
        raise NotFound("Screenshot not found")
    if c.status in ACTIVE_SCREENSHOT_STATES:
        raise ValidationFailed("Cancel the capture before deleting it")
    if not _delete(db, c):
        raise ValidationFailed("The image could not be deleted from storage; try again")
    audit.record(db, Action.SCREENSHOT_DELETED, tenant_id=c.tenant_id, object_type="screenshot", object_id=c.id,
                 previous={"asset_id": str(asset_id)})


def apply_retention(db: Session, tenant_id: uuid.UUID, now: datetime | None = None) -> dict[str, int]:
    """Per tenant: keep the newest N successful captures per endpoint; drop old failure records."""
    now = now or _now()
    pol = policy()
    keep = int(pol["retention_per_endpoint"])
    removed = failed = 0
    ranked = select(ScreenshotCapture.id, func.row_number().over(
        partition_by=ScreenshotCapture.asset_id, order_by=ScreenshotCapture.captured_at.desc()).label("n")).where(
        ScreenshotCapture.tenant_id == tenant_id, ScreenshotCapture.status == ScreenshotStatus.SUCCEEDED).subquery()
    extra = db.execute(select(ScreenshotCapture).join(ranked, ranked.c.id == ScreenshotCapture.id)
                       .where(ranked.c.n > keep)).scalars().all()
    for c in extra:
        removed += _delete(db, c)
    cutoff = now - timedelta(days=int(pol["failed_retention_days"]))
    for c in db.execute(select(ScreenshotCapture).where(
            ScreenshotCapture.tenant_id == tenant_id, ScreenshotCapture.created_at < cutoff,
            ScreenshotCapture.status.in_([ScreenshotStatus.FAILED.value, ScreenshotStatus.BLOCKED.value,
                                          ScreenshotStatus.CANCELLED.value]))).scalars():
        failed += _delete(db, c)
    return {"screenshots_removed": removed, "screenshot_records_removed": failed}


def delete_organization_objects(db: Session, organization_id: uuid.UUID) -> int:
    """Called before an organization is deleted: its rows cascade, its objects would not."""
    n = 0
    for (key,) in db.execute(select(ScreenshotCapture.storage_key).where(
            ScreenshotCapture.organization_id == organization_id, ScreenshotCapture.storage_key.is_not(None))):
        try:
            get_store().delete(key)
            n += 1
        except Exception:  # noqa: BLE001
            log.warning("could not delete a screenshot object while deleting organization %s", organization_id)
    return n


# ====================================================================== schedules
def schedule_weekly(db: Session, tenant: Tenant, now: datetime | None = None) -> int:
    """Queue captures for endpoints not captured in a week, within the tenant's daily cap."""
    now = now or _now()
    ts = tenant_settings(tenant)["screenshots"]
    if not ts.get("enabled") or ts.get("cadence") != "weekly":
        return 0
    st = status_for(db, tenant)
    if st["reason"]:
        return 0
    room = min(st["limits"]["per_tenant_daily"] - st["usage"]["captures_today"],
               st["limits"]["per_tenant_queued"] - st["usage"]["active"])
    if room <= 0:
        return 0
    recent = select(ScreenshotCapture.asset_id).where(
        ScreenshotCapture.tenant_id == tenant.id, ScreenshotCapture.created_at >= now - timedelta(days=7),
        ScreenshotCapture.status != ScreenshotStatus.CANCELLED)
    due = db.execute(select(Asset.id).where(
        Asset.tenant_id == tenant.id, Asset.asset_type.in_([t.value for t in WEB_TYPES]),
        Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE,
        Asset.id.not_in(recent)).order_by(Asset.risk_score.desc()).limit(room)).scalars().all()
    queued = 0
    for asset_id in due:
        try:
            with db.begin_nested():
                _, created = request_capture(db, tenant_id=tenant.id, asset_id=asset_id, user_id=None,
                                             trigger="scheduled")
            queued += created
        except (ScopeViolation, ValidationFailed, QuotaExceeded):
            continue
    return queued
