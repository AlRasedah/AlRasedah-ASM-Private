"""Support bundles: a bounded, sanitized archive for troubleshooting, made on request.

Scope decides everything that goes in:

* **tenant** bundle (tenant administrators) — built in the tenant's session, so RLS
  confines every query to that tenant: its scans and stage timelines, cleaned stage output
  for the scans chosen, its diagnostic events, its audit actions (no IP addresses or
  values), a scanner-availability summary, application and schema versions, an allowlisted
  configuration summary. No engines, hosts, queues or other tenants.
* **platform** bundle (platform administrators) — service/scanner/queue/host health,
  recent operational events (redacted), engine/OS/database versions, an allowlisted
  platform configuration summary, and timelines of the chosen (or recently failed) scans,
  identified by tenant id.

Never included: .env files or any secret, database dumps, screenshots, raw finding
evidence, raw HTTP traffic, other tenants' data. The manifest lists the files with their
SHA-256, what was omitted, and what was truncated.

Limits: one active bundle per tenant, three per deployment, 50 MB, 120 s of collection,
7 days' retention. Archive member names are fixed in code and checked against a strict
pattern; nothing a caller supplies becomes a path.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import logging
import platform as pyplatform
import re
import time
import uuid
import zipfile
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app import __version__
from app.core.errors import Conflict, NotFound, QuotaExceeded, ValidationFailed
from app.models import AuditLog, OpsEvent, Scan, ScanStage, StorageDeletion, SupportBundle, Tenant
from app.observability import codes
from app.services import audit
from app.services.audit import Action
from app.services.storage import get_store

log = logging.getLogger(__name__)

MAX_BYTES = 50 * 1024 * 1024
MAX_SECONDS = 120
MAX_WINDOW = timedelta(days=30)
MAX_SCANS = 20
MAX_EVENTS = 5000
RETENTION = timedelta(days=7)
TENANT_ACTIVE = 1
GLOBAL_ACTIVE = 3
_MEMBER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,80}(/[a-z0-9][a-z0-9._-]{0,80})?$")

EXCLUDED = ["environment files, keys and every other secret", "database dumps", "website screenshots",
            "raw finding evidence and request/response bodies", "raw HTTP traffic"]
CATEGORIES = {
    "tenant": ["scan timelines", "stage output for the selected scans (cleaned)", "diagnostic events",
               "audit actions (no IP addresses or changed values)", "scanner availability",
               "application and schema versions", "configuration summary (allowlisted)"],
    "platform": ["service, scanner, queue and host health", "operational events (redacted)",
                 "scan timelines (by tenant id)", "application, engine, OS and database versions",
                 "configuration summary (allowlisted)"],
}


def _now() -> datetime:
    return datetime.now(UTC)


# ------------------------------------------------------------------ requests
def _window(start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    end = min(end or _now(), _now())
    start = start or end - timedelta(hours=24)
    if start >= end:
        raise ValidationFailed("The time window must end after it starts")
    if end - start > MAX_WINDOW:
        raise ValidationFailed("The time window may span at most 30 days")
    return start, end


def _scans(db: Session, scan_ids: list[uuid.UUID]) -> list[Scan]:
    """In a tenant session RLS hides other tenants' scans: an id that is not the caller's is not found."""
    if len(scan_ids) > MAX_SCANS:
        raise ValidationFailed(f"Select at most {MAX_SCANS} scans")
    found = list(db.execute(select(Scan).where(Scan.id.in_(scan_ids))).scalars()) if scan_ids else []
    if len(found) != len(set(scan_ids)):
        raise NotFound("One or more selected scans were not found")
    return found


def preview(db: Session, scope: str, start: datetime | None, end: datetime | None,
            scan_ids: list[uuid.UUID]) -> dict[str, Any]:
    start, end = _window(start, end)
    scans = _scans(db, scan_ids)
    counts: dict[str, Any] = {"scans_selected": len(scans)}
    counts["scans_in_window"] = db.scalar(select(func.count()).select_from(Scan).where(
        Scan.created_at >= start, Scan.created_at <= end)) or 0
    if scope == "tenant":
        counts["audit_actions"] = min(MAX_EVENTS, db.scalar(select(func.count()).select_from(AuditLog).where(
            AuditLog.created_at >= start, AuditLog.created_at <= end)) or 0)
    else:
        counts["operational_events"] = min(MAX_EVENTS, db.scalar(select(func.count()).select_from(OpsEvent).where(
            OpsEvent.ts >= start, OpsEvent.ts <= end)) or 0)
    return {"scope": scope, "window_start": start.isoformat(), "window_end": end.isoformat(),
            "included": CATEGORIES[scope], "excluded": EXCLUDED, "counts": counts,
            "limits": {"max_mb": MAX_BYTES // (1024 * 1024), "max_seconds": MAX_SECONDS,
                       "retention_days": RETENTION.days}}


def create(db: Session, *, scope: str, tenant_id: uuid.UUID | None, user_id: uuid.UUID | None,
           start: datetime | None, end: datetime | None, scan_ids: list[uuid.UUID]) -> SupportBundle:
    """``db`` is the caller's tenant session (tenant scope) or a system session (platform scope)."""
    start, end = _window(start, end)
    scans = _scans(db, scan_ids)
    key = f"bundles:{tenant_id or 'platform'}"
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": key})
    active = select(func.count()).select_from(SupportBundle).where(SupportBundle.status.in_(["queued", "running"]))
    mine = db.scalar(active.where(SupportBundle.tenant_id == tenant_id) if tenant_id
                     else active.where(SupportBundle.tenant_id.is_(None))) or 0
    if mine >= TENANT_ACTIVE:
        raise Conflict("A support bundle is already being generated; wait for it to finish")
    from app.db.session import system_session

    with system_session() as sdb:
        if (sdb.scalar(active) or 0) >= GLOBAL_ACTIVE:
            raise QuotaExceeded("Several support bundles are being generated right now; try again in a minute")
    b = SupportBundle(tenant_id=tenant_id, scope=scope, requested_by=user_id, window_start=start, window_end=end,
                      scan_ids=[s.id for s in scans], organization_ids=sorted({s.organization_id for s in scans}),
                      status="queued", progress=0, expires_at=_now() + RETENTION, manifest={})
    db.add(b)
    db.flush()
    audit.record(db, Action.SUPPORT_BUNDLE_CREATED, tenant_id=tenant_id, platform=tenant_id is None,
                 object_type="support_bundle", object_id=b.id,
                 new={"scope": scope, "window_start": start.isoformat(), "window_end": end.isoformat(),
                      "scans": len(scans)})
    return b


def get(db: Session, bundle_id: uuid.UUID, scope: str) -> SupportBundle:
    """Ownership: a tenant session only ever sees its own tenant's bundles (RLS); a platform
    bundle has no tenant and is looked up in a system session by platform administrators only."""
    b = db.get(SupportBundle, bundle_id)
    if b is None or b.scope != scope or (scope == "platform") != (b.tenant_id is None):
        raise NotFound("Support bundle not found")
    return b


def delete(db: Session, b: SupportBundle, user_id: uuid.UUID | None) -> None:
    """Tenant bundles: the object is recorded as a pending deletion in this transaction and
    removed by maintenance if it cannot be removed at once. Platform bundles have no tenant
    to own that record, so their object is removed first and a failure is reported."""
    if b.storage_key:
        if b.tenant_id:
            db.add(StorageDeletion(tenant_id=b.tenant_id, storage_key=b.storage_key, size=b.size or 0, attempts=0))
        else:
            try:
                get_store().delete(b.storage_key)
            except Exception as exc:  # noqa: BLE001
                raise Conflict("The bundle's file could not be deleted right now; try again") from exc
    audit.record(db, Action.SUPPORT_BUNDLE_DELETED, tenant_id=b.tenant_id, platform=b.tenant_id is None,
                 object_type="support_bundle", object_id=b.id)
    db.delete(b)
    db.flush()


def download(db: Session, b: SupportBundle, user_id: uuid.UUID | None) -> bytes:
    if b.status != "ready" or not b.storage_key:
        raise Conflict("The support bundle is not ready")
    data = get_store().get(b.storage_key)
    if b.sha256 and hashlib.sha256(data).hexdigest() != b.sha256:
        raise Conflict("The stored support bundle does not match its checksum")
    audit.record(db, Action.SUPPORT_BUNDLE_DOWNLOADED, tenant_id=b.tenant_id, platform=b.tenant_id is None,
                 object_type="support_bundle", object_id=b.id, new={"sha256": b.sha256, "size": b.size})
    return data


# ---------------------------------------------------------------- generation
class _Archive:
    def __init__(self, deadline: float) -> None:
        self.buf = io.BytesIO()
        self.zip = zipfile.ZipFile(self.buf, "w", compression=zipfile.ZIP_DEFLATED)
        self.files: list[dict[str, Any]] = []
        self.truncated: list[str] = []
        self.deadline = deadline

    def out_of_budget(self) -> bool:
        return time.monotonic() > self.deadline or self.buf.tell() > MAX_BYTES * 0.9

    def add(self, name: str, content: str | bytes) -> bool:
        if not _MEMBER.match(name) or ".." in name:
            raise ValueError(f"unsafe archive member name {name!r}")
        data = content.encode() if isinstance(content, str) else content
        if self.out_of_budget():
            self.truncated.append(f"{name}: not added (size or time limit reached)")
            return False
        self.zip.writestr(zipfile.ZipInfo(name, date_time=(2000, 1, 1, 0, 0, 0)), data,
                          compress_type=zipfile.ZIP_DEFLATED)
        self.files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        return True

    def jsonl(self, name: str, rows: list[dict[str, Any]], limit: int = MAX_EVENTS) -> None:
        if len(rows) > limit:
            self.truncated.append(f"{name}: first {limit} of {len(rows)} records")
            rows = rows[:limit]
        self.add(name, "".join(json.dumps(r, default=str, ensure_ascii=False) + "\n" for r in rows))


def _versions(platform_scope: bool, db: Session) -> dict[str, Any]:
    from app.db.migrations import expected_head

    out: dict[str, Any] = {"application": __version__, "expected_schema": expected_head()}
    with contextlib.suppress(Exception):
        out["schema"] = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
    if platform_scope:
        out["python"] = pyplatform.python_version()
        with contextlib.suppress(Exception):
            out["database_server"] = db.execute(text("SHOW server_version")).scalar()
        with contextlib.suppress(OSError):
            osr = pyplatform.freedesktop_os_release()
            out["os"] = {k: osr.get(k) for k in ("NAME", "VERSION_ID", "PRETTY_NAME")}
        out["kernel"] = pyplatform.release()
        out["machine"] = pyplatform.machine()
    return out


_CONFIG_KEYS = ("environment", "sensor_mode", "worker_pools", "scanner_isolation", "storage_backend", "log_level",
                "log_json", "intel_refresh_enabled", "allow_non_public_scope", "stage_timeout_seconds",
                "max_concurrent_scans_global", "data_region", "public_url", "session_idle_ttl_minutes")


def _config(platform_scope: bool, tenant: Tenant | None) -> dict[str, Any]:
    from app.core.config import get_settings
    from app.tenants.settings import tenant_settings

    if platform_scope:
        s = get_settings()
        return {k: getattr(s, k) for k in _CONFIG_KEYS if hasattr(s, k)}
    assert tenant is not None
    ts = tenant_settings(tenant)
    return {"plan": tenant.plan.code if tenant.plan else None, "status": tenant.status.value,
            "dedicated_scanner_pool": (tenant.worker_pool or "default") != "default",
            "screenshots": {k: (ts.get("screenshots") or {}).get(k) for k in ("enabled", "cadence")},
            "settings_sections": sorted(ts.keys())}


def _stage_output_text(db: Session, stage: ScanStage) -> str:
    from app.scans import output

    return output.as_text(f"stage {stage.position} ({stage.stage_type.value})", output.read(db, stage))


def _build(db: Session, b: SupportBundle, tenant: Tenant | None, set_progress: Any) -> _Archive:
    from app.diagnostics import views
    from app.observability import health

    plat = b.scope == "platform"
    arc = _Archive(time.monotonic() + MAX_SECONDS)
    set_progress(10)
    arc.add("versions.json", json.dumps(_versions(plat, db), indent=2, default=str))
    arc.add("config-summary.json", json.dumps(_config(plat, tenant), indent=2, default=str))
    if plat:
        arc.add("health.json", json.dumps(health.collect_platform(db), indent=2, default=str))
    else:
        assert tenant is not None
        arc.add("health.json", json.dumps(views.tenant_overview(db, tenant), indent=2, default=str))
    set_progress(30)
    if b.scan_ids:
        scans = list(db.execute(select(Scan).where(Scan.id.in_(b.scan_ids))).scalars())
    else:
        stmt = select(Scan).where(Scan.created_at >= b.window_start, Scan.created_at <= b.window_end)
        if plat:
            stmt = stmt.where(Scan.status.in_(["failed", "partial"]))
        scans = list(db.execute(stmt.order_by(Scan.created_at.desc()).limit(50)).scalars())
    names = ({t.id: t.name for t in db.execute(select(Tenant).where(Tenant.id.in_({s.tenant_id for s in scans})))
              .scalars()} if plat and scans else {})
    arc.jsonl("scans.jsonl", [views.scan_view(s, names.get(s.tenant_id, "?") if plat else None) for s in scans])
    if b.scan_ids and not plat:
        for s in scans:
            for st in sorted(s.stages, key=lambda x: x.position):
                arc.add(f"stage-output/{s.id}-{st.position}.txt", _stage_output_text(db, st))
    set_progress(60)
    if plat:
        rows = db.execute(select(OpsEvent).where(OpsEvent.ts >= b.window_start, OpsEvent.ts <= b.window_end)
                          .order_by(OpsEvent.ts.desc()).limit(MAX_EVENTS + 1)).scalars()
        arc.jsonl("operational-events.jsonl", [{
            "ts": r.ts, "level": r.level, "service": r.service, "event": r.event, "error_code": r.error_code,
            "message": r.message, "tenant_id": r.tenant_id, "request_id": r.request_id, "scan_id": r.scan_id,
            "stage_id": r.stage_id, "pool": r.pool} for r in rows])
    else:
        events: list[dict[str, Any]] = []
        page = 1
        while True:
            chunk = views.tenant_events(db, page)
            events += [e for e in chunk["items"] if e["ts"] and b.window_start.isoformat() <= e["ts"]
                       <= b.window_end.isoformat()]
            if not chunk["has_more"] or page >= views.MAX_PAGE:
                break
            page += 1
        arc.jsonl("diagnostic-events.jsonl", events)
        rows = db.execute(select(AuditLog).where(AuditLog.created_at >= b.window_start,
                                                 AuditLog.created_at <= b.window_end)
                          .order_by(AuditLog.created_at.desc()).limit(MAX_EVENTS + 1)).scalars()
        arc.jsonl("audit-actions.jsonl", [{"ts": r.created_at, "action": r.action, "actor": r.actor,
                                           "object_type": r.object_type, "object_id": r.object_id,
                                           "success": r.success, "request_id": r.request_id} for r in rows])
    set_progress(90)
    return arc


def generate(bundle_id: uuid.UUID, tenant_id: uuid.UUID | None) -> None:
    """Worker task body. Tenant bundles are built in the tenant's session (RLS)."""
    from app.db.session import new_session, system_session

    opener = (lambda: new_session(tenant_id)) if tenant_id else system_session
    with opener() as db:
        b = db.get(SupportBundle, bundle_id, with_for_update=True)
        if b is None or b.status != "queued":
            return
        b.status, b.started_at, b.progress = "running", _now(), 5
        db.commit()
    stored_key = None
    try:
        with opener() as db:
            b = db.get(SupportBundle, bundle_id)
            assert b is not None
            tenant = db.get(Tenant, tenant_id) if tenant_id else None

            def set_progress(p: int) -> None:
                with opener() as pdb:
                    row = pdb.get(SupportBundle, bundle_id)
                    if row is not None:
                        row.progress = p
                        pdb.commit()

            arc = _build(db, b, tenant, set_progress)
            created = _now()
            manifest = {
                "schema": "exteriq.support-bundle/1", "bundle_id": str(b.id), "scope": b.scope,
                "tenant_id": str(tenant_id) if tenant_id else None, "created_at": created.isoformat(),
                "application_version": __version__, "window_start": b.window_start.isoformat(),
                "window_end": b.window_end.isoformat(), "scans_selected": [str(s) for s in b.scan_ids],
                "files": list(arc.files), "included": CATEGORIES[b.scope], "omitted": EXCLUDED,
                "truncated": arc.truncated,
            }
            arc.zip.writestr(zipfile.ZipInfo("manifest.json", date_time=(2000, 1, 1, 0, 0, 0)),
                             json.dumps(manifest, indent=2), compress_type=zipfile.ZIP_DEFLATED)
            arc.zip.close()
            data = arc.buf.getvalue()
            if len(data) > MAX_BYTES:
                raise ValueError("the bundle is larger than its size limit")
            prefix = f"tenants/{tenant_id}/support" if tenant_id else "platform/support"
            stored_key = f"{prefix}/{b.id}.zip"
            get_store().put(stored_key, data, "application/zip")
            b.storage_key, b.size, b.sha256 = stored_key, len(data), hashlib.sha256(data).hexdigest()
            b.filename = f"exteriq-support-{b.scope}-{created:%Y%m%d-%H%M}-{str(b.id)[:8]}.zip"
            b.manifest = {k: manifest[k] for k in ("files", "truncated", "included", "omitted")}
            b.status, b.progress, b.finished_at = "ready", 100, _now()
            db.commit()
            stored_key = None
    except Exception as exc:  # noqa: BLE001 - recorded on the bundle; no partial file is kept
        log.warning("support bundle %s failed: %s", bundle_id, type(exc).__name__,
                    extra={"event": "support_bundle.failed", "error_code": codes.BUNDLE_FAILED,
                           "bundle_id": str(bundle_id)})
        if stored_key:
            with contextlib.suppress(Exception):
                get_store().delete(stored_key)
        with opener() as db:
            b = db.get(SupportBundle, bundle_id)
            if b is not None:
                b.status, b.error, b.finished_at = "failed", "The bundle could not be generated; see the operational " \
                                                             "events for details", _now()
                db.commit()


# ------------------------------------------------------------------- cleanup
def purge_expired(now: datetime | None = None) -> int:
    """Maintenance: expired bundles (and stale queued/running ones) are deleted with their object."""
    from app.db.session import system_session

    now = now or _now()
    n = 0
    with system_session() as db:
        stale = now - timedelta(hours=1)
        for b in db.execute(select(SupportBundle).where(
                (SupportBundle.expires_at < now)
                | (SupportBundle.status.in_(["queued", "running"]) & (SupportBundle.created_at < stale)))).scalars():
            if b.storage_key:
                try:
                    get_store().delete(b.storage_key)
                except Exception:  # noqa: BLE001
                    if b.tenant_id:
                        db.add(StorageDeletion(tenant_id=b.tenant_id, storage_key=b.storage_key, size=b.size or 0,
                                               attempts=1))
                    else:
                        continue  # retried next run
            db.delete(b)
            n += 1
        db.commit()
    return n


def queue_organization_bundles(db: Session, organization_id: uuid.UUID) -> int:
    """With an organization's deletion (same transaction): bundles holding its data go too —
    those made from its scans, and tenant-wide ones (they include every organization)."""
    rows = list(db.execute(select(SupportBundle).where(
        (SupportBundle.organization_ids.any(organization_id)) | (func.cardinality(SupportBundle.organization_ids) == 0),
        SupportBundle.tenant_id.is_not(None))).scalars())
    for b in rows:
        if b.storage_key:
            db.add(StorageDeletion(tenant_id=b.tenant_id, storage_key=b.storage_key, size=b.size or 0, attempts=0))
        db.delete(b)
    db.flush()
    return len(rows)
