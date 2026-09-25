"""Periodic housekeeping: time-based inactivity, certificate expiry alerts,
risk-acceptance expiry, scheduled scans, retention."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.changes import detector
from app.core.config import get_settings
from app.core.errors import AppError
from app.db.session import new_session, system_session
from app.findings.service import _activity
from app.models import (
    Asset,
    AssetEvent,
    AssetObservation,
    Finding,
    Organization,
    ScanArtifact,
    ScanSchedule,
    Tenant,
)
from app.models.enums import AssetStatus, AssetType, EventType, FindingStatus, ScanTrigger, Severity, TenantStatus
from app.scans import orchestrator
from app.scans.schedules import next_run
from app.services.storage import get_store
from app.tenants.settings import tenant_settings

log = logging.getLogger(__name__)
NO_AGE_OUT = {AssetType.ROOT_DOMAIN, AssetType.TECHNOLOGY, AssetType.ASN, AssetType.CIDR}


def active_tenants() -> list[uuid.UUID]:
    with system_session() as db:
        return [t for (t,) in db.execute(select(Tenant.id).where(Tenant.status == TenantStatus.ACTIVE))]


def _event(db: Session, a: Asset, draft: detector.EventDraft, now: datetime) -> None:
    db.add(AssetEvent(tenant_id=a.tenant_id, organization_id=a.organization_id, asset_id=a.id, asset_type=a.asset_type,
                      asset_value=a.value, event_type=draft.event_type, severity=draft.severity, title=draft.title,
                      summary=draft.summary, previous_state=draft.previous, new_state=draft.new,
                      details=draft.details, occurred_at=now))


def age_out_assets(db: Session, tenant: Tenant, now: datetime) -> int:
    days = int(tenant_settings(tenant)["inactivity"].get("max_age_days", 30))
    cutoff = now - timedelta(days=days)
    rows = db.execute(select(Asset).where(Asset.status == AssetStatus.ACTIVE, Asset.last_seen < cutoff,
                                          Asset.asset_type.not_in([t.value for t in NO_AGE_OUT]),
                                          Asset.source != "scope")).scalars().all()
    for a in rows:
        a.status = AssetStatus.INACTIVE
        a.inactive_since = now
        if a.asset_type not in (AssetType.CERTIFICATE, AssetType.DNS_RECORD):
            draft = detector.EventDraft(EventType.ASSET_DISAPPEARED, Severity.INFO, f"{a.value} not observed for {days} days",
                                        new={"last_seen": a.last_seen.isoformat()})
            _event(db, a, draft, now)
    return len(rows)


def certificate_alerts(db: Session, now: datetime) -> int:
    count = 0
    for a in db.execute(select(Asset).where(Asset.asset_type == AssetType.CERTIFICATE,
                                            Asset.status == AssetStatus.ACTIVE)).scalars():
        meta = dict(a.meta or {})
        na = meta.get("not_after")
        try:
            exp = datetime.fromisoformat(str(na).replace("Z", "+00:00")) if na else None
        except ValueError:
            continue
        if exp is None:
            continue
        exp = exp if exp.tzinfo else exp.replace(tzinfo=UTC)
        res = detector.certificate_expiry(a.value, meta.get("subject_cn"), (exp - now).days,
                                          list(meta.get("expiry_alerts") or []))
        if res:
            draft, threshold = res
            _event(db, a, draft, now)
            meta["expiry_alerts"] = sorted(set(meta.get("expiry_alerts") or []) | {threshold})
            a.meta = meta
            count += 1
    return count


def expire_risk_acceptance(db: Session, now: datetime) -> int:
    rows = db.execute(select(Finding).where(Finding.status == FindingStatus.ACCEPTED_RISK,
                                            Finding.accepted_until.is_not(None), Finding.accepted_until < now)).scalars().all()
    for f in rows:
        _activity(db, f, "reopened", previous={"status": "accepted_risk"}, new={"status": "reopened"},
                  comment="Risk acceptance expired.")
        f.status = FindingStatus.REOPENED
        f.accepted_until = None
        db.add(AssetEvent(tenant_id=f.tenant_id, organization_id=f.organization_id, asset_id=f.asset_id, finding_id=f.id,
                          event_type=EventType.VULNERABILITY_REOPENED, severity=f.severity,
                          title=f"Risk acceptance expired: {f.title}", details={}, occurred_at=now))
    return len(rows)


def run_tenant_maintenance() -> dict[str, int]:
    now = datetime.now(UTC)
    stats = {"aged_out": 0, "certificate_alerts": 0, "acceptance_expired": 0}
    for tid in active_tenants():
        with new_session(tid) as db:
            tenant = db.get(Tenant, tid)
            stats["aged_out"] += age_out_assets(db, tenant, now)
            stats["certificate_alerts"] += certificate_alerts(db, now)
            stats["acceptance_expired"] += expire_risk_acceptance(db, now)
            db.commit()
    return stats


def purge_retention() -> dict[str, int]:
    s = get_settings()
    now = datetime.now(UTC)
    removed = {"artifacts": 0, "observations": 0}
    with system_session() as db:
        store = get_store()
        for art in db.execute(select(ScanArtifact).where(ScanArtifact.expires_at < now)).scalars().all():
            try:
                store.delete(art.storage_key)
            except OSError:
                log.warning("could not delete artifact %s", art.storage_key)
            db.delete(art)
            removed["artifacts"] += 1
        res = db.execute(delete(AssetObservation).where(
            AssetObservation.observed_at < now - timedelta(days=s.observation_retention_days)))
        removed["observations"] = res.rowcount or 0
        from app.observability import opsdb

        removed["ops_events"] = opsdb.prune(db, now)
        db.commit()
    from app.diagnostics.bundles import purge_expired

    removed["support_bundles"] = purge_expired(now)
    with system_session() as db:
        db.commit()
        tenant_ids = list(db.execute(select(Tenant.id)).scalars())
    # Website screenshots: every tenant, suspended ones included (their storage still counts).
    from app.screenshots.service import apply_retention

    for tid in tenant_ids:
        with new_session(tid) as tdb:
            for k, v in apply_retention(tdb, tid, now).items():
                removed[k] = removed.get(k, 0) + v
            tdb.commit()
    return removed


def due_schedules(now: datetime | None = None) -> list[tuple[uuid.UUID, uuid.UUID]]:
    now = now or datetime.now(UTC)
    with system_session() as db:
        rows = db.execute(select(ScanSchedule.tenant_id, ScanSchedule.id)
                          .join(Tenant, Tenant.id == ScanSchedule.tenant_id)
                          .where(ScanSchedule.enabled.is_(True), ScanSchedule.next_run_at <= now,
                                 Tenant.status == TenantStatus.ACTIVE)).all()
    return [(t, i) for t, i in rows]


def fire_schedule(tenant_id: uuid.UUID, schedule_id: uuid.UUID) -> uuid.UUID | None:
    """Create the scheduled scan and advance next_run_at. Returns the scan id (if created)."""
    now = datetime.now(UTC)
    with new_session(tenant_id) as db:
        sched = db.execute(select(ScanSchedule).where(ScanSchedule.id == schedule_id).with_for_update(skip_locked=True)
                           ).scalar_one_or_none()
        if sched is None or not sched.enabled or (sched.next_run_at and sched.next_run_at > now):
            return None
        sched.next_run_at = next_run(sched.cron, sched.timezone, now)
        sched.last_run_at = now
        scan_id = None
        org = db.get(Organization, sched.organization_id)
        if org is not None and org.is_active:
            try:
                scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=sched.organization_id,
                                                profile_id=sched.profile_id, trigger=ScanTrigger.SCHEDULED,
                                                schedule_id=sched.id)
                sched.last_scan_id = scan.id
                scan_id = scan.id
            except AppError as exc:
                log.warning("scheduled scan %s not started: %s", schedule_id, exc.message)
        db.commit()
        return scan_id
