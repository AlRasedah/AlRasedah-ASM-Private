"""Daily attack-surface metric snapshots (risk trend, growth charts)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, Finding, MetricSnapshot, Organization
from app.models.enums import OPEN_FINDING_STATES, PRIMARY_TYPES, SHADOW_IT_STATES, AssetStatus, ScopeStatus


def snapshot_organization(db: Session, org: Organization) -> MetricSnapshot:
    from app.risk.service import organization_score

    today = datetime.now(UTC).date()
    since = datetime.now(UTC) - timedelta(days=1)
    primary = [t.value for t in PRIMARY_TYPES]
    base = select(func.count()).select_from(Asset).where(
        Asset.organization_id == org.id, Asset.asset_type.in_(primary),
        Asset.scope_status != ScopeStatus.OUT_OF_SCOPE)
    total = db.scalar(base) or 0
    active = db.scalar(base.where(Asset.status == AssetStatus.ACTIVE)) or 0
    new = db.scalar(base.where(Asset.first_seen >= since)) or 0
    unknown = db.scalar(base.where(Asset.status == AssetStatus.ACTIVE,
                                   Asset.approval_status.in_([s.value for s in SHADOW_IT_STATES]))) or 0
    sev_rows = db.execute(select(Finding.severity, func.count()).where(
        Finding.organization_id == org.id, Finding.status.in_([s.value for s in OPEN_FINDING_STATES]))
        .group_by(Finding.severity)).all()
    snap = db.execute(select(MetricSnapshot).where(MetricSnapshot.organization_id == org.id,
                                                   MetricSnapshot.day == today)).scalar_one_or_none()
    if snap is None:
        snap = MetricSnapshot(tenant_id=org.tenant_id, organization_id=org.id, day=today)
        db.add(snap)
    snap.total_assets, snap.active_assets, snap.new_assets, snap.unknown_assets = total, active, new, unknown
    snap.open_findings = {getattr(s, "value", s): c for s, c in sev_rows}
    snap.risk_score = organization_score(db, org)
    db.flush()
    return snap
