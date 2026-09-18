"""Recompute stored risk scores for an organization and emit risk-change events."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.changes import detector
from app.models import Asset, AssetEvent, AssetRelationship, Finding, Organization, Tenant
from app.models.enums import OPEN_FINDING_STATES, AssetStatus, AssetType, RelationType, RiskLevel
from app.tenants.settings import tenant_settings

from .engine import score_asset, score_finding

# parent -[relation]-> child: parents inherit their riskiest child's score.
ROLLUP = {
    RelationType.SERVES, RelationType.HAS_PORT, RelationType.RUNS_SERVICE, RelationType.RESOLVES_TO,
}
# Evaluation order: leaves first.
ORDER = [AssetType.SERVICE, AssetType.PORT, AssetType.HTTP_ENDPOINT, AssetType.IP_ADDRESS, AssetType.SUBDOMAIN,
         AssetType.DOMAIN, AssetType.ROOT_DOMAIN]


def recompute_organization(db: Session, org: Organization, *, scan_id: uuid.UUID | None = None,
                           emit_events: bool = True, baseline: bool = False) -> dict[str, int]:
    tenant = db.get(Tenant, org.tenant_id)
    cfg = tenant_settings(tenant)["risk"]
    now = datetime.now(UTC)
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.organization_id == org.id)).scalars()}
    findings = db.execute(select(Finding).where(Finding.organization_id == org.id)).scalars().all()

    by_asset: dict[uuid.UUID, list[int]] = defaultdict(list)
    counts: dict[uuid.UUID, int] = defaultdict(int)
    for f in findings:
        asset = assets.get(f.asset_id)
        if asset is None:
            continue
        r = score_finding(f, asset, cfg, now)
        f.risk_score, f.risk_level, f.risk_factors = r.score, r.level, r.factors
        if f.status in OPEN_FINDING_STATES and asset.status == AssetStatus.ACTIVE:
            by_asset[f.asset_id].append(r.score)
            counts[f.asset_id] += 1

    children: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for rel in db.execute(select(AssetRelationship).where(
            AssetRelationship.organization_id == org.id, AssetRelationship.active.is_(True),
            AssetRelationship.relation_type.in_([r.value for r in ROLLUP]))).scalars():
        children[rel.source_asset_id].append(rel.target_asset_id)

    computed: dict[uuid.UUID, int] = {}
    ordered = sorted(assets.values(), key=lambda a: ORDER.index(a.asset_type) if a.asset_type in ORDER else -1)
    changed = events = 0
    for a in ordered:
        if a.status != AssetStatus.ACTIVE:
            new_score, new_level, factors = 0, RiskLevel.INFO, []
        else:
            child_scores = [(computed[c], assets[c].value) for c in children.get(a.id, []) if c in computed]
            r = score_asset(a, by_asset.get(a.id, []), child_scores, cfg, now)
            new_score, new_level, factors = r.score, r.level, r.factors
        computed[a.id] = new_score
        old_score, old_level = a.risk_score or 0, a.risk_level
        a.open_findings = counts.get(a.id, 0)
        if new_score != old_score or new_level != old_level:
            changed += 1
            if emit_events and a.status == AssetStatus.ACTIVE and a.asset_type not in (
                    AssetType.TECHNOLOGY, AssetType.CERTIFICATE, AssetType.ASN, AssetType.CIDR):
                draft = detector.risk_changed(a.value, old_score, new_score, old_level.value, new_level.value, factors)
                if draft:
                    db.add(AssetEvent(
                        tenant_id=a.tenant_id, organization_id=org.id, asset_id=a.id, asset_type=a.asset_type,
                        asset_value=a.value, scan_id=scan_id, event_type=draft.event_type, severity=draft.severity,
                        title=draft.title, summary=draft.summary, previous_state=draft.previous,
                        new_state=draft.new, details={}, occurred_at=now, is_baseline=baseline))
                    events += 1
        a.risk_score, a.risk_level, a.risk_factors = new_score, new_level, factors
    db.flush()
    return {"assets": len(assets), "findings": len(findings), "changed": changed, "events": events}


def organization_score(db: Session, org: Organization) -> int:
    """Headline organization risk: dominated by the worst assets, damped by breadth."""
    scores = sorted((s for (s,) in db.execute(select(Asset.risk_score).where(
        Asset.organization_id == org.id, Asset.status == AssetStatus.ACTIVE, Asset.risk_score > 0))), reverse=True)
    if not scores:
        return 0
    top = scores[0]
    breadth = sum(scores[1:10]) / 10 if len(scores) > 1 else 0
    return int(min(100, round(top * 0.8 + breadth * 0.2)))
