"""Inventory query building shared by the API, exports and reports."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import Select, and_, exists, func, or_, select
from sqlalchemy.orm import aliased

from app.models import Asset, AssetRelationship, Finding
from app.models.enums import (
    OPEN_FINDING_STATES,
    SHADOW_IT_STATES,
    ApprovalStatus,
    AssetStatus,
    AssetType,
    Criticality,
    RelationType,
    ScopeStatus,
    Severity,
)

SORTS = {
    "risk": Asset.risk_score,
    "value": Asset.normalized_value,
    "first_seen": Asset.first_seen,
    "last_seen": Asset.last_seen,
    "status": Asset.status,
    "owner": Asset.owner,
    "findings": Asset.open_findings,
    "type": Asset.asset_type,
}


@dataclass
class AssetFilter:
    organization_id: uuid.UUID | None = None
    asset_types: list[AssetType] = field(default_factory=list)
    status: AssetStatus | None = None
    scope_statuses: list[ScopeStatus] = field(default_factory=list)
    approval: list[ApprovalStatus] = field(default_factory=list)
    unknown: bool | None = None
    owner: str | None = None
    business_unit: str | None = None
    criticality: list[Criticality] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    technology: str | None = None
    asn: str | None = None
    severity: list[Severity] = field(default_factory=list)
    risk_min: int | None = None
    risk_max: int | None = None
    first_seen_after: datetime | None = None
    first_seen_before: datetime | None = None
    last_seen_after: datetime | None = None
    q: str | None = None
    include_third_party: bool = False
    sort: str = "risk"
    order: str = "desc"


def build(f: AssetFilter) -> Select:
    stmt = select(Asset)
    conds: list[Any] = []
    if f.organization_id:
        conds.append(Asset.organization_id == f.organization_id)
    if f.asset_types:
        conds.append(Asset.asset_type.in_([t.value for t in f.asset_types]))
    if f.status:
        conds.append(Asset.status == f.status)
    if f.scope_statuses:
        conds.append(Asset.scope_status.in_([s.value for s in f.scope_statuses]))
    elif not f.include_third_party:
        conds.append(Asset.scope_status != ScopeStatus.OUT_OF_SCOPE)
    if f.approval:
        conds.append(Asset.approval_status.in_([a.value for a in f.approval]))
    if f.unknown is True:
        conds.append(Asset.approval_status.in_([a.value for a in SHADOW_IT_STATES]))
    elif f.unknown is False:
        conds.append(Asset.approval_status.not_in([a.value for a in SHADOW_IT_STATES]))
    if f.owner:
        conds.append(Asset.owner.ilike(f"%{_like(f.owner)}%"))
    if f.business_unit:
        conds.append(Asset.business_unit.ilike(f"%{_like(f.business_unit)}%"))
    if f.criticality:
        conds.append(Asset.criticality.in_([c.value for c in f.criticality]))
    if f.tags:
        conds.append(Asset.tags.overlap(f.tags))
    if f.risk_min is not None:
        conds.append(Asset.risk_score >= f.risk_min)
    if f.risk_max is not None:
        conds.append(Asset.risk_score <= f.risk_max)
    if f.first_seen_after:
        conds.append(Asset.first_seen >= f.first_seen_after)
    if f.first_seen_before:
        conds.append(Asset.first_seen <= f.first_seen_before)
    if f.last_seen_after:
        conds.append(Asset.last_seen >= f.last_seen_after)
    if f.q:
        needle = f"%{_like(f.q.strip().lower())}%"
        conds.append(or_(Asset.normalized_value.ilike(needle), Asset.owner.ilike(needle),
                         Asset.meta["title"].astext.ilike(needle)))
    if f.technology:
        tech = aliased(Asset)
        conds.append(exists(select(AssetRelationship.id).join(tech, tech.id == AssetRelationship.target_asset_id).where(
            AssetRelationship.source_asset_id == Asset.id, AssetRelationship.active.is_(True),
            AssetRelationship.relation_type == RelationType.USES_TECHNOLOGY,
            tech.normalized_value == f.technology.strip().lower())))
    if f.asn:
        asn = f.asn.strip().upper()
        asn = asn if asn.startswith("AS") else f"AS{asn}"
        ip = aliased(Asset)
        conds.append(or_(
            Asset.meta["asn"].astext == asn,
            exists(select(AssetRelationship.id).join(ip, ip.id == AssetRelationship.target_asset_id).where(
                AssetRelationship.source_asset_id == Asset.id, AssetRelationship.active.is_(True),
                AssetRelationship.relation_type == RelationType.RESOLVES_TO, ip.meta["asn"].astext == asn)),
        ))
    if f.severity:
        conds.append(exists(select(Finding.id).where(
            Finding.asset_id == Asset.id, Finding.status.in_([s.value for s in OPEN_FINDING_STATES]),
            Finding.severity.in_([s.value for s in f.severity]))))
    if conds:
        stmt = stmt.where(and_(*conds))
    col = SORTS.get(f.sort, Asset.risk_score)
    stmt = stmt.order_by(col.desc() if f.order == "desc" else col.asc(), Asset.normalized_value.asc())
    return stmt


def _like(v: str) -> str:
    return v.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def display_ips(a: Asset) -> list[str]:
    meta = a.meta or {}
    if a.asset_type in (AssetType.ROOT_DOMAIN, AssetType.DOMAIN, AssetType.SUBDOMAIN):
        dns = meta.get("dns") or {}
        return list(dns.get("a", []))[:4] + list(dns.get("aaaa", []))[:2]
    if a.asset_type == AssetType.IP_ADDRESS:
        return [a.normalized_value]
    if a.asset_type in (AssetType.PORT, AssetType.SERVICE):
        return [a.normalized_value.rsplit(":", 1)[0].strip("[]")]
    if meta.get("ip"):
        return [meta["ip"]]
    return []


def count_by(db, column, org_id: uuid.UUID | None, extra: list | None = None) -> dict[str, int]:  # type: ignore[no-untyped-def]
    q = select(column, func.count()).group_by(column)
    if org_id:
        q = q.where(Asset.organization_id == org_id)
    for c in extra or []:
        q = q.where(c)
    return {getattr(k, "value", k) if k is not None else "unknown": v for k, v in db.execute(q).all()}
