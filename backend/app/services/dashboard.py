"""Dashboard aggregations (also reused by reports)."""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from app.models import Asset, AssetEvent, AssetRelationship, Finding, MetricSnapshot, Organization
from app.models.enums import (
    OPEN_FINDING_STATES,
    PRIMARY_TYPES,
    SHADOW_IT_STATES,
    AssetStatus,
    AssetType,
    EventType,
    RelationType,
    ScopeStatus,
)
from app.risk.service import organization_score


def _org(q, org_id: uuid.UUID | None, col=Asset.organization_id):  # type: ignore[no-untyped-def]
    return q.where(col == org_id) if org_id else q


def _asset_row(a: Asset) -> dict[str, Any]:
    return {"id": str(a.id), "asset_type": a.asset_type.value, "value": a.value, "risk_score": a.risk_score,
            "risk_level": a.risk_level.value, "open_findings": a.open_findings, "status": a.status.value,
            "approval_status": a.approval_status.value, "first_seen": a.first_seen.isoformat()}


def _event_row(e: AssetEvent) -> dict[str, Any]:
    return {"id": str(e.id), "event_type": e.event_type.value, "severity": e.severity.value, "title": e.title,
            "asset_id": str(e.asset_id) if e.asset_id else None, "asset_value": e.asset_value,
            "occurred_at": e.occurred_at.isoformat(), "acknowledged": e.acknowledged}


def summary(db: Session, org_id: uuid.UUID | None = None) -> dict[str, Any]:
    now = datetime.now(UTC)
    primary = [t.value for t in PRIMARY_TYPES]
    in_scope = [Asset.asset_type.in_(primary), Asset.scope_status != ScopeStatus.OUT_OF_SCOPE]

    def count(*conds) -> int:  # type: ignore[no-untyped-def]
        return db.scalar(_org(select(func.count()).select_from(Asset).where(*in_scope, *conds), org_id)) or 0

    open_f = Finding.status.in_([s.value for s in OPEN_FINDING_STATES])
    sev = {getattr(k, "value", k): v for k, v in db.execute(
        _org(select(Finding.severity, func.count()).where(open_f).group_by(Finding.severity), org_id,
             Finding.organization_id)).all()}

    totals = {
        "total_assets": count(),
        "active_assets": count(Asset.status == AssetStatus.ACTIVE),
        "new_assets_7d": count(Asset.first_seen >= now - timedelta(days=7)),
        "unknown_assets": count(Asset.status == AssetStatus.ACTIVE,
                                Asset.approval_status.in_([s.value for s in SHADOW_IT_STATES])),
        "critical_findings": sev.get("critical", 0),
        "high_findings": sev.get("high", 0),
        "kev_findings": db.scalar(_org(select(func.count()).select_from(Finding).where(open_f, Finding.kev.is_(True)),
                                       org_id, Finding.organization_id)) or 0,
        "changes_24h": db.scalar(_org(select(func.count()).select_from(AssetEvent).where(
            AssetEvent.is_baseline.is_(False), AssetEvent.occurred_at >= now - timedelta(days=1)), org_id,
            AssetEvent.organization_id)) or 0,
    }
    orgs = [db.get(Organization, org_id)] if org_id else db.execute(select(Organization)).scalars().all()
    totals["risk_score"] = max((organization_score(db, o) for o in orgs if o), default=0)

    active = [Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE]
    exposed_types = [AssetType.SUBDOMAIN.value, AssetType.ROOT_DOMAIN.value, AssetType.HTTP_ENDPOINT.value,
                     AssetType.IP_ADDRESS.value, AssetType.PORT.value]
    most_exposed = db.execute(_org(select(Asset).where(*active, Asset.asset_type.in_(exposed_types),
                                                       Asset.risk_score > 0)
                                   .order_by(Asset.risk_score.desc()).limit(10), org_id)).scalars().all()
    top_vulnerable = db.execute(_org(select(Asset).where(*active, Asset.open_findings > 0)
                                     .order_by(Asset.open_findings.desc(), Asset.risk_score.desc()).limit(10),
                                     org_id)).scalars().all()
    recent = db.execute(_org(select(AssetEvent).where(AssetEvent.is_baseline.is_(False),
                                                      AssetEvent.event_type != EventType.SCAN_COMPLETED)
                             .order_by(AssetEvent.occurred_at.desc()).limit(12), org_id,
                             AssetEvent.organization_id)).scalars().all()
    opened = db.execute(_org(select(AssetEvent).where(AssetEvent.event_type == EventType.PORT_OPENED)
                             .order_by(AssetEvent.occurred_at.desc()).limit(10), org_id,
                             AssetEvent.organization_id)).scalars().all()

    certs = []
    for a in db.execute(_org(select(Asset).where(Asset.asset_type == AssetType.CERTIFICATE,
                                                 Asset.status == AssetStatus.ACTIVE), org_id)).scalars():
        na = (a.meta or {}).get("not_after")
        try:
            exp = datetime.fromisoformat(str(na).replace("Z", "+00:00")) if na else None
        except ValueError:
            exp = None
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        if exp and exp <= now + timedelta(days=30):
            certs.append({"id": str(a.id), "subject": (a.meta or {}).get("subject_cn") or a.value[:16],
                          "issuer": (a.meta or {}).get("issuer_cn"), "not_after": exp.isoformat(),
                          "days_left": (exp - now).days})
    certs.sort(key=lambda c: c["days_left"])

    types = {getattr(k, "value", k): v for k, v in db.execute(_org(select(Asset.asset_type, func.count()).where(
        *active).group_by(Asset.asset_type), org_id)).all()}

    tech = aliased(Asset)
    technologies = [{"name": n, "count": c} for n, c in db.execute(
        _org(select(tech.normalized_value, func.count(AssetRelationship.id))
             .join(AssetRelationship, AssetRelationship.target_asset_id == tech.id)
             .where(tech.asset_type == AssetType.TECHNOLOGY, AssetRelationship.active.is_(True),
                    AssetRelationship.relation_type == RelationType.USES_TECHNOLOGY)
             .group_by(tech.normalized_value).order_by(func.count(AssetRelationship.id).desc()).limit(12),
             org_id, tech.organization_id)).all()]

    asns: dict[str, dict[str, Any]] = {}
    providers: dict[str, int] = defaultdict(int)
    for meta in db.execute(_org(select(Asset.meta).where(Asset.asset_type == AssetType.IP_ADDRESS, *active),
                                org_id)).scalars():
        meta = meta or {}
        if meta.get("asn"):
            row = asns.setdefault(meta["asn"], {"asn": meta["asn"], "name": meta.get("as_name"), "count": 0})
            row["count"] += 1
        providers[meta.get("hosting_provider") or "other"] += 1
    for meta in db.execute(_org(select(Asset.meta).where(Asset.asset_type == AssetType.CLOUD_RESOURCE, *active),
                                org_id)).scalars():
        providers[(meta or {}).get("provider") or "other"] += 1

    return {
        "totals": totals,
        "findings_by_severity": {k: sev.get(k, 0) for k in ("critical", "high", "medium", "low", "info")},
        "asset_types": types,
        "most_exposed_assets": [_asset_row(a) for a in most_exposed],
        "top_vulnerable_assets": [_asset_row(a) for a in top_vulnerable],
        "recent_changes": [_event_row(e) for e in recent],
        "recently_opened_services": [_event_row(e) for e in opened],
        "expiring_certificates": certs[:10],
        "technologies": technologies,
        "asn_distribution": sorted(asns.values(), key=lambda r: -r["count"])[:10],
        "hosting_distribution": [{"provider": k, "count": v} for k, v in sorted(providers.items(), key=lambda x: -x[1])],
    }


def trends(db: Session, org_id: uuid.UUID | None = None, days: int = 30) -> list[dict[str, Any]]:
    start = date.today() - timedelta(days=days - 1)
    q = select(MetricSnapshot).where(MetricSnapshot.day >= start).order_by(MetricSnapshot.day)
    if org_id:
        q = q.where(MetricSnapshot.organization_id == org_id)
    by_day: dict[date, dict[str, Any]] = {}
    for s in db.execute(q).scalars():
        row = by_day.setdefault(s.day, {"day": s.day.isoformat(), "total_assets": 0, "active_assets": 0,
                                        "new_assets": 0, "unknown_assets": 0, "risk_score": 0,
                                        "critical": 0, "high": 0, "medium": 0, "low": 0})
        row["total_assets"] += s.total_assets
        row["active_assets"] += s.active_assets
        row["new_assets"] += s.new_assets
        row["unknown_assets"] += s.unknown_assets
        row["risk_score"] = max(row["risk_score"], s.risk_score)
        for k in ("critical", "high", "medium", "low"):
            row[k] += int((s.open_findings or {}).get(k, 0))
    return [by_day[d] for d in sorted(by_day)]
