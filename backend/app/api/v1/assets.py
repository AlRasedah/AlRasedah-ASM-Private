from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, aliased

from app.api.deps import Paging, Principal, get_db, require
from app.assets.queries import AssetFilter, build, display_ips
from app.auth.permissions import Permission
from app.core.errors import NotFound
from app.models import Asset, AssetEvent, AssetObservation, AssetRelationship
from app.models.enums import (
    ApprovalStatus,
    AssetStatus,
    AssetType,
    Criticality,
    EventType,
    RelationType,
    ScopeStatus,
    Severity,
)
from app.schemas.assets import (
    AssetBulkUpdate,
    AssetDetail,
    AssetFacets,
    AssetOut,
    AssetRef,
    AssetUpdate,
    EventOut,
    FacetCount,
    ObservationOut,
    RelatedAsset,
)
from app.schemas.common import Page, paginate, source_label
from app.services import audit
from app.services.audit import Action
from app.workers import dispatch

router = APIRouter(prefix="/assets", tags=["assets"])


def asset_filter(
    organization_id: uuid.UUID | None = None,
    asset_type: list[AssetType] = Query(default=[]),
    status: AssetStatus | None = None,
    scope_status: list[ScopeStatus] = Query(default=[]),
    approval: list[ApprovalStatus] = Query(default=[]),
    unknown: bool | None = None,
    owner: str | None = Query(None, max_length=200),
    business_unit: str | None = Query(None, max_length=200),
    criticality: list[Criticality] = Query(default=[]),
    tag: list[str] = Query(default=[]),
    technology: str | None = Query(None, max_length=128),
    asn: str | None = Query(None, max_length=16),
    severity: list[Severity] = Query(default=[]),
    risk_min: int | None = Query(None, ge=0, le=100),
    risk_max: int | None = Query(None, ge=0, le=100),
    first_seen_after: datetime | None = None,
    first_seen_before: datetime | None = None,
    last_seen_after: datetime | None = None,
    q: str | None = Query(None, max_length=255),
    include_third_party: bool = False,
    sort: str = Query("risk", pattern="^(risk|value|first_seen|last_seen|findings|type|status|owner)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> AssetFilter:
    return AssetFilter(organization_id=organization_id, asset_types=asset_type, status=status,
                       scope_statuses=scope_status, approval=approval, unknown=unknown, owner=owner,
                       business_unit=business_unit, criticality=criticality, tags=[t.lower() for t in tag],
                       technology=technology, asn=asn, severity=severity, risk_min=risk_min, risk_max=risk_max,
                       first_seen_after=first_seen_after, first_seen_before=first_seen_before,
                       last_seen_after=last_seen_after, q=q, include_third_party=include_third_party, sort=sort,
                       order=order)


def to_out(a: Asset) -> AssetOut:
    out = AssetOut.model_validate(a)
    out.ips = display_ips(a)
    out.source_label = source_label(a.source)
    out.title = (a.meta or {}).get("title") or (a.meta or {}).get("subject_cn")
    return out


@router.get("", response_model=Page[AssetOut])
def list_assets(f: AssetFilter = Depends(asset_filter), paging: Paging = Depends(),
                _: Principal = Depends(require(Permission.ASSETS_READ)), db: Session = Depends(get_db)) -> Page[AssetOut]:
    rows, total = paginate(db, build(f), paging.page, paging.page_size)
    return Page(items=[to_out(a) for a in rows], total=total, page=paging.page, page_size=paging.page_size)


@router.get("/facets", response_model=AssetFacets)
def facets(organization_id: uuid.UUID | None = None, _: Principal = Depends(require(Permission.ASSETS_READ)),
           db: Session = Depends(get_db)) -> AssetFacets:
    base = [Asset.scope_status != ScopeStatus.OUT_OF_SCOPE]
    if organization_id:
        base.append(Asset.organization_id == organization_id)

    def grouped(col, *extra, limit: int = 100) -> list[FacetCount]:  # type: ignore[no-untyped-def]
        rows = db.execute(select(col, func.count()).where(*base, *extra).group_by(col)
                          .order_by(func.count().desc()).limit(limit)).all()
        return [FacetCount(value=str(getattr(v, "value", v)), count=c) for v, c in rows if v not in (None, "")]

    tech = aliased(Asset)
    tech_rows = db.execute(
        select(tech.normalized_value, func.count(AssetRelationship.id))
        .join(AssetRelationship, AssetRelationship.target_asset_id == tech.id)
        .where(tech.asset_type == AssetType.TECHNOLOGY, AssetRelationship.active.is_(True),
               *([tech.organization_id == organization_id] if organization_id else []))
        .group_by(tech.normalized_value).order_by(func.count(AssetRelationship.id).desc()).limit(100)).all()
    tag_rows = db.execute(select(func.unnest(Asset.tags).label("t"), func.count()).where(*base)
                          .group_by("t").order_by(func.count().desc()).limit(100)).all()
    return AssetFacets(
        asset_types=grouped(Asset.asset_type, Asset.status == AssetStatus.ACTIVE),
        statuses=grouped(Asset.status),
        approval=grouped(Asset.approval_status, Asset.status == AssetStatus.ACTIVE),
        technologies=[FacetCount(value=v, count=c) for v, c in tech_rows],
        asns=grouped(Asset.meta["asn"].astext, Asset.asset_type == AssetType.IP_ADDRESS,
                     Asset.status == AssetStatus.ACTIVE),
        owners=grouped(Asset.owner),
        business_units=grouped(Asset.business_unit),
        tags=[FacetCount(value=v, count=c) for v, c in tag_rows],
    )


@router.get("/export.csv")
def export_csv(f: AssetFilter = Depends(asset_filter), _: Principal = Depends(require(Permission.ASSETS_READ)),
               db: Session = Depends(get_db)) -> StreamingResponse:
    rows = db.execute(build(f).limit(100_000)).scalars().all()
    audit.record(db, Action.DATA_EXPORTED, object_type="assets", new={"rows": len(rows), "format": "csv"})
    db.commit()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["asset", "type", "ip", "status", "scope", "approval", "owner", "business_unit", "criticality",
                "first_seen", "last_seen", "risk_score", "risk_level", "open_findings", "tags"])
    for a in rows:
        w.writerow([_csv_safe(a.value), a.asset_type.value, " ".join(display_ips(a)), a.status.value,
                    a.scope_status.value, a.approval_status.value, _csv_safe(a.owner), _csv_safe(a.business_unit),
                    a.criticality.value, a.first_seen.isoformat(), a.last_seen.isoformat(), a.risk_score,
                    a.risk_level.value, a.open_findings, _csv_safe(" ".join(a.tags or []))])
    name = f"asm-assets-{datetime.now(UTC):%Y%m%d-%H%M}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _csv_safe(v: str | None) -> str:
    """Neutralize spreadsheet formula injection."""
    s = v or ""
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _get(db: Session, asset_id: uuid.UUID) -> Asset:
    a = db.get(Asset, asset_id)
    if a is None:
        raise NotFound("Asset not found")
    return a


def _relationships(db: Session, asset: Asset, limit: int = 500) -> list[RelatedAsset]:
    other = aliased(Asset)
    out: list[RelatedAsset] = []
    for direction, mine, theirs in (("out", AssetRelationship.source_asset_id, AssetRelationship.target_asset_id),
                                    ("in", AssetRelationship.target_asset_id, AssetRelationship.source_asset_id)):
        rows = db.execute(select(AssetRelationship, other).join(other, other.id == theirs)
                          .where(mine == asset.id).order_by(AssetRelationship.active.desc(),
                                                            AssetRelationship.last_seen.desc()).limit(limit)).all()
        for rel, o in rows:
            out.append(RelatedAsset(relation=rel.relation_type, direction=direction, active=rel.active,
                                    first_seen=rel.first_seen, last_seen=rel.last_seen, attributes=rel.attributes or {},
                                    asset=AssetRef.model_validate(o)))
    return out


@router.get("/{asset_id}", response_model=AssetDetail)
def get_asset(asset_id: uuid.UUID, _: Principal = Depends(require(Permission.ASSETS_READ)),
              db: Session = Depends(get_db)) -> AssetDetail:
    a = _get(db, asset_id)
    base = to_out(a)
    detail = AssetDetail(**base.model_dump(), normalized_value=a.normalized_value, meta=a.meta or {}, notes=a.notes,
                         risk_factors=a.risk_factors or [], discovered_at=a.discovered_at,
                         last_scanned_at=a.last_scanned_at, inactive_since=a.inactive_since,
                         missed_count=a.missed_count, discovery_method=a.discovery_method,
                         # Capability labels only: never the engine names stored on the row.
                         sources=sorted({source_label(s) or "Scan" for s in (a.sources or [])}))
    detail.relationships = _relationships(db, a)
    return detail


@router.get("/{asset_id}/observations", response_model=Page[ObservationOut])
def observations(asset_id: uuid.UUID, paging: Paging = Depends(), _: Principal = Depends(require(Permission.ASSETS_READ)),
                 db: Session = Depends(get_db)) -> Page[ObservationOut]:
    _get(db, asset_id)
    stmt = select(AssetObservation).where(AssetObservation.asset_id == asset_id).order_by(AssetObservation.observed_at.desc())
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    items = []
    for r in rows:
        o = ObservationOut.model_validate(r)
        o.source_label = source_label(r.source)
        items.append(o)
    return Page(items=items, total=total, page=paging.page, page_size=paging.page_size)


TIMELINE_CHILD_RELATIONS = (RelationType.SERVES, RelationType.HAS_PORT, RelationType.RUNS_SERVICE,
                            RelationType.RESOLVES_TO, RelationType.USES_TECHNOLOGY)


@router.get("/{asset_id}/timeline", response_model=Page[EventOut])
def timeline(asset_id: uuid.UUID, paging: Paging = Depends(), include_baseline: bool = True,
             _: Principal = Depends(require(Permission.ASSETS_READ)), db: Session = Depends(get_db)) -> Page[EventOut]:
    """Chronological changes of this asset and the assets directly beneath it."""
    a = _get(db, asset_id)
    child_ids = select(AssetRelationship.target_asset_id).where(
        AssetRelationship.source_asset_id == a.id,
        AssetRelationship.relation_type.in_([r.value for r in TIMELINE_CHILD_RELATIONS]))
    grandchild_ids = select(AssetRelationship.target_asset_id).where(
        AssetRelationship.source_asset_id.in_(child_ids),
        AssetRelationship.relation_type.in_([RelationType.HAS_PORT.value, RelationType.RUNS_SERVICE.value]))
    stmt = select(AssetEvent).where(or_(AssetEvent.asset_id == a.id, AssetEvent.asset_id.in_(child_ids),
                                        AssetEvent.asset_id.in_(grandchild_ids)))
    if not include_baseline:
        stmt = stmt.where(AssetEvent.is_baseline.is_(False))
    stmt = stmt.order_by(AssetEvent.occurred_at.desc())
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=[EventOut.model_validate(r) for r in rows], total=total, page=paging.page,
                page_size=paging.page_size)


def _apply_update(db: Session, a: Asset, changes: dict, principal: Principal, add_tags: list[str] | None = None) -> bool:
    before = {"owner": a.owner, "business_unit": a.business_unit, "criticality": a.criticality.value,
              "approval_status": a.approval_status.value, "tags": list(a.tags or []), "notes": a.notes}
    for k, v in changes.items():
        if k == "tags" and v is None:
            continue
        setattr(a, k, v)
    if add_tags:
        a.tags = sorted(set(a.tags or []) | {t.strip().lower()[:64] for t in add_tags if t.strip()})
    after = {"owner": a.owner, "business_unit": a.business_unit, "criticality": a.criticality.value,
             "approval_status": a.approval_status.value, "tags": list(a.tags or []), "notes": a.notes}
    prev, new = audit.diff(before, after)
    if not new:
        return False
    now = datetime.now(UTC)
    if "owner" in new or "business_unit" in new:
        db.add(AssetEvent(tenant_id=a.tenant_id, organization_id=a.organization_id, asset_id=a.id,
                          asset_type=a.asset_type, asset_value=a.value, event_type=EventType.OWNERSHIP_CHANGED,
                          severity=Severity.INFO, title=f"Ownership updated for {a.value}",
                          previous_state={k: prev.get(k) for k in ("owner", "business_unit") if k in prev},
                          new_state={k: new.get(k) for k in ("owner", "business_unit") if k in new},
                          details={"by": principal.email}, occurred_at=now, notified=True))
    if "approval_status" in new:
        db.add(AssetEvent(tenant_id=a.tenant_id, organization_id=a.organization_id, asset_id=a.id,
                          asset_type=a.asset_type, asset_value=a.value, event_type=EventType.APPROVAL_CHANGED,
                          severity=Severity.INFO, title=f"{a.value} marked {a.approval_status.value.replace('_', ' ')}",
                          previous_state={"approval_status": prev["approval_status"]},
                          new_state={"approval_status": new["approval_status"]}, details={"by": principal.email},
                          occurred_at=now, notified=True))
    audit.record(db, Action.ASSET_UPDATED, object_type="asset", object_id=a.id, previous=prev, new=new)
    return True


@router.patch("/{asset_id}", response_model=AssetDetail)
def update_asset(asset_id: uuid.UUID, body: AssetUpdate, principal: Principal = Depends(require(Permission.ASSETS_WRITE)),
                 db: Session = Depends(get_db)) -> AssetDetail:
    a = _get(db, asset_id)
    changed = _apply_update(db, a, body.model_dump(exclude_unset=True), principal)
    db.commit()
    if changed and {"criticality", "approval_status"} & body.model_fields_set:
        dispatch.recompute_risk(a.tenant_id, a.organization_id)
    return get_asset(asset_id, principal, db)


@router.post("/bulk-update", response_model=dict)
def bulk_update(body: AssetBulkUpdate, principal: Principal = Depends(require(Permission.ASSETS_WRITE)),
                db: Session = Depends(get_db)) -> dict:
    assets = db.execute(select(Asset).where(Asset.id.in_(body.asset_ids))).scalars().all()
    changes = body.changes.model_dump(exclude_unset=True)
    updated = sum(_apply_update(db, a, changes, principal, body.add_tags) for a in assets)
    db.commit()
    for org_id in {a.organization_id for a in assets}:
        dispatch.recompute_risk(principal.require_tenant(), org_id)
    return {"updated": updated, "requested": len(body.asset_ids)}
