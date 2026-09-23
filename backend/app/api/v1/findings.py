from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, and_, case, func, or_, select
from sqlalchemy.orm import Session

from app.api.deps import Paging, Principal, get_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound, ValidationFailed
from app.findings import service as findings
from app.models import Asset, Finding, FindingActivity, TenantMembership, User
from app.models.enums import OPEN_FINDING_STATES, FindingCategory, FindingStatus, RiskLevel, Severity
from app.schemas.assets import AssetRef
from app.schemas.common import DAST_SOURCES, Page, paginate, source_label
from app.schemas.findings import ActivityOut, CommentCreate, FindingDetail, FindingOut, FindingStats, FindingUpdate
from app.services import audit
from app.services.audit import Action
from app.workers import dispatch

router = APIRouter(prefix="/findings", tags=["findings"])
# Severity is stored as text, so sort by rank rather than alphabetically.
_SEVERITY_RANK = case({s.value: i for i, s in enumerate(
    (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL))}, value=Finding.severity)
SORTS = {"risk": Finding.risk_score, "severity": _SEVERITY_RANK, "first_seen": Finding.first_seen,
         "last_seen": Finding.last_seen, "title": Finding.title, "status": Finding.status, "detection": Finding.source,
         "asset": select(Asset.normalized_value).where(Asset.id == Finding.asset_id).scalar_subquery()}


def finding_query(
    organization_id: uuid.UUID | None = None,
    status: list[FindingStatus] = Query(default=[]),
    open_only: bool = False,
    severity: list[Severity] = Query(default=[]),
    risk_level: list[RiskLevel] = Query(default=[]),
    category: list[FindingCategory] = Query(default=[]),
    asset_id: uuid.UUID | None = None,
    assigned_to: uuid.UUID | None = None,
    unassigned: bool | None = None,
    cve: str | None = Query(None, max_length=32),
    kev: bool | None = None,
    tag: str | None = Query(None, max_length=64),
    q: str | None = Query(None, max_length=255),
    first_seen_after: datetime | None = None,
    # Third-party reports nobody tested (e.g. Shodan CVE matches) live in their own
    # view: excluded by default, shown on their own with unverified=true.
    unverified: bool = False,
    sort: str = Query("risk", pattern="^(risk|severity|first_seen|last_seen|title|status|detection|asset)$"),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Select:
    conds = [Finding.unverified.is_(bool(unverified))]
    if organization_id:
        conds.append(Finding.organization_id == organization_id)
    if status:
        conds.append(Finding.status.in_([s.value for s in status]))
    elif open_only:
        conds.append(Finding.status.in_([s.value for s in OPEN_FINDING_STATES]))
    if severity:
        conds.append(Finding.severity.in_([s.value for s in severity]))
    if risk_level:
        conds.append(Finding.risk_level.in_([r.value for r in risk_level]))
    if category:
        conds.append(Finding.category.in_([c.value for c in category]))
    if asset_id:
        conds.append(Finding.asset_id == asset_id)
    if assigned_to:
        conds.append(Finding.assigned_to == assigned_to)
    if unassigned:
        conds.append(Finding.assigned_to.is_(None))
    if cve:
        conds.append(Finding.cve.any(cve.upper()))
    if kev is not None:
        conds.append(Finding.kev.is_(kev))
    if tag:
        conds.append(Finding.tags.any(tag.lower()))
    if first_seen_after:
        conds.append(Finding.first_seen >= first_seen_after)
    if q:
        needle = "%" + q.replace("%", "\\%").replace("_", "\\_") + "%"
        conds.append(or_(Finding.title.ilike(needle), Finding.location.ilike(needle),
                         Finding.source_finding_id.ilike(needle)))
    stmt = select(Finding)
    if conds:
        stmt = stmt.where(and_(*conds))
    col = SORTS[sort]
    return stmt.order_by(col.desc() if order == "desc" else col.asc(), Finding.last_seen.desc())


def _with_assets(db: Session, rows: list[Finding]) -> list[FindingOut]:
    ids = {f.asset_id for f in rows}
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_(ids))).scalars()} if ids else {}
    out = []
    for f in rows:
        o = FindingOut.model_validate(f)
        o.source_label = source_label(f.source)
        o.dast = f.source in DAST_SOURCES  # actively verified against the running application
        a = assets.get(f.asset_id)
        o.asset = AssetRef.model_validate(a) if a else None
        out.append(o)
    return out


@router.get("", response_model=Page[FindingOut])
def list_findings(stmt: Select = Depends(finding_query), paging: Paging = Depends(),
                  _: Principal = Depends(require(Permission.FINDINGS_READ)), db: Session = Depends(get_db)) -> Page:
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=_with_assets(db, rows), total=total, page=paging.page, page_size=paging.page_size)


@router.get("/stats", response_model=FindingStats)
def stats(organization_id: uuid.UUID | None = None, _: Principal = Depends(require(Permission.FINDINGS_READ)),
          db: Session = Depends(get_db)) -> FindingStats:
    base = [Finding.unverified.is_(False)]  # unverified third-party reports are counted separately
    if organization_id:
        base.append(Finding.organization_id == organization_id)
    open_ = [Finding.status.in_([s.value for s in OPEN_FINDING_STATES])]

    def grouped(col, *extra):  # type: ignore[no-untyped-def]
        return {getattr(k, "value", k): v for k, v in db.execute(
            select(col, func.count()).where(*base, *extra).group_by(col)).all()}

    return FindingStats(by_severity=grouped(Finding.severity, *open_), by_status=grouped(Finding.status),
                        by_category=grouped(Finding.category, *open_),
                        kev_open=db.scalar(select(func.count()).select_from(Finding).where(
                            *base, *open_, Finding.kev.is_(True))) or 0)


@router.get("/export.csv")
def export_csv(stmt: Select = Depends(finding_query), _: Principal = Depends(require(Permission.FINDINGS_READ)),
               db: Session = Depends(get_db)) -> StreamingResponse:
    rows = db.execute(stmt.limit(100_000)).scalars().all()
    assets = {a.id: a.value for a in db.execute(select(Asset).where(Asset.id.in_({f.asset_id for f in rows}))).scalars()} \
        if rows else {}
    audit.record(db, Action.DATA_EXPORTED, object_type="findings", new={"rows": len(rows), "format": "csv"})
    db.commit()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["title", "asset", "severity", "risk_score", "risk_level", "status", "category", "cve", "cvss", "epss",
                "kev", "first_seen", "last_seen", "location", "detection_source"])
    for f in rows:
        w.writerow([_safe(f.title), _safe(assets.get(f.asset_id)), f.severity.value, f.risk_score, f.risk_level.value,
                    f.status.value, f.category.value, " ".join(f.cve or []), f.cvss_score or "", f.epss_score or "",
                    "yes" if f.kev else "no", f.first_seen.isoformat(), f.last_seen.isoformat(), _safe(f.location),
                    source_label(f.source)])
    name = f"asm-findings-{datetime.now(UTC):%Y%m%d-%H%M}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


def _safe(v: str | None) -> str:
    s = v or ""
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _detail(db: Session, f: Finding) -> FindingDetail:
    base = _with_assets(db, [f])[0]
    return FindingDetail(**base.model_dump(), description=f.description, remediation=f.remediation,
                         references=f.references or [], evidence=f.evidence or {}, cwe=f.cwe or [],
                         cvss_vector=f.cvss_vector, epss_percentile=f.epss_percentile, kev_due_date=f.kev_due_date,
                         exploit_available=f.exploit_available, confidence=f.confidence,
                         occurrence_count=f.occurrence_count, notes=f.notes, accepted_until=f.accepted_until,
                         risk_factors=f.risk_factors or [],
                         # The detection's own id, without the engine prefix it is stored with.
                         source_finding_id=f.source_finding_id.split(":", 1)[-1])


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: uuid.UUID, _: Principal = Depends(require(Permission.FINDINGS_READ)),
                db: Session = Depends(get_db)) -> FindingDetail:
    f = db.get(Finding, finding_id)
    if f is None:
        raise NotFound("Finding not found")
    return _detail(db, f)


@router.patch("/{finding_id}", response_model=FindingDetail)
def update(finding_id: uuid.UUID, body: FindingUpdate, principal: Principal = Depends(require(Permission.FINDINGS_WRITE)),
           db: Session = Depends(get_db)) -> FindingDetail:
    changes = body.model_dump(exclude_unset=True)
    if "assigned_to" in changes and changes["assigned_to"] is not None:
        member = db.execute(select(TenantMembership).where(TenantMembership.user_id == changes["assigned_to"],
                                                           TenantMembership.is_active.is_(True))).scalar_one_or_none()
        if member is None:
            raise ValidationFailed("Assignee must be an active member of this tenant")
    f = findings.update_finding(db, finding_id, changes, user_id=principal.user_id,
                                can_accept_risk=principal.can(Permission.FINDINGS_ACCEPT_RISK))
    db.commit()
    if "status" in changes:
        dispatch.recompute_risk(f.tenant_id, f.organization_id)
    return _detail(db, f)


@router.get("/{finding_id}/activity", response_model=list[ActivityOut])
def activity(finding_id: uuid.UUID, _: Principal = Depends(require(Permission.FINDINGS_READ)),
             db: Session = Depends(get_db)) -> list[ActivityOut]:
    if db.get(Finding, finding_id) is None:
        raise NotFound("Finding not found")
    rows = db.execute(select(FindingActivity, User.email).outerjoin(User, User.id == FindingActivity.user_id)
                      .where(FindingActivity.finding_id == finding_id).order_by(FindingActivity.created_at.desc())).all()
    assignee_ids = {uuid.UUID(v) for act, _email in rows
                    if act.activity_type == "assignment" and (v := (act.new or {}).get("assigned_to"))}
    names = {uid: name or mail for uid, name, mail in db.execute(
        select(User.id, User.full_name, User.email).where(User.id.in_(assignee_ids)))} if assignee_ids else {}
    out = []
    for act, email in rows:
        o = ActivityOut.model_validate(act)
        o.user_email = email
        if act.activity_type == "assignment":
            new_id = (act.new or {}).get("assigned_to")
            o.summary = (f"Assigned to {names.get(uuid.UUID(new_id), 'a former member')}" if new_id else "Unassigned")
        out.append(o)
    return out


@router.post("/{finding_id}/comments", response_model=ActivityOut, status_code=201)
def comment(finding_id: uuid.UUID, body: CommentCreate, principal: Principal = Depends(require(Permission.FINDINGS_WRITE)),
            db: Session = Depends(get_db)) -> ActivityOut:
    act = findings.add_comment(db, finding_id, principal.user_id, body.comment)
    db.commit()
    o = ActivityOut.model_validate(act)
    o.user_email = principal.email
    return o
