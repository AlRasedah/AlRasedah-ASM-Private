"""Threat Center: tenant views of the advisory catalog, and its platform administration."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from app.api.deps import Paging, Principal, get_db, get_system_db, require
from app.api.v1.assets import _csv_safe
from app.auth.permissions import Permission
from app.core.errors import NotFound
from app.models import (
    Asset,
    Finding,
    ThreatAdvisory,
    ThreatAdvisoryVersion,
    ThreatCheck,
    ThreatCheckRun,
    ThreatMatch,
    VulnIntel,
)
from app.models.enums import AFFECTED_ASSESSMENTS, AdvisoryStatus, Assessment, ScanTrigger
from app.schemas.assets import AssetRef
from app.schemas.common import Message, Page, paginate
from app.schemas.threats import (
    AdvisoryAdminOut,
    AdvisoryCreate,
    AdvisoryDetail,
    AdvisorySummary,
    CheckAdminIn,
    CheckAdminOut,
    CheckInfo,
    CheckRequest,
    CheckRunOut,
    CveIntel,
    FeedSettingsIn,
    FindingRef,
    MatchOut,
    MatchUpdate,
    ThreatCounts,
)
from app.services import audit
from app.services.audit import Action
from app.threats import feed
from app.threats import service as threats
from app.threats.content import AdvisoryContent
from app.workers import dispatch

router = APIRouter(tags=["threats"])


# ======================================================================== tenant
def _summaries(db: Session, advisories: list[ThreatAdvisory], organization_id: uuid.UUID | None,
               has_check: dict[uuid.UUID, bool]) -> list[AdvisorySummary]:
    ids = [a.id for a in advisories]
    counts = threats.counts_by_advisory(db, ids, organization_id)
    fresh = threats.freshness(db, ids)
    all_cves = {c for a in advisories for c in a.cves or []}
    kev = set(db.execute(select(VulnIntel.cve_id).where(VulnIntel.cve_id.in_(all_cves), VulnIntel.kev.is_(True)))
              .scalars()) if all_cves else set()
    out = []
    for a in advisories:
        c = fresh.get(a.id)
        out.append(AdvisorySummary(
            id=a.id, slug=a.slug, title=a.title, severity=a.severity, cves=a.cves or [], status=a.status,
            published_version=a.published_version, source_published_at=a.source_published_at,
            source_updated_at=a.source_updated_at, version_published_at=a.version_published_at,
            counts=ThreatCounts(**counts[a.id]), last_evaluated_at=c.last_evaluated_at if c else None,
            evaluated_version=c.evaluated_version if c else None,
            stale=bool(c is None or (a.published_version or 0) > (c.evaluated_version or 0)),
            incomplete=_gaps(c, organization_id), origin=a.origin, kev=bool(kev & set(a.cves or [])),
            has_check=has_check.get(a.id, False)))
    return out


def _gaps(c: Any, organization_id: uuid.UUID | None) -> list[str]:
    """Why the assessment covers only part of the inventory (empty when it covers all)."""
    gaps = (c.incomplete_orgs or {}) if c is not None else {}
    return [v for k, v in sorted(gaps.items()) if organization_id is None or k == str(organization_id)]


def _has_checks(db: Session, advisories: list[ThreatAdvisory]) -> dict[uuid.UUID, bool]:
    """Whether each advisory's current version names an enabled approved check."""
    if not advisories:
        return {}
    current = {a.id: a.published_version for a in advisories}
    rows = db.execute(select(ThreatAdvisoryVersion.advisory_id, ThreatAdvisoryVersion.version,
                             ThreatAdvisoryVersion.content).where(
        ThreatAdvisoryVersion.advisory_id.in_(list(current)), ThreatAdvisoryVersion.state == "published")).all()
    enabled = set(db.execute(select(ThreatCheck.key).where(ThreatCheck.enabled.is_(True))).scalars())
    return {aid: bool(set((content or {}).get("check_keys") or []) & enabled)
            for aid, version, content in rows if current.get(aid) == version}


@router.get("/threats", response_model=Page[AdvisorySummary])
def list_threats(status: str = Query("published", pattern="^(published|archived|all)$"),
                 q: str | None = Query(None, max_length=200), organization_id: uuid.UUID | None = None,
                 relevant: bool = Query(False, description="only advisories that may affect this tenant's assets"),
                 paging: Paging = Depends(), _: Principal = Depends(require(Permission.FINDINGS_READ)),
                 db: Session = Depends(get_db)) -> Page[AdvisorySummary]:
    # RLS already hides drafts from tenant sessions; the filter makes the intent explicit.
    stmt = select(ThreatAdvisory).where(ThreatAdvisory.published_version.is_not(None))
    if status != "all":
        stmt = stmt.where(ThreatAdvisory.status == AdvisoryStatus(status))
    if q:
        needle = "%" + q.replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(or_(ThreatAdvisory.title.ilike(needle), ThreatAdvisory.slug.ilike(needle),
                              ThreatAdvisory.cves.any(q.strip().upper())))
    if relevant:  # RLS confines the matches to the caller's tenant
        hit = select(ThreatMatch.id).where(ThreatMatch.advisory_id == ThreatAdvisory.id,
                                           ThreatMatch.assessment.in_([a.value for a in AFFECTED_ASSESSMENTS]))
        if organization_id:
            hit = hit.where(ThreatMatch.organization_id == organization_id)
        stmt = stmt.where(exists(hit))
    stmt = stmt.order_by(ThreatAdvisory.version_published_at.desc().nulls_last(), ThreatAdvisory.title)
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=_summaries(db, rows, organization_id, _has_checks(db, rows)), total=total, page=paging.page,
                page_size=paging.page_size)


def _visible(db: Session, advisory_id: uuid.UUID) -> ThreatAdvisory:
    adv = db.get(ThreatAdvisory, advisory_id)
    if adv is None or adv.published_version is None:
        raise NotFound("Advisory not found")
    return adv


@router.get("/threats/{advisory_id}", response_model=AdvisoryDetail)
def get_threat(advisory_id: uuid.UUID, organization_id: uuid.UUID | None = None,
               _: Principal = Depends(require(Permission.FINDINGS_READ)),
               db: Session = Depends(get_db)) -> AdvisoryDetail:
    adv = _visible(db, advisory_id)
    ver = threats.published_of(db, adv)
    content = AdvisoryContent.model_validate(ver.content) if ver else None
    summary = _summaries(db, [adv], organization_id, _has_checks(db, [adv]))[0]
    intel = [CveIntel(cve=r.cve_id, kev=r.kev, kev_due_date=r.kev_due_date.isoformat() if r.kev_due_date else None,
                      epss_score=r.epss_score, cvss_score=r.cvss_score)
             for r in db.execute(select(VulnIntel).where(VulnIntel.cve_id.in_(adv.cves or []))).scalars()]
    check = threats.usable_check(db, content) if content else None
    runs_stmt = select(ThreatCheckRun).where(ThreatCheckRun.advisory_id == adv.id)
    if organization_id:
        runs_stmt = runs_stmt.where(ThreatCheckRun.organization_id == organization_id)
    runs = list(db.execute(runs_stmt.order_by(ThreatCheckRun.created_at.desc()).limit(20)).scalars())
    if any([threats.refresh_run_status(db, r) for r in runs]):
        db.commit()  # a run whose scan had ended is finished now (idempotent repair)
        summary = _summaries(db, [adv], organization_id, _has_checks(db, [adv]))[0]
    return AdvisoryDetail(
        **summary.model_dump(), summary=content.summary if content else "",
        remediation=content.remediation if content else "", references=content.references if content else [],
        affected_products=[p.model_dump(mode="json") for p in content.affected] if content else [],
        intel=sorted(intel, key=lambda i: i.cve),
        check=CheckInfo(key=check.key, name=check.name, description=check.description) if check else None,
        check_runs=[CheckRunOut.model_validate(r) for r in runs])


def _match_rows(db: Session, advisory_id: uuid.UUID, assessment: list[Assessment], organization_id: uuid.UUID | None):
    stmt = select(ThreatMatch).where(ThreatMatch.advisory_id == advisory_id)
    if assessment:
        stmt = stmt.where(ThreatMatch.assessment.in_([a.value for a in assessment]))
    if organization_id:
        stmt = stmt.where(ThreatMatch.organization_id == organization_id)
    return stmt.order_by(ThreatMatch.assessment, ThreatMatch.first_matched_at.desc())


def _match_out(db: Session, rows: list[ThreatMatch]) -> list[MatchOut]:
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_({m.asset_id for m in rows}))).scalars()} \
        if rows else {}
    fids = {f for m in rows for f in (m.finding_ids or []) + (m.unverified_finding_ids or [])}
    findings = {f.id: f for f in db.execute(select(Finding).where(Finding.id.in_(fids))).scalars()} if fids else {}
    out = []
    for m in rows:
        a = assets.get(m.asset_id)
        refs = [FindingRef(id=f.id, title=f.title, severity=f.severity, status=f.status.value, unverified=f.unverified)
                for fid in (m.finding_ids or []) + (m.unverified_finding_ids or []) if (f := findings.get(fid))]
        out.append(MatchOut(
            id=m.id, organization_id=m.organization_id, asset=AssetRef.model_validate(a) if a else None,
            owner=a.owner if a else None, business_unit=a.business_unit if a else None, basis=m.basis,
            match_status=m.match_status, assessment=m.assessment, evidence=m.evidence or {}, findings=refs,
            check_outcome=m.check_outcome, check_detail=m.check_detail, checked_at=m.checked_at,
            remediation_status=m.remediation_status, assigned_to=m.assigned_to,
            remediation_note=m.remediation_note, first_matched_at=m.first_matched_at,
            last_evaluated_at=m.last_evaluated_at, advisory_version=m.advisory_version))
    return out


@router.get("/threats/{advisory_id}/assets", response_model=Page[MatchOut])
def threat_assets(advisory_id: uuid.UUID, assessment: list[Assessment] = Query(default=[]),
                  organization_id: uuid.UUID | None = None, paging: Paging = Depends(),
                  _: Principal = Depends(require(Permission.FINDINGS_READ)),
                  db: Session = Depends(get_db)) -> Page[MatchOut]:
    _visible(db, advisory_id)
    rows, total = paginate(db, _match_rows(db, advisory_id, assessment, organization_id), paging.page,
                           paging.page_size)
    return Page(items=_match_out(db, rows), total=total, page=paging.page, page_size=paging.page_size)


@router.get("/threats/{advisory_id}/assets/export.csv")
def export_threat_assets(advisory_id: uuid.UUID, organization_id: uuid.UUID | None = None,
                         _: Principal = Depends(require(Permission.FINDINGS_READ)),
                         db: Session = Depends(get_db)) -> StreamingResponse:
    adv = _visible(db, advisory_id)
    rows = list(db.execute(_match_rows(db, advisory_id, [], organization_id).limit(10_000)).scalars())
    out = _match_out(db, rows)
    audit.record(db, Action.DATA_EXPORTED, object_type="threat_advisory", object_id=adv.id,
                 new={"rows": len(out), "format": "csv"})
    db.commit()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["asset", "type", "assessment", "match", "evidence", "check", "checked_at", "findings",
                "remediation", "owner", "business_unit"])
    for m in out:
        ev = "; ".join(f"{o.get('product')} {o.get('version') or '(no version)'}: {o.get('reason')}"
                       for o in (m.evidence.get("observations") or []))
        w.writerow([_csv_safe(m.asset.value if m.asset else ""), m.asset.asset_type.value if m.asset else "",
                    m.assessment.value, m.match_status.value, _csv_safe(ev or m.evidence.get("reason")),
                    m.check_outcome.value, m.checked_at.isoformat() if m.checked_at else "",
                    _csv_safe(" | ".join(f"{f.title} ({f.status}{', unverified' if f.unverified else ''})"
                                         for f in m.findings)),
                    m.remediation_status.value, _csv_safe(m.owner), _csv_safe(m.business_unit)])
    name = f"threat-{adv.slug}-{datetime.now(UTC):%Y%m%d-%H%M}.csv"
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/threats/{advisory_id}/checks", response_model=list[CheckRunOut], status_code=201)
def check_assets(advisory_id: uuid.UUID, body: CheckRequest,
                 principal: Principal = Depends(require(Permission.SCANS_RUN)),
                 db: Session = Depends(get_db)) -> list[Any]:
    _visible(db, advisory_id)
    runs = threats.request_checks(db, tenant_id=principal.require_tenant(), advisory_id=advisory_id,
                                  match_ids=body.match_ids, user_id=principal.user_id,
                                  trigger=ScanTrigger.API if principal.api_token_id else ScanTrigger.MANUAL)
    db.commit()
    for r in runs:
        if r.scan_id:
            dispatch.start_scan(r.tenant_id, r.scan_id)
    for r in runs:
        db.refresh(r)
    return [CheckRunOut.model_validate(r) for r in runs]


@router.get("/threats/{advisory_id}/checks", response_model=list[CheckRunOut])
def list_checks(advisory_id: uuid.UUID, _: Principal = Depends(require(Permission.FINDINGS_READ)),
                db: Session = Depends(get_db)) -> list[Any]:
    _visible(db, advisory_id)
    runs = list(db.execute(select(ThreatCheckRun).where(ThreatCheckRun.advisory_id == advisory_id)
                           .order_by(ThreatCheckRun.created_at.desc()).limit(50)).scalars())
    if any([threats.refresh_run_status(db, r) for r in runs]):
        db.commit()
    return [CheckRunOut.model_validate(r) for r in runs]


@router.patch("/threats/matches/{match_id}", response_model=MatchOut)
def update_match(match_id: uuid.UUID, body: MatchUpdate,
                 principal: Principal = Depends(require(Permission.FINDINGS_WRITE)),
                 db: Session = Depends(get_db)) -> MatchOut:
    m = threats.update_match(db, match_id, changes=body.model_dump(exclude_unset=True), user_id=principal.user_id)
    db.commit()
    return _match_out(db, [m])[0]


# ==================================================================== platform
def _admin_out(db: Session, adv: ThreatAdvisory, full: bool = False) -> AdvisoryAdminOut:
    draft = threats.draft_of(db, adv.id)
    out = AdvisoryAdminOut(id=adv.id, slug=adv.slug, title=adv.title, severity=adv.severity, status=adv.status,
                           published_version=adv.published_version, version_published_at=adv.version_published_at,
                           updated_at=adv.updated_at, has_draft=draft is not None, origin=adv.origin)
    if full:
        pub = threats.published_of(db, adv)
        out.draft = draft.content if draft else None
        out.draft_version = draft.version if draft else None
        out.published = pub.content if pub else None
        out.versions = [{"version": v.version, "state": v.state, "published_at": v.published_at,
                         "created_at": v.created_at}
                        for v in db.execute(select(ThreatAdvisoryVersion).where(
                            ThreatAdvisoryVersion.advisory_id == adv.id)
                            .order_by(ThreatAdvisoryVersion.version.desc())).scalars()]
    return out


@router.get("/threat-catalog", response_model=list[AdvisoryAdminOut])
def catalog(origin: str = Query("all", pattern="^(all|manual|feed)$"), q: str | None = Query(None, max_length=200),
            drafts: bool = Query(False, description="only advisories with an unpublished draft"),
            _: Principal = Depends(require(Permission.INTEL_ADMIN)),
            db: Session = Depends(get_system_db)) -> list[AdvisoryAdminOut]:
    stmt = select(ThreatAdvisory)
    if origin != "all":
        stmt = stmt.where(ThreatAdvisory.origin == origin)
    if q:
        needle = "%" + q.replace("%", "\\%").replace("_", "\\_") + "%"
        stmt = stmt.where(or_(ThreatAdvisory.title.ilike(needle), ThreatAdvisory.slug.ilike(needle),
                              ThreatAdvisory.cves.any(q.strip().upper())))
    if drafts:
        stmt = stmt.where(exists(select(ThreatAdvisoryVersion.id).where(
            ThreatAdvisoryVersion.advisory_id == ThreatAdvisory.id, ThreatAdvisoryVersion.state == "draft")))
    rows = db.execute(stmt.order_by(ThreatAdvisory.updated_at.desc()).limit(500)).scalars()
    return [_admin_out(db, a) for a in rows]


@router.get("/threat-catalog/feed")
def feed_settings(_: Principal = Depends(require(Permission.INTEL_ADMIN)),
                  db: Session = Depends(get_system_db)) -> dict[str, Any]:
    """Automatic advisories: settings (without the NVD key), built-in name aliases and status."""
    return {"settings": feed.settings(db), "builtin_aliases": feed.BUILTIN_ALIASES, "status": feed.status(db)}


@router.put("/threat-catalog/feed")
def save_feed_settings(body: FeedSettingsIn, principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
                       db: Session = Depends(get_system_db)) -> dict[str, Any]:
    values = body.model_dump(exclude={"nvd_api_key", "clear_nvd_api_key"}, exclude_none=True)
    feed.set_settings(db, values, api_key=body.nvd_api_key or None, clear_key=body.clear_nvd_api_key,
                      user_id=principal.user_id)
    db.commit()
    return {"settings": feed.settings(db), "builtin_aliases": feed.BUILTIN_ALIASES, "status": feed.status(db)}


@router.post("/threat-catalog/feed/run", response_model=Message, status_code=202)
def run_feed(_: Principal = Depends(require(Permission.INTEL_ADMIN))) -> Message:
    """Fetch now instead of waiting for the hourly run."""
    dispatch.run_threat_feed()
    return Message(message="The feed is running; new advisories appear within a few minutes")


@router.get("/threat-catalog/checks", response_model=list[CheckAdminOut])
def catalog_checks(_: Principal = Depends(require(Permission.INTEL_ADMIN)),
                   db: Session = Depends(get_system_db)) -> list[Any]:
    return list(db.execute(select(ThreatCheck).order_by(ThreatCheck.key)).scalars())


@router.put("/threat-catalog/checks/{key}", response_model=CheckAdminOut)
def save_check(key: str, body: CheckAdminIn, principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
               db: Session = Depends(get_system_db)) -> Any:
    if key != body.key:
        raise NotFound("Check identifier mismatch")
    row = threats.save_check(db, key=body.key, name=body.name, description=body.description,
                             template_id=body.template_id, enabled=body.enabled, user_id=principal.user_id)
    db.commit()
    db.refresh(row)
    return row


@router.post("/threat-catalog", response_model=AdvisoryAdminOut, status_code=201)
def create_advisory(body: AdvisoryCreate, principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
                    db: Session = Depends(get_system_db)) -> AdvisoryAdminOut:
    adv = threats.create_advisory(db, slug=body.slug, content=body.content, user_id=principal.user_id)
    db.commit()
    db.refresh(adv)
    return _admin_out(db, adv, full=True)


def _catalog_item(db: Session, advisory_id: uuid.UUID) -> ThreatAdvisory:
    adv = db.get(ThreatAdvisory, advisory_id)
    if adv is None:
        raise NotFound("Advisory not found")
    return adv


@router.get("/threat-catalog/{advisory_id}", response_model=AdvisoryAdminOut)
def catalog_item(advisory_id: uuid.UUID, _: Principal = Depends(require(Permission.INTEL_ADMIN)),
                 db: Session = Depends(get_system_db)) -> AdvisoryAdminOut:
    return _admin_out(db, _catalog_item(db, advisory_id), full=True)


@router.put("/threat-catalog/{advisory_id}/draft", response_model=AdvisoryAdminOut)
def save_draft(advisory_id: uuid.UUID, body: AdvisoryContent,
               principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
               db: Session = Depends(get_system_db)) -> AdvisoryAdminOut:
    threats.save_draft(db, advisory_id, body, principal.user_id)
    db.commit()
    return _admin_out(db, _catalog_item(db, advisory_id), full=True)


@router.post("/threat-catalog/{advisory_id}/publish", response_model=AdvisoryAdminOut)
def publish(advisory_id: uuid.UUID, principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
            db: Session = Depends(get_system_db)) -> AdvisoryAdminOut:
    adv = threats.publish(db, advisory_id, principal.user_id)
    db.commit()
    # Matching every tenant's inventory happens in the background (inline in development).
    dispatch.evaluate_advisory(adv.id)
    db.refresh(adv)
    return _admin_out(db, adv, full=True)


@router.post("/threat-catalog/{advisory_id}/archive", response_model=AdvisoryAdminOut)
def archive(advisory_id: uuid.UUID, principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
            db: Session = Depends(get_system_db)) -> AdvisoryAdminOut:
    adv = threats.set_archived(db, advisory_id, True, principal.user_id)
    db.commit()
    db.refresh(adv)
    return _admin_out(db, adv, full=True)


@router.post("/threat-catalog/{advisory_id}/restore", response_model=AdvisoryAdminOut)
def restore(advisory_id: uuid.UUID, principal: Principal = Depends(require(Permission.INTEL_ADMIN)),
            db: Session = Depends(get_system_db)) -> AdvisoryAdminOut:
    adv = threats.set_archived(db, advisory_id, False, principal.user_id)
    db.commit()
    if adv.published_version:
        dispatch.evaluate_advisory(adv.id)
    db.refresh(adv)
    return _admin_out(db, adv, full=True)


@router.post("/threat-catalog/evaluate", response_model=Message)
def evaluate_now(_: Principal = Depends(require(Permission.INTEL_ADMIN))) -> Message:
    """Re-run matching for every published advisory and tenant (normally daily and on change)."""
    dispatch.evaluate_advisory(None)
    return Message(message="Re-evaluation started")
