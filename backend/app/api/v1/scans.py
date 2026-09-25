from __future__ import annotations

import uuid

from asm_sensors.registry import describe_adapters
from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Paging, Principal, get_db, require
from app.auth.permissions import Permission
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound
from app.models import Scan, ScanArtifact, ScanProfile, ScanSchedule, ScanStage, ScopeDecision
from app.models.enums import DecisionResult, ScanStatus, ScanTrigger, StageType
from app.scans import engines as engine_identity
from app.scans import orchestrator, output, schedules
from app.scans.profiles import INTERNAL_SLUGS, STAGE_LABELS, profile_is_active, stage_time_limit, validate_stages
from app.scans.schedules import next_run, validate_timezone
from app.schemas.common import Message, Page, paginate
from app.schemas.scans import (
    ArtifactOut,
    DecisionOut,
    EngineOut,
    ProfileCreate,
    ProfileOut,
    ProfileStage,
    ProfileUpdate,
    RecurrenceOut,
    ScanCreate,
    ScanDetail,
    ScanOut,
    ScheduleCreate,
    ScheduleOut,
    ScheduleUpdate,
    StageOut,
)
from app.services import audit
from app.services.audit import Action
from app.services.storage import get_store
from app.tenants.service import slugify
from app.workers import dispatch

router = APIRouter(tags=["scans"])


# ---------------------------------------------------------------------- scans
def _detail(scan: Scan) -> ScanDetail:
    stages = []
    for st in sorted(scan.stages, key=lambda s: s.position):
        o = StageOut.model_validate(st)
        # Each stage is named by the capability it performs, so two engines doing the
        # same kind of work do not look like the same stage running twice.
        o.label = engine_identity.label_for(st.engine, STAGE_LABELS.get(st.stage_type, st.stage_type.value))
        o.time_limit_seconds = stage_time_limit(st.engine, st.config, get_settings().stage_timeout_seconds)
        stages.append(o)
    return ScanDetail(**ScanOut.model_validate(scan).model_dump(), stages=stages)


@router.get("/scans", response_model=Page[ScanOut], tags=["scans"])
def list_scans(organization_id: uuid.UUID | None = None, status: list[ScanStatus] = Query(default=[]),
               paging: Paging = Depends(), _: Principal = Depends(require(Permission.SCANS_READ)),
               db: Session = Depends(get_db)) -> Page:
    stmt = select(Scan).order_by(Scan.created_at.desc())
    if organization_id:
        stmt = stmt.where(Scan.organization_id == organization_id)
    if status:
        stmt = stmt.where(Scan.status.in_([s.value for s in status]))
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=[ScanOut.model_validate(s) for s in rows], total=total, page=paging.page,
                page_size=paging.page_size)


@router.post("/scans", response_model=ScanDetail, status_code=201)
def create_scan(body: ScanCreate, principal: Principal = Depends(require(Permission.SCANS_RUN)),
                db: Session = Depends(get_db)) -> ScanDetail:
    scan = orchestrator.create_scan(db, tenant_id=principal.require_tenant(), organization_id=body.organization_id,
                                    profile_id=body.profile_id,
                                    trigger=ScanTrigger.API if principal.api_token_id else ScanTrigger.MANUAL,
                                    requested_by=principal.user_id, target_override=body.targets,
                                    auth_secret=body.auth_secret, auth_header_name=body.auth_header_name)
    db.commit()
    dispatch.start_scan(scan.tenant_id, scan.id)
    db.refresh(scan)
    return _detail(scan)


def _scan(db: Session, scan_id: uuid.UUID) -> Scan:
    s = db.get(Scan, scan_id)
    if s is None:
        raise NotFound("Scan not found")
    return s


@router.get("/scans/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: uuid.UUID, _: Principal = Depends(require(Permission.SCANS_READ)),
             db: Session = Depends(get_db)) -> ScanDetail:
    return _detail(_scan(db, scan_id))


@router.post("/scans/{scan_id}/cancel", response_model=ScanDetail)
def cancel(scan_id: uuid.UUID, _: Principal = Depends(require(Permission.SCANS_RUN)),
           db: Session = Depends(get_db)) -> ScanDetail:
    _scan(db, scan_id)
    scan, task_ids = orchestrator.cancel_scan(db, scan_id)
    db.commit()
    dispatch.revoke(task_ids)
    return _detail(scan)


@router.get("/scans/{scan_id}/decisions", response_model=Page[DecisionOut])
def decisions(scan_id: uuid.UUID, decision: DecisionResult | None = None, paging: Paging = Depends(),
              _: Principal = Depends(require(Permission.SCANS_READ)), db: Session = Depends(get_db)) -> Page:
    _scan(db, scan_id)
    stmt = select(ScopeDecision).where(ScopeDecision.scan_id == scan_id).order_by(ScopeDecision.id)
    if decision:
        stmt = stmt.where(ScopeDecision.decision == decision)
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=[DecisionOut.model_validate(r) for r in rows], total=total, page=paging.page,
                page_size=paging.page_size)


def _stage(db: Session, scan_id: uuid.UUID, stage_id: uuid.UUID) -> ScanStage:
    _scan(db, scan_id)
    stage = db.get(ScanStage, stage_id)
    if stage is None or stage.scan_id != scan_id:
        raise NotFound("Stage not found")
    return stage


@router.get("/scans/{scan_id}/stages/{stage_id}/output")
def stage_output(scan_id: uuid.UUID, stage_id: uuid.UUID, _: Principal = Depends(require(Permission.SCANS_READ)),
                 db: Session = Depends(get_db)) -> dict:
    """The stage's verbose output: first and last lines, cleaned (no engine names, no secrets)."""
    return output.read(db, _stage(db, scan_id, stage_id))


@router.get("/scans/{scan_id}/stages/{stage_id}/output.txt")
def stage_output_text(scan_id: uuid.UUID, stage_id: uuid.UUID, _: Principal = Depends(require(Permission.SCANS_READ)),
                      db: Session = Depends(get_db)) -> Response:
    stage = _stage(db, scan_id, stage_id)
    label = engine_identity.label_for(stage.engine, STAGE_LABELS.get(stage.stage_type, ""))
    body = output.as_text(label, output.read(db, stage))
    audit.record(db, Action.DATA_EXPORTED, object_type="scan_stage", object_id=stage.id,
                 new={"format": "text", "kind": "stage_output"})
    db.commit()
    return Response(body, media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}-stage-{stage.position}.txt"'})


@router.get("/scans/{scan_id}/artifacts", response_model=list[ArtifactOut])
def artifacts(scan_id: uuid.UUID, _: Principal = Depends(require(Permission.SCANS_READ)),
              db: Session = Depends(get_db)) -> list:
    _scan(db, scan_id)
    return list(db.execute(select(ScanArtifact).where(ScanArtifact.scan_id == scan_id)).scalars())


@router.get("/scans/{scan_id}/artifacts/{artifact_id}/download")
def download_artifact(scan_id: uuid.UUID, artifact_id: uuid.UUID,
                      _: Principal = Depends(require(Permission.SCANS_RUN)), db: Session = Depends(get_db)) -> Response:
    art = db.get(ScanArtifact, artifact_id)
    if art is None or art.scan_id != scan_id:
        raise NotFound("Artifact not found")
    data = get_store().get(art.storage_key)
    return Response(data, media_type="application/gzip",
                    headers={"Content-Disposition": f'attachment; filename="{art.name}.gz"'})


# ------------------------------------------------------------------- profiles
def _profile_out(p: ScanProfile) -> ProfileOut:
    stages = [ProfileStage(**{**s, "engine": engine_identity.token_for(s["engine"])},
                           label=engine_identity.label_for(s["engine"], STAGE_LABELS.get(StageType(s["stage"]))),
                           accepts_login=engine_identity.accepts_login(s["engine"]))
              for s in p.stages]
    return ProfileOut(id=p.id, slug=p.slug, name=p.name, description=p.description, stages=stages,
                      is_builtin=p.is_builtin, is_active_scanning=p.is_active_scanning,
                      retain_raw_output=p.retain_raw_output, tenant_id=p.tenant_id)


@router.get("/scan-profiles", response_model=list[ProfileOut], tags=["scan-profiles"])
def list_profiles(_: Principal = Depends(require(Permission.SCANS_READ)), db: Session = Depends(get_db)) -> list:
    rows = db.execute(select(ScanProfile).order_by(ScanProfile.is_builtin.desc(), ScanProfile.name)).scalars()
    # Internal profiles (Threat Center checks) are never offered to people.
    return [_profile_out(p) for p in rows if not (p.tenant_id is None and p.slug in INTERNAL_SLUGS)]


@router.get("/scan-profiles/engines", response_model=list[EngineOut], tags=["scan-profiles"])
def engines(_: Principal = Depends(require(Permission.SCANS_READ))) -> list:
    """The capabilities a profile can use. Engines are identified by an opaque,
    deployment-specific token; the implementing tool is not disclosed."""
    return [EngineOut(id=engine_identity.token_for(d["name"]), display_name=d["display_name"],
                      stage_types=d["stage_types"], target_kinds=d["target_kinds"], active=d["active"],
                      credential_providers=d["credential_providers"],
                      config_schema=engine_identity.sanitize_schema(d["config_schema"], d["display_name"]))
            # Capabilities that are not scan stages (website screenshots) cannot go in a profile.
            for d in describe_adapters() if d["stage_types"]]


@router.get("/scan-profiles/{profile_id}", response_model=ProfileOut, tags=["scan-profiles"])
def get_profile(profile_id: uuid.UUID, _: Principal = Depends(require(Permission.SCANS_READ)),
                db: Session = Depends(get_db)) -> ProfileOut:
    p = db.get(ScanProfile, profile_id)
    if p is None or (p.tenant_id is None and p.slug in INTERNAL_SLUGS):
        raise NotFound("Profile not found")
    return _profile_out(p)


@router.post("/scan-profiles", response_model=ProfileOut, status_code=201, tags=["scan-profiles"])
def create_profile(body: ProfileCreate, principal: Principal = Depends(require(Permission.PROFILES_WRITE)),
                   db: Session = Depends(get_db)) -> ProfileOut:
    tid = principal.require_tenant()
    stages = validate_stages(body.stages)
    slug = slugify(body.name)[:64]
    if db.execute(select(ScanProfile.id).where(ScanProfile.tenant_id == tid, ScanProfile.slug == slug)).first():
        raise Conflict("A profile with this name already exists")
    p = ScanProfile(tenant_id=tid, slug=slug, name=body.name, description=body.description, stages=stages,
                    is_builtin=False, is_active_scanning=profile_is_active(stages),
                    retain_raw_output=body.retain_raw_output, created_by=principal.user_id)
    db.add(p)
    db.flush()
    audit.record(db, Action.PROFILE_CHANGED, object_type="scan_profile", object_id=p.id,
                 new={"name": p.name, "stages": stages})
    db.commit()
    return _profile_out(p)


@router.patch("/scan-profiles/{profile_id}", response_model=ProfileOut, tags=["scan-profiles"])
def update_profile(profile_id: uuid.UUID, body: ProfileUpdate, principal: Principal = Depends(require(Permission.PROFILES_WRITE)),
                   db: Session = Depends(get_db)) -> ProfileOut:
    p = db.get(ScanProfile, profile_id)
    if p is None or p.tenant_id != principal.tenant_id:
        raise NotFound("Profile not found (built-in profiles cannot be edited; create a copy)")
    before = {"name": p.name, "stages": p.stages, "retain_raw_output": p.retain_raw_output}
    if body.name:
        p.name = body.name
    if body.description is not None:
        p.description = body.description
    if body.stages is not None:
        p.stages = validate_stages(body.stages)
        p.is_active_scanning = profile_is_active(p.stages)
    if body.retain_raw_output is not None:
        p.retain_raw_output = body.retain_raw_output
    prev, new = audit.diff(before, {"name": p.name, "stages": p.stages, "retain_raw_output": p.retain_raw_output})
    audit.record(db, Action.PROFILE_CHANGED, object_type="scan_profile", object_id=p.id, previous=prev, new=new)
    db.commit()
    return _profile_out(p)


@router.delete("/scan-profiles/{profile_id}", response_model=Message, tags=["scan-profiles"])
def delete_profile(profile_id: uuid.UUID, principal: Principal = Depends(require(Permission.PROFILES_WRITE)),
                   db: Session = Depends(get_db)) -> Message:
    p = db.get(ScanProfile, profile_id)
    if p is None or p.tenant_id != principal.tenant_id:
        raise NotFound("Profile not found")
    audit.record(db, Action.PROFILE_CHANGED, object_type="scan_profile", object_id=p.id, previous={"name": p.name},
                 new={"deleted": True})
    db.delete(p)
    db.commit()
    return Message(message="Profile deleted")


# ------------------------------------------------------------------ schedules
def _schedule_out(s: ScanSchedule) -> ScheduleOut:
    """A schedule as words, so no screen has to show a cron expression."""
    rec = schedules.from_cron(s.cron)
    return ScheduleOut.model_validate(s).model_copy(update={
        "description": schedules.describe(s.cron),
        "recurrence": RecurrenceOut(**vars(rec)) if rec else None,
    })


def _cron_of(body: ScheduleCreate | ScheduleUpdate) -> str | None:
    if body.repeat is not None:
        return schedules.to_cron(schedules.Recurrence(**body.repeat.model_dump()))
    return body.cron


@router.get("/schedules", response_model=list[ScheduleOut], tags=["schedules"])
def list_schedules(organization_id: uuid.UUID | None = None, _: Principal = Depends(require(Permission.SCANS_READ)),
                   db: Session = Depends(get_db)) -> list:
    stmt = select(ScanSchedule).order_by(ScanSchedule.name)
    if organization_id:
        stmt = stmt.where(ScanSchedule.organization_id == organization_id)
    return [_schedule_out(s) for s in db.execute(stmt).scalars()]


@router.post("/schedules", response_model=ScheduleOut, status_code=201, tags=["schedules"])
def create_schedule(body: ScheduleCreate, principal: Principal = Depends(require(Permission.SCHEDULES_WRITE)),
                    db: Session = Depends(get_db)) -> ScheduleOut:
    tid = principal.require_tenant()
    validate_timezone(body.timezone)
    profile = db.get(ScanProfile, body.profile_id)
    if profile is None or (profile.tenant_id is None and profile.slug in INTERNAL_SLUGS):
        raise NotFound("Profile not found")
    cron = _cron_of(body)
    assert cron is not None  # the schema requires exactly one of repeat/cron
    s = ScanSchedule(tenant_id=tid, organization_id=body.organization_id, profile_id=body.profile_id, name=body.name,
                     cron=cron, timezone=body.timezone, enabled=body.enabled,
                     next_run_at=next_run(cron, body.timezone) if body.enabled else None,
                     created_by=principal.user_id)
    db.add(s)
    db.flush()
    audit.record(db, Action.SCHEDULE_CHANGED, object_type="scan_schedule", object_id=s.id,
                 new={**body.model_dump(mode="json", exclude={"repeat"}), "cron": cron,
                      "schedule": schedules.describe(cron)})
    db.commit()
    return _schedule_out(s)


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut, tags=["schedules"])
def update_schedule(schedule_id: uuid.UUID, body: ScheduleUpdate,
                    _: Principal = Depends(require(Permission.SCHEDULES_WRITE)), db: Session = Depends(get_db)) -> ScheduleOut:
    s = db.get(ScanSchedule, schedule_id)
    if s is None:
        raise NotFound("Schedule not found")
    changes = body.model_dump(exclude_unset=True, exclude={"repeat"})
    if (cron := _cron_of(body)) is not None:
        changes["cron"] = cron
    if changes.get("timezone"):
        validate_timezone(changes["timezone"])
    before = {k: getattr(s, k) for k in changes}
    for k, v in changes.items():
        if v is not None:
            setattr(s, k, v)
    s.next_run_at = next_run(s.cron, s.timezone) if s.enabled else None
    audit.record(db, Action.SCHEDULE_CHANGED, object_type="scan_schedule", object_id=s.id, previous=before,
                 new={**changes, "schedule": schedules.describe(s.cron)})
    db.commit()
    return _schedule_out(s)


@router.delete("/schedules/{schedule_id}", response_model=Message, tags=["schedules"])
def delete_schedule(schedule_id: uuid.UUID, _: Principal = Depends(require(Permission.SCHEDULES_WRITE)),
                    db: Session = Depends(get_db)) -> Message:
    s = db.get(ScanSchedule, schedule_id)
    if s is None:
        raise NotFound("Schedule not found")
    audit.record(db, Action.SCHEDULE_CHANGED, object_type="scan_schedule", object_id=s.id, previous={"name": s.name},
                 new={"deleted": True})
    db.delete(s)
    db.commit()
    return Message(message="Schedule deleted")
