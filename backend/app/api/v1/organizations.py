from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, require
from app.auth.permissions import Permission
from app.core.errors import Conflict, NotFound
from app.models import Asset, Finding, Organization, Scan, ScopeEntry
from app.models.enums import OPEN_FINDING_STATES, AssetStatus
from app.risk.service import organization_score
from app.schemas.common import Message
from app.schemas.core import OrganizationCreate, OrganizationOut, OrganizationSummary, OrganizationUpdate
from app.scope.service import rescope_assets
from app.services import audit
from app.services.audit import Action
from app.tenants import service as tenants

router = APIRouter(prefix="/organizations", tags=["organizations"])


def _summary(db: Session, org: Organization) -> OrganizationSummary:
    out = OrganizationSummary.model_validate(org)
    out.scope_entries = db.scalar(select(func.count()).select_from(ScopeEntry).where(
        ScopeEntry.organization_id == org.id)) or 0
    out.assets = db.scalar(select(func.count()).select_from(Asset).where(
        Asset.organization_id == org.id, Asset.status == AssetStatus.ACTIVE)) or 0
    out.open_findings = db.scalar(select(func.count()).select_from(Finding).where(
        Finding.organization_id == org.id, Finding.status.in_([s.value for s in OPEN_FINDING_STATES]))) or 0
    out.risk_score = organization_score(db, org)
    out.last_scan_at = db.scalar(select(func.max(Scan.finished_at)).where(Scan.organization_id == org.id))
    return out


@router.get("", response_model=list[OrganizationSummary])
def list_organizations(_: Principal = Depends(require(Permission.ORGS_READ)), db: Session = Depends(get_db)) -> list:
    orgs = db.execute(select(Organization).order_by(Organization.name)).scalars().all()
    return [_summary(db, o) for o in orgs]


@router.post("", response_model=OrganizationOut, status_code=201)
def create_organization(body: OrganizationCreate, principal: Principal = Depends(require(Permission.ORGS_WRITE)),
                        db: Session = Depends(get_db)) -> Organization:
    tid = principal.require_tenant()
    tenants.check_can_add_organization(db, tid)
    if db.execute(select(Organization.id).where(Organization.name == body.name)).first():
        raise Conflict("An organization with this name already exists")
    org = Organization(tenant_id=tid, name=body.name, description=body.description, industry=body.industry,
                       settings={})
    db.add(org)
    db.flush()
    audit.record(db, Action.ORG_CREATED, object_type="organization", object_id=org.id, new=body.model_dump())
    db.commit()
    return org


def _get(db: Session, org_id: uuid.UUID) -> Organization:
    org = db.get(Organization, org_id)
    if org is None:
        raise NotFound("Organization not found")
    return org


@router.get("/{org_id}", response_model=OrganizationSummary)
def get_organization(org_id: uuid.UUID, _: Principal = Depends(require(Permission.ORGS_READ)),
                     db: Session = Depends(get_db)) -> OrganizationSummary:
    return _summary(db, _get(db, org_id))


@router.patch("/{org_id}", response_model=OrganizationOut)
def update_organization(org_id: uuid.UUID, body: OrganizationUpdate,
                        _: Principal = Depends(require(Permission.ORGS_WRITE)),
                        db: Session = Depends(get_db)) -> Organization:
    org = _get(db, org_id)
    before = {"name": org.name, "description": org.description, "industry": org.industry,
              "is_active": org.is_active, "settings": dict(org.settings or {})}
    data = body.model_dump(exclude_unset=True, exclude={"settings"})
    for k, v in data.items():
        if v is not None or k == "description":
            setattr(org, k, v)
    if body.settings is not None:
        org.settings = {**(org.settings or {}), **body.settings.model_dump(exclude_none=True)}
        rescope_assets(db, org)
    after = {"name": org.name, "description": org.description, "industry": org.industry,
             "is_active": org.is_active, "settings": dict(org.settings or {})}
    prev, new = audit.diff(before, after)
    audit.record(db, Action.ORG_UPDATED, object_type="organization", object_id=org.id, previous=prev, new=new)
    db.commit()
    return org


@router.delete("/{org_id}", response_model=Message)
def delete_organization(org_id: uuid.UUID, _: Principal = Depends(require(Permission.ORGS_WRITE)),
                        db: Session = Depends(get_db)) -> Message:
    org = _get(db, org_id)
    audit.record(db, Action.ORG_DELETED, object_type="organization", object_id=org.id, previous={"name": org.name})
    db.delete(org)
    db.commit()
    return Message(message="Organization and all of its data were deleted")
