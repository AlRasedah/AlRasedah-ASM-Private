from __future__ import annotations

import ipaddress
import uuid

from asm_sensors.targets import Target, TargetKind
from fastapi import APIRouter, Depends, Query
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound, ValidationFailed
from app.models import Organization, ScopeEntry
from app.models.enums import ScopeEntryType
from app.schemas.common import Message
from app.schemas.core import (
    ScopeCheckRequest,
    ScopeCheckResponse,
    ScopeEntryBulkCreate,
    ScopeEntryCreate,
    ScopeEntryOut,
    ScopeEntryUpdate,
    VerificationInstructions,
)
from app.scope import service as scope

router = APIRouter(prefix="/scopes", tags=["scope"])


@router.get("", response_model=list[ScopeEntryOut])
def list_scope(organization_id: uuid.UUID | None = Query(None), _: Principal = Depends(require(Permission.SCOPE_READ)),
               db: Session = Depends(get_db)) -> list:
    q = select(ScopeEntry).order_by(ScopeEntry.is_exclusion, ScopeEntry.entry_type, ScopeEntry.value)
    if organization_id:
        q = q.where(ScopeEntry.organization_id == organization_id)
    return list(db.execute(q).scalars())


@router.post("", response_model=ScopeEntryOut, status_code=201)
def add_scope_entry(body: ScopeEntryCreate, principal: Principal = Depends(require(Permission.SCOPE_WRITE)),
                    db: Session = Depends(get_db)) -> ScopeEntry:
    entry = scope.add_entry(db, tenant_id=principal.require_tenant(), organization_id=body.organization_id,
                            entry_type=body.entry_type, value=body.value, include_subdomains=body.include_subdomains,
                            is_exclusion=body.is_exclusion, allow_active_scanning=body.allow_active_scanning,
                            notes=body.notes, user_id=principal.user_id)
    db.commit()
    return entry


def _guess_type(value: str) -> ScopeEntryType:
    v = value.strip()
    if "/" in v:
        return ScopeEntryType.CIDR
    try:
        ipaddress.ip_address(v)
        return ScopeEntryType.IP
    except ValueError:
        return ScopeEntryType.DOMAIN


@router.post("/bulk", response_model=list[ScopeEntryOut], status_code=201)
def bulk_add(body: ScopeEntryBulkCreate, principal: Principal = Depends(require(Permission.SCOPE_WRITE)),
             db: Session = Depends(get_db)) -> list:
    created, errors = [], []
    for raw in body.entries:
        raw = raw.strip()
        if not raw:
            continue
        try:
            with db.begin_nested():
                created.append(scope.add_entry(db, tenant_id=principal.require_tenant(),
                                               organization_id=body.organization_id, entry_type=_guess_type(raw),
                                               value=raw, is_exclusion=body.is_exclusion,
                                               allow_active_scanning=body.allow_active_scanning,
                                               user_id=principal.user_id))
        except (ValidationFailed, NotFound) as exc:
            errors.append(f"{raw}: {exc.message}")
        except Exception as exc:  # noqa: BLE001 - e.g. duplicates
            errors.append(f"{raw}: {getattr(exc, 'message', 'could not be added')}")
    if errors and not created:
        raise ValidationFailed("No scope entries were added", details=errors)
    db.commit()
    return created


def _entry(db: Session, entry_id: uuid.UUID) -> ScopeEntry:
    e = db.get(ScopeEntry, entry_id)
    if e is None:
        raise NotFound("Scope entry not found")
    return e


@router.patch("/{entry_id}", response_model=ScopeEntryOut)
def update_scope_entry(entry_id: uuid.UUID, body: ScopeEntryUpdate,
                       _: Principal = Depends(require(Permission.SCOPE_WRITE)), db: Session = Depends(get_db)) -> ScopeEntry:
    _entry(db, entry_id)
    e = scope.update_entry(db, entry_id, body.model_dump(exclude_unset=True))
    db.commit()
    return e


@router.delete("/{entry_id}", response_model=Message)
def delete_scope_entry(entry_id: uuid.UUID, _: Principal = Depends(require(Permission.SCOPE_WRITE)),
                       db: Session = Depends(get_db)) -> Message:
    _entry(db, entry_id)
    scope.remove_entry(db, entry_id)
    db.commit()
    return Message(message="Scope entry removed")


@router.post("/check", response_model=ScopeCheckResponse)
def check_target(body: ScopeCheckRequest, _: Principal = Depends(require(Permission.SCOPE_READ)),
                 db: Session = Depends(get_db)) -> ScopeCheckResponse:
    org = db.get(Organization, body.organization_id)
    if org is None:
        raise NotFound("Organization not found")
    raw = body.target.strip()
    kind = TargetKind.URL if "://" in raw else TargetKind.CIDR if "/" in raw else (
        TargetKind.IP if _guess_type(raw) == ScopeEntryType.IP else TargetKind.HOSTNAME)
    try:
        target = Target(kind=kind, value=raw)
    except (ValidationError, ValueError) as exc:
        raise ValidationFailed("Not a valid hostname, IP, CIDR or URL") from exc
    d = scope.load_checker(db, org).check(target, active=body.active)
    return ScopeCheckResponse(target=target.value, allowed=d.allowed, reason=d.reason, scope_status=d.status.value)


@router.get("/{entry_id}/verification", response_model=VerificationInstructions)
def verification(entry_id: uuid.UUID, _: Principal = Depends(require(Permission.SCOPE_READ)),
                 db: Session = Depends(get_db)) -> VerificationInstructions:
    e = _entry(db, entry_id)
    if e.entry_type != ScopeEntryType.DOMAIN or not e.verification_token:
        raise ValidationFailed("Only domain entries support DNS verification")
    return VerificationInstructions(**scope.verification_instructions(e), status=e.verification_status)


@router.post("/{entry_id}/verify", response_model=ScopeEntryOut)
def verify(entry_id: uuid.UUID, _: Principal = Depends(require(Permission.SCOPE_WRITE)),
           db: Session = Depends(get_db)) -> ScopeEntry:
    _entry(db, entry_id)
    e = scope.verify_entry(db, entry_id)
    db.commit()
    return e
