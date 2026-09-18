"""Tenant settings, audit log, vulnerability intelligence and health endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app import __version__
from app.api.deps import Paging, Principal, get_db, get_system_db, require
from app.auth.permissions import Permission
from app.core.config import get_settings
from app.core.errors import NotFound
from app.models import AuditLog, IntelFeedState, Organization, Tenant, VulnIntel
from app.schemas.common import ORM, Input, Message, Page, paginate
from app.services import audit
from app.services.audit import Action
from app.tenants.settings import DEFAULT_TENANT_SETTINGS, deep_merge, tenant_settings
from app.workers import dispatch

router = APIRouter()


# ------------------------------------------------------------------ settings
class Inactivity(Input):
    default: int | None = Field(default=None, ge=1, le=20)
    subdomain: int | None = Field(default=None, ge=1, le=20)
    root_domain: int | None = Field(default=None, ge=1, le=20)
    domain: int | None = Field(default=None, ge=1, le=20)
    port: int | None = Field(default=None, ge=1, le=20)
    service: int | None = Field(default=None, ge=1, le=20)
    http_endpoint: int | None = Field(default=None, ge=1, le=20)
    relation: int | None = Field(default=None, ge=1, le=20)
    finding: int | None = Field(default=None, ge=1, le=20)
    max_age_days: int | None = Field(default=None, ge=1, le=3650)


class RiskLevels(Input):
    critical: int = Field(ge=1, le=100)
    high: int = Field(ge=1, le=100)
    medium: int = Field(ge=1, le=100)
    low: int = Field(ge=1, le=100)


class RiskWeights(Input):
    severity_points: dict[str, float] | None = None
    kev_points: float | None = Field(default=None, ge=0, le=100)
    epss_max_points: float | None = Field(default=None, ge=0, le=100)
    exploit_points: float | None = Field(default=None, ge=0, le=100)
    exposure_points: float | None = Field(default=None, ge=0, le=100)
    management_interface_points: float | None = Field(default=None, ge=0, le=100)
    auth_exposure_points: float | None = Field(default=None, ge=0, le=100)
    risky_port_points: float | None = Field(default=None, ge=0, le=100)
    criticality_points: dict[str, float] | None = None
    shadow_it_points: float | None = Field(default=None, ge=0, le=100)
    unauthorized_points: float | None = Field(default=None, ge=0, le=100)
    new_asset_points: float | None = Field(default=None, ge=0, le=100)
    new_asset_days: int | None = Field(default=None, ge=0, le=365)
    age_points_per_30_days: float | None = Field(default=None, ge=0, le=50)
    age_max_points: float | None = Field(default=None, ge=0, le=100)
    levels: RiskLevels | None = None


class Scanning(Input):
    require_scope_verification: bool | None = None


class DetectionRules(Input):
    risky_ports: bool | None = None
    management_interfaces: bool | None = None
    certificates: bool | None = None
    weak_tls: bool | None = None
    api_documentation: bool | None = None
    certificate_expiry_days: int | None = Field(default=None, ge=1, le=365)


class Branding(Input):
    name: str | None = Field(default=None, max_length=100)
    primary_color: str | None = Field(default=None, pattern=r"^#[0-9a-fA-F]{6}$")


class SettingsUpdate(Input):
    inactivity: Inactivity | None = None
    risk: RiskWeights | None = None
    scanning: Scanning | None = None
    detection_rules: DetectionRules | None = None
    branding: Branding | None = None


@router.get("/settings", tags=["settings"])
def get_tenant_settings(principal: Principal = Depends(require(Permission.ASSETS_READ)),
                        db: Session = Depends(get_db)) -> dict[str, Any]:
    tenant = db.get(Tenant, principal.require_tenant())
    return {"effective": tenant_settings(tenant), "defaults": DEFAULT_TENANT_SETTINGS,
            "overrides": tenant.settings if tenant else {}}


@router.put("/settings", tags=["settings"])
def update_tenant_settings(body: SettingsUpdate, principal: Principal = Depends(require(Permission.SETTINGS_WRITE)),
                           db: Session = Depends(get_system_db)) -> dict[str, Any]:
    tenant = db.get(Tenant, principal.require_tenant())
    assert tenant is not None
    before = dict(tenant.settings or {})
    tenant.settings = deep_merge(before, body.model_dump(exclude_none=True, mode="json"))
    audit.record(db, Action.SETTINGS_CHANGED, tenant_id=tenant.id, object_type="tenant_settings", object_id=tenant.id,
                 previous=before, new=tenant.settings)
    db.commit()
    if body.risk is not None:
        for (org_id,) in db.execute(select(Organization.id).where(Organization.tenant_id == tenant.id)):
            dispatch.recompute_risk(tenant.id, org_id)
    return {"effective": tenant_settings(tenant), "overrides": tenant.settings}


# ------------------------------------------------------------------ audit
class AuditOut(ORM):
    id: int
    chain_seq: int
    user_id: uuid.UUID | None
    actor: str | None
    action: str
    object_type: str | None
    object_id: str | None
    previous: dict[str, Any] | None
    new: dict[str, Any] | None
    ip_address: str | None
    user_agent: str | None
    request_id: str | None
    success: bool
    created_at: datetime


@router.get("/audit-logs", response_model=Page[AuditOut], tags=["audit"])
def audit_logs(action: str | None = Query(None, max_length=64), actor: str | None = Query(None, max_length=320),
               since: datetime | None = None, paging: Paging = Depends(),
               _: Principal = Depends(require(Permission.AUDIT_READ)), db: Session = Depends(get_db)) -> Page:
    stmt = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if actor:
        stmt = stmt.where(AuditLog.actor.ilike(f"%{actor}%"))
    if since:
        stmt = stmt.where(AuditLog.created_at >= since)
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total, page=paging.page,
                page_size=paging.page_size)


@router.get("/audit-logs/verify", tags=["audit"])
def verify_audit(principal: Principal = Depends(require(Permission.AUDIT_READ)),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    r = audit.check_chain(db, principal.require_tenant())
    return {"intact": r.intact, "entries": r.entries, "first_tampered_id": r.first_bad_id,
            "first_tampered_seq": r.first_bad_seq, "reason": r.reason}


# ------------------------------------------------------------------ intel
class IntelOut(ORM):
    cve_id: str
    description: str | None
    cvss_score: float | None
    cvss_vector: str | None
    epss_score: float | None
    epss_percentile: float | None
    kev: bool
    kev_date_added: Any
    kev_due_date: Any
    kev_ransomware: bool
    exploit_available: bool


class FeedOut(ORM):
    feed: str
    last_success_at: datetime | None
    last_attempt_at: datetime | None
    last_error: str | None
    records: int | None


@router.get("/intel/feeds", response_model=list[FeedOut], tags=["intel"])
def feeds(_: Principal = Depends(require(Permission.FINDINGS_READ)), db: Session = Depends(get_system_db)) -> list:
    return list(db.execute(select(IntelFeedState)).scalars())


@router.get("/intel/cve/{cve_id}", response_model=IntelOut, tags=["intel"])
def cve(cve_id: str, _: Principal = Depends(require(Permission.FINDINGS_READ)),
        db: Session = Depends(get_system_db)) -> VulnIntel:
    row = db.get(VulnIntel, cve_id.upper()[:32])
    if row is None:
        raise NotFound("No intelligence cached for this CVE")
    return row


@router.post("/intel/refresh", response_model=Message, tags=["intel"])
def refresh(_: Principal = Depends(require(Permission.INTEL_ADMIN))) -> Message:
    dispatch.refresh_intel()
    return Message(message="Vulnerability intelligence refresh started")


# ------------------------------------------------------------------ health
class Health(BaseModel):
    status: str
    version: str
    checks: dict[str, str] = {}


@router.get("/health", response_model=Health, tags=["health"])
def health() -> Health:
    return Health(status="ok", version=__version__)


@router.get("/health/ready", response_model=Health, tags=["health"])
def ready(db: Session = Depends(get_system_db)) -> Health:
    checks = {}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001
        checks["database"] = "unavailable"
    s = get_settings()
    if s.env != "test":
        try:
            import redis

            redis.Redis.from_url(s.redis_url, socket_timeout=1).ping()
            checks["redis"] = "ok"
        except Exception:  # noqa: BLE001
            checks["redis"] = "unavailable"
    status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return Health(status=status, version=__version__, checks=checks)
