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
from app.api.deps import Paging, Principal, get_db, get_principal, get_system_db, require
from app.auth.permissions import Permission
from app.core.config import get_settings
from app.core.errors import NotFound, ValidationFailed
from app.integrations import notifications
from app.models import AuditLog, IntelFeedState, Organization, Tenant, User, UserAlertPreference, VulnIntel
from app.models.enums import Severity
from app.schemas.common import ORM, Input, Message, Page, paginate
from app.scope import service as scope_service
from app.services import audit, platform_settings
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
    db.flush()
    # Turning verification on must not grandfather scope that was never proven.
    scope_service.apply_verification_policy(db, tenant.id)
    db.commit()
    if body.risk is not None:
        for (org_id,) in db.execute(select(Organization.id).where(Organization.tenant_id == tenant.id)):
            dispatch.recompute_risk(tenant.id, org_id)
    return {"effective": tenant_settings(tenant), "overrides": tenant.settings}


# ------------------------------------------------------- email delivery (platform)
class EmailSettingsIn(Input):
    host: str = Field(max_length=255)
    port: int = Field(default=587, ge=1, le=65535)
    username: str | None = Field(default=None, max_length=255)
    # Omit to keep the stored password; send "" to remove it.
    password: str | None = Field(default=None, max_length=512)
    sender: str = Field(max_length=320)
    starttls: bool = True
    ssl: bool = False


@router.get("/settings/email", tags=["settings"])
def get_email_settings(_: Principal = Depends(require(Permission.TENANTS_ADMIN)),
                       db: Session = Depends(get_system_db)) -> dict[str, Any]:
    """Mail server used for password resets, invitations and alerts (platform administrators)."""
    return platform_settings.email_status(db)


@router.put("/settings/email", tags=["settings"])
def update_email_settings(body: EmailSettingsIn, principal: Principal = Depends(require(Permission.TENANTS_ADMIN)),
                          db: Session = Depends(get_system_db)) -> dict[str, Any]:
    before = platform_settings.email_status(db)
    platform_settings.set_email(db, body.model_dump(exclude={"password"}), body.password,
                                clear_password=body.password == "", user_id=principal.user_id)
    after = platform_settings.email_status(db)
    audit.record(db, Action.SETTINGS_CHANGED, tenant_id=principal.tenant_id, object_type="platform_email",
                 previous={k: before[k] for k in ("host", "port", "sender", "username")},
                 new={k: after[k] for k in ("host", "port", "sender", "username")})
    db.commit()
    return after


@router.post("/settings/email/test", response_model=Message, tags=["settings"])
def test_email_settings(principal: Principal = Depends(require(Permission.TENANTS_ADMIN)),
                        db: Session = Depends(get_system_db)) -> Message:
    """Send a test message to the signed-in administrator with the saved settings."""
    from app.integrations.mailer import MailNotConfigured, send_email
    from app.models import User

    user = db.get(User, principal.user_id)
    assert user is not None
    s = get_settings()
    try:
        send_email([user.email], f"{s.app_name}: test message",
                   "Email delivery works. This message was sent from Settings → Email delivery.")
    except MailNotConfigured as exc:
        raise ValidationFailed(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - surface the reason, not a stack trace
        raise ValidationFailed(f"The mail server refused the message: {type(exc).__name__}") from exc
    return Message(message=f"Test message sent to {user.email}")


# ------------------------------------------------------- personal alerts (per user)
class MyAlertsIn(Input):
    enabled: bool = True
    min_severity: Severity = Severity.HIGH
    event_types: list[str] = Field(default_factory=list, max_length=40)
    organization_ids: list[uuid.UUID] = Field(default_factory=list, max_length=100)
    include_baseline: bool = False


def _my_alerts(db: Session, principal: Principal) -> dict[str, Any]:
    tid = principal.require_tenant()
    row = db.execute(select(UserAlertPreference).where(UserAlertPreference.tenant_id == tid,
                                                       UserAlertPreference.user_id == principal.user_id)
                     ).scalar_one_or_none()
    user = db.get(User, principal.user_id)
    base = {"email": user.email if user else None,
            "email_configured": platform_settings.email_status(db)["configured"]}
    if row is None:  # no choice made yet: the default (high and critical)
        return {**base, **{k: (v.value if isinstance(v, Severity) else v)
                           for k, v in notifications.DEFAULT_ALERTS.items()}, "is_default": True}
    return {**base, "enabled": row.enabled, "min_severity": row.min_severity.value,
            "event_types": row.event_types, "organization_ids": [str(o) for o in row.organization_ids],
            "include_baseline": row.include_baseline, "is_default": False}


@router.get("/settings/my-alerts", tags=["settings"])
def get_my_alerts(principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_system_db)) -> dict[str, Any]:
    """What this user receives at their own login address."""
    return _my_alerts(db, principal)


@router.put("/settings/my-alerts", tags=["settings"])
def update_my_alerts(body: MyAlertsIn, principal: Principal = Depends(get_principal),
                     db: Session = Depends(get_system_db)) -> dict[str, Any]:
    tid = principal.require_tenant()
    row = db.execute(select(UserAlertPreference).where(UserAlertPreference.tenant_id == tid,
                                                       UserAlertPreference.user_id == principal.user_id)
                     ).scalar_one_or_none()
    if row is None:
        row = UserAlertPreference(tenant_id=tid, user_id=principal.user_id)
        db.add(row)
    row.enabled, row.min_severity = body.enabled, body.min_severity
    row.event_types = [e[:64] for e in body.event_types]
    row.organization_ids = body.organization_ids
    row.include_baseline = body.include_baseline
    db.commit()
    return _my_alerts(db, principal)


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
