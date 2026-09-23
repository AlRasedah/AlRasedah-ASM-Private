"""Tenants, plans, quotas, usage metering and first-run bootstrap."""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import Conflict, QuotaExceeded, ValidationFailed
from app.models import Asset, Organization, Plan, Scan, Tenant, TenantMembership, UsageRecord, User
from app.models.enums import ACTIVE_SCAN_STATES, AssetStatus, Role, ScanStatus, TenantStatus
from app.services import audit
from app.services.audit import Action

log = logging.getLogger(__name__)

DEFAULT_PLANS: list[dict[str, Any]] = [
    {"code": "self-hosted", "name": "Self-hosted (unlimited)", "is_default": True, "max_concurrent_scans": 4,
     "description": "Default plan for self-hosted deployments. No quotas beyond concurrency."},
    {"code": "starter", "name": "Starter", "max_organizations": 1, "max_assets": 2500, "max_users": 5,
     "max_scans_per_day": 4, "max_concurrent_scans": 1},
    {"code": "professional", "name": "Professional", "max_organizations": 5, "max_assets": 25000, "max_users": 25,
     "max_scans_per_day": 24, "max_concurrent_scans": 3},
    {"code": "enterprise", "name": "Enterprise", "max_concurrent_scans": 8},
]

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    return _SLUG_RE.sub("-", name.lower()).strip("-")[:90] or "tenant"


def ensure_plans(db: Session) -> None:
    for spec in DEFAULT_PLANS:
        plan = db.execute(select(Plan).where(Plan.code == spec["code"])).scalar_one_or_none()
        if plan is None:
            db.add(Plan(**{"features": {}, **spec}))
    db.flush()


def default_plan(db: Session) -> Plan | None:
    return db.execute(select(Plan).where(Plan.is_default.is_(True)).limit(1)).scalar_one_or_none()


def create_tenant(db: Session, name: str, *, slug: str | None = None, plan_code: str | None = None) -> Tenant:
    """System session required."""
    slug = slugify(slug or name)
    if db.execute(select(Tenant).where(Tenant.slug == slug)).scalar_one_or_none():
        raise Conflict(f"A tenant with slug '{slug}' already exists")
    plan = db.execute(select(Plan).where(Plan.code == plan_code)).scalar_one_or_none() if plan_code else default_plan(db)
    if plan_code and plan is None:
        raise ValidationFailed(f"Unknown plan '{plan_code}'")
    s = get_settings()
    # A pool is a trust domain (see orchestrator.scanner_pool_error), so a new tenant
    # gets one of its own rather than landing in whichever pool happens to exist. Its
    # scans then wait, with a clear reason, until an administrator provisions it —
    # which is the intended answer, not an accident of configuration.
    pool = f"t-{slug}"[:64] if s.scanner_isolation == "per_tenant" else "default"
    tenant = Tenant(name=name.strip(), slug=slug, plan_id=plan.id if plan else None,
                    worker_pool=pool, data_region=s.data_region, settings={})
    db.add(tenant)
    db.flush()
    audit.record(db, Action.TENANT_CREATED, tenant_id=tenant.id, object_type="tenant", object_id=tenant.id,
                 new={"name": tenant.name, "slug": slug, "plan": plan.code if plan else None})
    return tenant


# ------------------------------------------------------------------ quotas
def _plan(db: Session, tenant_id: uuid.UUID) -> Plan | None:
    tenant = db.get(Tenant, tenant_id)
    return tenant.plan if tenant else None


def check_can_add_organization(db: Session, tenant_id: uuid.UUID) -> None:
    plan = _plan(db, tenant_id)
    if plan and plan.max_organizations is not None:
        n = db.scalar(select(func.count()).select_from(Organization).where(Organization.tenant_id == tenant_id))
        if n >= plan.max_organizations:
            raise QuotaExceeded(f"Your plan allows {plan.max_organizations} organization(s)")


def check_can_add_user(db: Session, tenant_id: uuid.UUID) -> None:
    plan = _plan(db, tenant_id)
    if plan and plan.max_users is not None:
        n = db.scalar(select(func.count()).select_from(TenantMembership).where(
            TenantMembership.tenant_id == tenant_id, TenantMembership.is_active.is_(True)))
        if n >= plan.max_users:
            raise QuotaExceeded(f"Your plan allows {plan.max_users} user(s)")


def check_can_start_scan(db: Session, tenant_id: uuid.UUID) -> None:
    plan = _plan(db, tenant_id)
    if plan and plan.max_scans_per_day is not None:
        since = datetime.now(UTC) - timedelta(days=1)
        n = db.scalar(select(func.count()).select_from(Scan).where(Scan.tenant_id == tenant_id, Scan.created_at >= since))
        if n >= plan.max_scans_per_day:
            raise QuotaExceeded(f"Your plan allows {plan.max_scans_per_day} scans per day")


def scan_concurrency_limit(db: Session, tenant_id: uuid.UUID) -> int:
    plan = _plan(db, tenant_id)
    return plan.max_concurrent_scans if plan else 2


def running_scans(db: Session, tenant_id: uuid.UUID | None = None) -> int:
    q = select(func.count()).select_from(Scan).where(Scan.status == ScanStatus.RUNNING)
    if tenant_id:
        q = q.where(Scan.tenant_id == tenant_id)
    return db.scalar(q) or 0


def asset_quota_remaining(db: Session, tenant_id: uuid.UUID) -> int | None:
    plan = _plan(db, tenant_id)
    if not plan or plan.max_assets is None:
        return None
    n = db.scalar(select(func.count()).select_from(Asset).where(Asset.tenant_id == tenant_id,
                                                                 Asset.status == AssetStatus.ACTIVE))
    return max(plan.max_assets - (n or 0), 0)


def record_usage(db: Session, tenant_id: uuid.UUID, metric: str, quantity: int = 1,
                 reference_id: uuid.UUID | None = None, **details: Any) -> None:
    db.add(UsageRecord(tenant_id=tenant_id, metric=metric, quantity=quantity, reference_id=reference_id,
                       details=details))


def active_scan_count(db: Session, tenant_id: uuid.UUID) -> int:
    return db.scalar(select(func.count()).select_from(Scan).where(
        Scan.tenant_id == tenant_id, Scan.status.in_(ACTIVE_SCAN_STATES))) or 0


# --------------------------------------------------------------- bootstrap
def bootstrap(db: Session) -> None:
    """First-run initialization. Idempotent; runs in a system session."""
    from app.auth.service import normalize_email, set_password
    from app.scans.profiles import ensure_builtin_profiles

    ensure_plans(db)
    ensure_builtin_profiles(db)
    s = get_settings()
    if s.bootstrap_admin_email and s.bootstrap_admin_password:
        email = normalize_email(s.bootstrap_admin_email)
        if not db.execute(select(User).where(User.email == email)).scalar_one_or_none():
            tenant = db.execute(select(Tenant).order_by(Tenant.created_at).limit(1)).scalar_one_or_none()
            if tenant is None:
                tenant = create_tenant(db, s.bootstrap_tenant_name)
            user = User(email=email, full_name="Platform Administrator", is_platform_admin=True,
                        default_tenant_id=tenant.id)
            db.add(user)
            db.flush()
            set_password(db, user, s.bootstrap_admin_password.get_secret_value())
            db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.TENANT_ADMIN))
            audit.record(db, Action.USER_CREATED, tenant_id=tenant.id, user_id=user.id, actor="bootstrap",
                         object_type="user", object_id=user.id, new={"email": email, "platform_admin": True})
            log.info("bootstrap: created platform administrator %s", email)
    db.commit()


def tenant_is_active(db: Session, tenant_id: uuid.UUID) -> bool:
    t = db.get(Tenant, tenant_id)
    return bool(t and t.status == TenantStatus.ACTIVE)
