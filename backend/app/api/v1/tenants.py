"""Platform administration of tenants and plans (platform admins only)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_system_db, require
from app.auth.permissions import Permission
from app.auth.service import normalize_email, revoke_user_sessions
from app.core.errors import NotFound, ValidationFailed
from app.core.security import hash_token, new_token
from app.models import PasswordResetToken, Plan, Tenant, TenantMembership, User
from app.models.enums import Role, TenantStatus
from app.scans.orchestrator import cancel_tenant_scans
from app.schemas.core import PlanOut, TenantCreate, TenantCreated, TenantOut, TenantUpdate
from app.services import audit
from app.services.audit import Action
from app.tenants.service import create_tenant
from app.workers import dispatch

router = APIRouter(prefix="/tenants", tags=["platform"])


@router.get("", response_model=list[TenantOut])
def list_tenants(_: Principal = Depends(require(Permission.TENANTS_ADMIN)), db: Session = Depends(get_system_db)) -> list:
    return list(db.execute(select(Tenant).order_by(Tenant.name)).scalars())


@router.get("/plans", response_model=list[PlanOut])
def list_plans(_: Principal = Depends(require(Permission.TENANTS_ADMIN)), db: Session = Depends(get_system_db)) -> list:
    return list(db.execute(select(Plan).order_by(Plan.name)).scalars())


@router.post("", response_model=TenantCreated, status_code=201)
def create(body: TenantCreate, _: Principal = Depends(require(Permission.TENANTS_ADMIN)),
           db: Session = Depends(get_system_db)) -> TenantCreated:
    tenant = create_tenant(db, body.name, slug=body.slug, plan_code=body.plan_code)
    token = None
    if body.admin_email:
        email = normalize_email(body.admin_email)
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = User(email=email, full_name=body.admin_name, default_tenant_id=tenant.id)
            db.add(user)
            db.flush()
            token = new_token()
            db.add(PasswordResetToken(user_id=user.id, token_hash=hash_token(token),
                                      expires_at=datetime.now(UTC) + timedelta(days=3)))
        db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.TENANT_ADMIN))
        audit.record(db, Action.USER_CREATED, tenant_id=tenant.id, object_type="user", object_id=user.id,
                     new={"email": email, "role": "tenant_admin"})
    db.commit()
    db.refresh(tenant)
    return TenantCreated(**TenantOut.model_validate(tenant).model_dump(), admin_password_reset_token=token)


@router.patch("/{tenant_id}", response_model=TenantOut)
def update(tenant_id: uuid.UUID, body: TenantUpdate, principal: Principal = Depends(require(Permission.TENANTS_ADMIN)),
           db: Session = Depends(get_system_db)) -> Tenant:
    tenant = db.get(Tenant, tenant_id)
    if tenant is None:
        raise NotFound("Tenant not found")
    if body.status == TenantStatus.SUSPENDED and tenant.id == principal.tenant_id:
        # Suspension revokes every session in the tenant, including the caller's own.
        raise ValidationFailed("You are signed in to this tenant. Switch to another tenant before suspending it, "
                               "or suspending it would sign you out.")
    before = {"name": tenant.name, "status": tenant.status.value, "plan_id": str(tenant.plan_id),
              "worker_pool": tenant.worker_pool}
    if body.name:
        tenant.name = body.name
    if body.worker_pool:
        tenant.worker_pool = body.worker_pool
    if body.plan_code:
        plan = db.execute(select(Plan).where(Plan.code == body.plan_code)).scalar_one_or_none()
        if plan is None:
            raise ValidationFailed("Unknown plan")
        tenant.plan_id = plan.id
    to_revoke: list[tuple[str, str]] = []
    if body.status and body.status != tenant.status:
        tenant.status = body.status
        if body.status == TenantStatus.SUSPENDED:
            for (uid,) in db.execute(select(TenantMembership.user_id).where(TenantMembership.tenant_id == tenant.id)):
                revoke_user_sessions(db, uid, "tenant_suspended", tenant_id=tenant.id)
            # Suspension stops scanning: queued and running scans are cancelled now.
            to_revoke = cancel_tenant_scans(db, tenant.id, "Cancelled: the tenant was suspended")
    after = {"name": tenant.name, "status": tenant.status.value, "plan_id": str(tenant.plan_id),
             "worker_pool": tenant.worker_pool}
    prev, new = audit.diff(before, after)
    audit.record(db, Action.TENANT_UPDATED, tenant_id=tenant.id, object_type="tenant", object_id=tenant.id,
                 previous=prev, new=new)
    db.commit()
    dispatch.revoke(to_revoke)
    db.refresh(tenant)
    return tenant
