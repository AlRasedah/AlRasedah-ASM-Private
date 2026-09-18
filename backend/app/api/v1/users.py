"""Tenant user management (memberships). Users are global identities; access is per tenant."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_system_db, require
from app.auth import service as auth
from app.auth.permissions import Permission, can_assign
from app.core.config import get_settings
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailed
from app.core.security import hash_token, new_token
from app.models import PasswordResetToken, TenantMembership, User
from app.models.enums import Role
from app.schemas.common import Message
from app.schemas.core import MemberOut, UserCreate, UserCreated, UserUpdate
from app.services import audit
from app.services.audit import Action
from app.tenants import service as tenants

router = APIRouter(prefix="/users", tags=["users"])


def _member_out(m: TenantMembership, u: User) -> MemberOut:
    return MemberOut(user_id=u.id, email=u.email, full_name=u.full_name, role=m.role, is_active=m.is_active and u.is_active,
                     mfa_enabled=u.mfa_enabled, last_login_at=u.last_login_at, created_at=m.created_at)


def _actor_role(p: Principal) -> Role:
    return Role.TENANT_ADMIN if p.role == Role.PLATFORM_ADMIN else p.role


@router.get("", response_model=list[MemberOut])
def list_users(principal: Principal = Depends(require(Permission.USERS_READ)),
               db: Session = Depends(get_system_db)) -> list[MemberOut]:
    tid = principal.require_tenant()
    rows = db.execute(select(TenantMembership, User).join(User, User.id == TenantMembership.user_id)
                      .where(TenantMembership.tenant_id == tid).order_by(User.email)).all()
    return [_member_out(m, u) for m, u in rows]


def _invite_token(db: Session, user: User) -> str:
    raw = new_token()
    db.add(PasswordResetToken(user_id=user.id, token_hash=hash_token(raw),
                              expires_at=datetime.now(UTC) + timedelta(days=3)))
    return raw


@router.post("", response_model=UserCreated, status_code=201)
def create_user(body: UserCreate, principal: Principal = Depends(require(Permission.USERS_WRITE)),
                db: Session = Depends(get_system_db)) -> UserCreated:
    tid = principal.require_tenant()
    if not can_assign(_actor_role(principal), body.role):
        raise Forbidden("You cannot grant a role above your own")
    tenants.check_can_add_user(db, tid)
    email = auth.normalize_email(body.email)
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    created = user is None
    if user is None:
        user = User(email=email, full_name=body.full_name, default_tenant_id=tid)
        db.add(user)
        db.flush()
        if body.password:
            auth.set_password(db, user, body.password)
    elif db.execute(select(TenantMembership).where(TenantMembership.tenant_id == tid,
                                                   TenantMembership.user_id == user.id)).scalar_one_or_none():
        raise Conflict("This user is already a member of the tenant")
    membership = TenantMembership(tenant_id=tid, user_id=user.id, role=body.role)
    db.add(membership)
    db.flush()
    token = None
    if created and not body.password:
        raw = _invite_token(db, user)
        from app.integrations.mailer import MailNotConfigured, send_email

        link = f"{get_settings().public_url.rstrip('/')}/reset-password?token={raw}"
        try:
            send_email([email], "You have been invited to Exteriq ASM",
                       f"An account was created for you. Set your password within 3 days: {link}")
        except (MailNotConfigured, OSError):
            token = raw  # no mail delivery: hand the one-time link to the administrator
    audit.record(db, Action.USER_CREATED, tenant_id=tid, object_type="user", object_id=user.id,
                 new={"email": email, "role": body.role.value, "new_identity": created})
    db.commit()
    out = _member_out(membership, user)
    return UserCreated(**out.model_dump(), password_reset_token=token)


def _membership(db: Session, tid: uuid.UUID, user_id: uuid.UUID) -> tuple[TenantMembership, User]:
    row = db.execute(select(TenantMembership, User).join(User, User.id == TenantMembership.user_id).where(
        TenantMembership.tenant_id == tid, TenantMembership.user_id == user_id)).first()
    if row is None:
        raise NotFound("User not found")
    return row[0], row[1]


def _admins(db: Session, tid: uuid.UUID) -> int:
    return db.scalar(select(func.count()).select_from(TenantMembership).where(
        TenantMembership.tenant_id == tid, TenantMembership.role == Role.TENANT_ADMIN,
        TenantMembership.is_active.is_(True))) or 0


@router.patch("/{user_id}", response_model=MemberOut)
def update_user(user_id: uuid.UUID, body: UserUpdate, principal: Principal = Depends(require(Permission.USERS_WRITE)),
                db: Session = Depends(get_system_db)) -> MemberOut:
    tid = principal.require_tenant()
    m, u = _membership(db, tid, user_id)
    before = {"role": m.role.value, "is_active": m.is_active, "full_name": u.full_name}
    if body.role is not None and body.role != m.role:
        if not can_assign(_actor_role(principal), body.role) or not can_assign(_actor_role(principal), m.role):
            raise Forbidden("You cannot change this user's role")
        if m.role == Role.TENANT_ADMIN and _admins(db, tid) <= 1:
            raise ValidationFailed("The tenant must keep at least one administrator")
        m.role = body.role
        auth.revoke_user_sessions(db, u.id, "role_changed", tenant_id=tid)
    if body.is_active is not None and body.is_active != m.is_active:
        if user_id == principal.user_id:
            raise ValidationFailed("You cannot deactivate yourself")
        if not body.is_active and m.role == Role.TENANT_ADMIN and _admins(db, tid) <= 1:
            raise ValidationFailed("The tenant must keep at least one administrator")
        m.is_active = body.is_active
        if not body.is_active:
            auth.revoke_user_sessions(db, u.id, "deactivated", tenant_id=tid)
    if body.full_name is not None:
        u.full_name = body.full_name
    after = {"role": m.role.value, "is_active": m.is_active, "full_name": u.full_name}
    prev, new = audit.diff(before, after)
    action = Action.ROLE_CHANGED if "role" in new else Action.USER_UPDATED
    audit.record(db, action, tenant_id=tid, object_type="user", object_id=u.id, previous=prev, new=new)
    db.commit()
    return _member_out(m, u)


@router.post("/{user_id}/mfa/reset", response_model=Message)
def reset_mfa(user_id: uuid.UUID, principal: Principal = Depends(require(Permission.USERS_WRITE)),
              db: Session = Depends(get_system_db)) -> Message:
    """Turn off a member's MFA (lost authenticator). They are signed out and can enrol again from Account.

    Users are global identities, so a tenant admin may only reset users whose account belongs to
    this tenant alone; anyone else (platform admins, members of other tenants) needs a platform admin.
    """
    tid = principal.require_tenant()
    m, u = _membership(db, tid, user_id)
    if user_id == principal.user_id:
        raise ValidationFailed("Use Account → Two-factor authentication to change your own MFA")
    if not u.mfa_enabled:
        raise ValidationFailed("MFA is not enabled for this user")
    if not principal.is_platform_admin:
        if not can_assign(_actor_role(principal), m.role):
            raise Forbidden("You cannot reset MFA for this user")
        other_tenants = db.scalar(select(func.count()).select_from(TenantMembership).where(
            TenantMembership.user_id == u.id, TenantMembership.tenant_id != tid))
        if u.is_platform_admin or other_tenants:
            raise Forbidden("This account is shared with other tenants; ask a platform administrator to reset its MFA")
    u.mfa_enabled = False
    u.mfa_secret_encrypted = None
    auth.revoke_user_sessions(db, u.id, "mfa_reset")
    audit.record(db, Action.MFA_DISABLED, tenant_id=tid, object_type="user", object_id=u.id,
                 new={"reset_by_admin": True, "user": u.email})
    db.commit()
    return Message(message="MFA reset. The user has been signed out and can set up MFA again "
                           "from Account → Two-factor authentication.")


@router.delete("/{user_id}", response_model=Message)
def remove_user(user_id: uuid.UUID, principal: Principal = Depends(require(Permission.USERS_WRITE)),
                db: Session = Depends(get_system_db)) -> Message:
    tid = principal.require_tenant()
    m, u = _membership(db, tid, user_id)
    if user_id == principal.user_id:
        raise ValidationFailed("You cannot remove yourself")
    if m.role == Role.TENANT_ADMIN and _admins(db, tid) <= 1:
        raise ValidationFailed("The tenant must keep at least one administrator")
    if not can_assign(_actor_role(principal), m.role):
        raise Forbidden("You cannot remove this user")
    auth.revoke_user_sessions(db, u.id, "removed", tenant_id=tid)
    audit.record(db, Action.USER_REMOVED, tenant_id=tid, object_type="user", object_id=u.id,
                 previous={"email": u.email, "role": m.role.value})
    db.delete(m)
    db.commit()
    return Message(message="User removed from tenant")
