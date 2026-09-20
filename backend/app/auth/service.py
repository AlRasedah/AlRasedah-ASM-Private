"""Authentication: local credentials, session/refresh-token rotation, TOTP MFA,
password reset and API tokens.

All functions here run in a *system* database session: authentication happens
before a tenant context exists. Callers must never pass that session to
tenant-scoped business logic.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
import pyotp
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import get_settings
from app.core.context import get_context
from app.core.errors import Forbidden, Unauthorized, ValidationFailed
from app.core.security import (
    create_access_token,
    create_mfa_challenge,
    decode_mfa_challenge,
    hash_password,
    hash_token,
    new_token,
    password_needs_rehash,
    password_policy_errors,
    verify_password,
)
from app.models import ApiToken, PasswordResetToken, Tenant, TenantMembership, User, UserSession
from app.models.enums import Role, TenantStatus
from app.services import audit
from app.services.audit import Action

GENERIC_LOGIN_ERROR = "Invalid email or password"
API_TOKEN_PREFIX = "asmpat_"


def normalize_email(email: str) -> str:
    return email.strip().lower()


@dataclass
class SessionTokens:
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    refresh_expires_at: datetime
    session_id: uuid.UUID
    user: User
    tenant_id: uuid.UUID | None
    role: Role


@dataclass
class LoginOutcome:
    tokens: SessionTokens | None = None
    mfa_required: bool = False
    mfa_token: str | None = None


def _now() -> datetime:
    return datetime.now(UTC)


def active_membership(db: Session, user: User, tenant_id: uuid.UUID) -> TenantMembership | None:
    return db.execute(
        select(TenantMembership)
        .join(Tenant, Tenant.id == TenantMembership.tenant_id)
        .where(TenantMembership.user_id == user.id, TenantMembership.tenant_id == tenant_id,
               TenantMembership.is_active.is_(True), Tenant.status == TenantStatus.ACTIVE)
    ).scalar_one_or_none()


def resolve_tenant(db: Session, user: User, requested: uuid.UUID | None = None) -> tuple[uuid.UUID | None, Role]:
    """Pick the tenant context for a session and the user's role in it."""
    candidates = [requested] if requested else []
    if user.default_tenant_id:
        candidates.append(user.default_tenant_id)
    for tid in candidates:
        m = active_membership(db, user, tid)
        if m:
            return tid, Role.PLATFORM_ADMIN if user.is_platform_admin else m.role
        if requested and tid == requested and user.is_platform_admin:
            tenant = db.get(Tenant, tid)
            if tenant and tenant.status == TenantStatus.ACTIVE:
                return tid, Role.PLATFORM_ADMIN
        if requested and tid == requested:
            raise Forbidden("You do not have access to this tenant")
    first = db.execute(
        select(TenantMembership)
        .join(Tenant, Tenant.id == TenantMembership.tenant_id)
        .where(TenantMembership.user_id == user.id, TenantMembership.is_active.is_(True),
               Tenant.status == TenantStatus.ACTIVE)
        .order_by(TenantMembership.created_at)
        .limit(1)
    ).scalar_one_or_none()
    if first:
        return first.tenant_id, Role.PLATFORM_ADMIN if user.is_platform_admin else first.role
    if user.is_platform_admin:
        return None, Role.PLATFORM_ADMIN
    # Only reached after the password has been verified, so naming the reason leaks nothing.
    suspended = db.execute(
        select(TenantMembership.id)
        .join(Tenant, Tenant.id == TenantMembership.tenant_id)
        .where(TenantMembership.user_id == user.id, TenantMembership.is_active.is_(True),
               Tenant.status == TenantStatus.SUSPENDED)
        .limit(1)
    ).first()
    if suspended:
        raise Forbidden("Your organization's access to Exteriq ASM is suspended. "
                        "Contact your platform administrator.", code="tenant_suspended")
    raise Forbidden("Your account is not a member of any active tenant")


def _issue_session(db: Session, user: User, tenant_id: uuid.UUID | None, role: Role, mfa_verified: bool) -> SessionTokens:
    s = get_settings()
    ctx = get_context()
    now = _now()
    raw = new_token()
    session = UserSession(
        user_id=user.id,
        tenant_id=tenant_id,
        refresh_token_hash=hash_token(raw),
        expires_at=now + timedelta(days=s.refresh_token_ttl_days),
        absolute_expires_at=now + timedelta(days=s.session_absolute_ttl_days),
        last_used_at=now,
        ip_address=ctx.ip,
        user_agent=(ctx.user_agent or "")[:512] or None,
        mfa_verified=mfa_verified,
    )
    db.add(session)
    db.flush()
    access, exp = create_access_token(user_id=user.id, tenant_id=tenant_id, role=role.value, session_id=session.id,
                                      platform_admin=user.is_platform_admin)
    return SessionTokens(access, exp, raw, session.expires_at, session.id, user, tenant_id, role)


def authenticate(db: Session, email: str, password: str) -> LoginOutcome:
    s = get_settings()
    email_n = normalize_email(email)
    user = db.execute(select(User).where(User.email == email_n)).scalar_one_or_none()
    now = _now()

    if user is None or not user.is_active or user.password_hash is None:
        verify_password(password, None)  # equalize timing
        audit.record(db, Action.LOGIN_FAILED, actor=email_n[:320], success=False,
                     new={"reason": "unknown_or_inactive"})
        db.commit()
        raise Unauthorized(GENERIC_LOGIN_ERROR)

    if user.locked_until and user.locked_until > now:
        audit.record(db, Action.LOGIN_FAILED, user_id=user.id, actor=user.email, success=False,
                     new={"reason": "locked"})
        db.commit()
        raise Unauthorized(GENERIC_LOGIN_ERROR)

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        reason = "bad_password"
        if user.failed_login_count >= s.account_lockout_threshold:
            user.locked_until = now + timedelta(minutes=s.account_lockout_minutes)
            user.failed_login_count = 0
            reason = "bad_password_locked"
        audit.record(db, Action.LOGIN_FAILED, user_id=user.id, actor=user.email, success=False,
                     new={"reason": reason}, tenant_id=user.default_tenant_id)
        db.commit()
        raise Unauthorized(GENERIC_LOGIN_ERROR)

    user.failed_login_count = 0
    user.locked_until = None
    if password_needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
    tenant_id, role = resolve_tenant(db, user)

    if user.mfa_enabled:
        db.commit()
        return LoginOutcome(mfa_required=True, mfa_token=create_mfa_challenge(user.id, tenant_id))

    user.last_login_at = now
    tokens = _issue_session(db, user, tenant_id, role, mfa_verified=False)
    audit.record(db, Action.LOGIN, tenant_id=tenant_id, user_id=user.id, actor=user.email,
                 object_type="session", object_id=tokens.session_id)
    db.commit()
    return LoginOutcome(tokens=tokens)


def _totp(user: User) -> pyotp.TOTP:
    if not user.mfa_secret_encrypted:
        raise ValidationFailed("MFA is not configured")
    secret = crypto.decrypt(user.mfa_secret_encrypted, f"user:{user.id}:mfa").decode()
    return pyotp.TOTP(secret)


def complete_mfa(db: Session, mfa_token: str, code: str) -> SessionTokens:
    try:
        claims = decode_mfa_challenge(mfa_token)
    except jwt.PyJWTError as exc:
        raise Unauthorized("MFA challenge expired or invalid") from exc
    user = db.get(User, uuid.UUID(claims["sub"]))
    if not user or not user.is_active or not user.mfa_enabled:
        raise Unauthorized("MFA challenge expired or invalid")
    if not _totp(user).verify(code.strip(), valid_window=1):
        user.failed_login_count += 1
        if user.failed_login_count >= get_settings().account_lockout_threshold:
            user.locked_until = _now() + timedelta(minutes=get_settings().account_lockout_minutes)
            user.failed_login_count = 0
        audit.record(db, Action.LOGIN_FAILED, user_id=user.id, actor=user.email, success=False,
                     new={"reason": "bad_mfa_code"})
        db.commit()
        raise Unauthorized("Invalid verification code")
    tenant_id, role = resolve_tenant(db, user, uuid.UUID(claims["tid"]) if claims.get("tid") else None)
    user.failed_login_count = 0
    user.last_login_at = _now()
    tokens = _issue_session(db, user, tenant_id, role, mfa_verified=True)
    audit.record(db, Action.LOGIN, tenant_id=tenant_id, user_id=user.id, actor=user.email,
                 object_type="session", object_id=tokens.session_id, new={"mfa": True})
    db.commit()
    return tokens


def refresh(db: Session, raw_refresh: str) -> SessionTokens:
    s = get_settings()
    token_hash = hash_token(raw_refresh)
    now = _now()
    session = db.execute(
        select(UserSession).where(UserSession.refresh_token_hash == token_hash).with_for_update()
    ).scalar_one_or_none()
    if session is None:
        reused = db.execute(select(UserSession).where(UserSession.previous_token_hash == token_hash)).scalar_one_or_none()
        if reused is not None and reused.revoked_at is None:
            # A rotated token was presented again: assume theft, kill the session.
            reused.revoked_at = now
            reused.revoked_reason = "refresh_token_reuse"
            audit.record(db, Action.TOKEN_REUSE, tenant_id=reused.tenant_id, user_id=reused.user_id,
                         object_type="session", object_id=reused.id, success=False)
            db.commit()
        raise Unauthorized("Session expired")
    if session.revoked_at or session.expires_at <= now or session.absolute_expires_at <= now:
        raise Unauthorized("Session expired")
    user = db.get(User, session.user_id)
    if not user or not user.is_active:
        raise Unauthorized("Session expired")
    try:
        tenant_id, role = resolve_tenant(db, user, session.tenant_id)
    except Forbidden as exc:
        session.revoked_at = now
        session.revoked_reason = "membership_revoked"
        db.commit()
        raise Unauthorized("Session expired") from exc

    raw = new_token()
    session.previous_token_hash = session.refresh_token_hash
    session.refresh_token_hash = hash_token(raw)
    session.expires_at = min(now + timedelta(days=s.refresh_token_ttl_days), session.absolute_expires_at)
    session.last_used_at = now
    access, exp = create_access_token(user_id=user.id, tenant_id=tenant_id, role=role.value, session_id=session.id,
                                      platform_admin=user.is_platform_admin)
    db.commit()
    return SessionTokens(access, exp, raw, session.expires_at, session.id, user, tenant_id, role)


def logout(db: Session, session_id: uuid.UUID, user_id: uuid.UUID, tenant_id: uuid.UUID | None) -> None:
    db.execute(update(UserSession).where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
               .values(revoked_at=_now(), revoked_reason="logout"))
    audit.record(db, Action.LOGOUT, tenant_id=tenant_id, user_id=user_id, object_type="session", object_id=session_id)
    db.commit()


def revoke_user_sessions(db: Session, user_id: uuid.UUID, reason: str, tenant_id: uuid.UUID | None = None) -> None:
    q = update(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    if tenant_id:
        q = q.where(UserSession.tenant_id == tenant_id)
    db.execute(q.values(revoked_at=_now(), revoked_reason=reason))


def switch_tenant(db: Session, user_id: uuid.UUID, session_id: uuid.UUID, tenant_id: uuid.UUID) -> SessionTokens:
    user = db.get(User, user_id)
    session = db.get(UserSession, session_id)
    if not user or not session or session.revoked_at:
        raise Unauthorized("Session expired")
    tid, role = resolve_tenant(db, user, tenant_id)
    session.tenant_id = tid
    raw = new_token()
    session.previous_token_hash = session.refresh_token_hash
    session.refresh_token_hash = hash_token(raw)
    access, exp = create_access_token(user_id=user.id, tenant_id=tid, role=role.value, session_id=session.id,
                                      platform_admin=user.is_platform_admin)
    audit.record(db, Action.TENANT_SWITCH, tenant_id=tid, user_id=user.id, actor=user.email,
                 object_type="tenant", object_id=tid)
    db.commit()
    return SessionTokens(access, exp, raw, session.expires_at, session.id, user, tid, role)


# ---------------------------------------------------------------- passwords
def set_password(db: Session, user: User, new_password: str) -> None:
    errors = password_policy_errors(new_password, user.email)
    if errors:
        raise ValidationFailed("Password " + "; ".join(errors), details={"password": errors})
    user.password_hash = hash_password(new_password)
    user.password_changed_at = _now()
    user.failed_login_count = 0
    user.locked_until = None


def change_password(db: Session, user_id: uuid.UUID, current: str, new: str) -> None:
    user = db.get(User, user_id)
    if not user or not verify_password(current, user.password_hash):
        raise Unauthorized("Current password is incorrect")
    set_password(db, user, new)
    revoke_user_sessions(db, user.id, "password_changed")
    audit.record(db, Action.PASSWORD_CHANGED, tenant_id=user.default_tenant_id, user_id=user.id, actor=user.email)
    db.commit()


def request_password_reset(db: Session, email: str) -> tuple[User, str] | None:
    """Create a reset token. Returns (user, raw_token) or None; callers must
    respond identically either way to avoid account enumeration."""
    user = db.execute(select(User).where(User.email == normalize_email(email))).scalar_one_or_none()
    if not user or not user.is_active or user.auth_provider != "local":
        return None
    raw = new_token()
    db.add(PasswordResetToken(user_id=user.id, token_hash=hash_token(raw), requested_ip=get_context().ip,
                              expires_at=_now() + timedelta(minutes=get_settings().password_reset_ttl_minutes)))
    audit.record(db, Action.PASSWORD_RESET_REQUESTED, tenant_id=user.default_tenant_id, user_id=user.id,
                 actor=user.email)
    db.commit()
    return user, raw


def reset_password(db: Session, raw_token: str, new_password: str) -> None:
    now = _now()
    token = db.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == hash_token(raw_token)).with_for_update()
    ).scalar_one_or_none()
    if not token or token.used_at or token.expires_at <= now:
        raise ValidationFailed("This password reset link is invalid or has expired")
    user = db.get(User, token.user_id)
    if not user or not user.is_active:
        raise ValidationFailed("This password reset link is invalid or has expired")
    set_password(db, user, new_password)
    token.used_at = now
    revoke_user_sessions(db, user.id, "password_reset")
    audit.record(db, Action.PASSWORD_RESET, tenant_id=user.default_tenant_id, user_id=user.id, actor=user.email)
    db.commit()


# ---------------------------------------------------------------------- MFA
def mfa_begin_setup(db: Session, user_id: uuid.UUID, password: str) -> tuple[str, str]:
    user = db.get(User, user_id)
    if user is None:
        raise Unauthorized("Unknown user")
    if not verify_password(password, user.password_hash):
        raise Unauthorized("Password is incorrect")
    if user.mfa_enabled:
        raise ValidationFailed("MFA is already enabled")
    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = crypto.encrypt(secret.encode(), f"user:{user.id}:mfa")
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=get_settings().app_name)
    return secret, uri


def mfa_enable(db: Session, user_id: uuid.UUID, code: str) -> None:
    user = db.get(User, user_id)
    if user is None or user.mfa_enabled:
        raise ValidationFailed("MFA setup is not in progress")
    if not _totp(user).verify(code.strip(), valid_window=1):
        raise ValidationFailed("Invalid verification code")
    user.mfa_enabled = True
    audit.record(db, Action.MFA_ENABLED, tenant_id=user.default_tenant_id, user_id=user.id, actor=user.email)
    db.commit()


def mfa_disable(db: Session, user_id: uuid.UUID, password: str, code: str) -> None:
    user = db.get(User, user_id)
    if user is None or not user.mfa_enabled:
        raise ValidationFailed("MFA is not enabled")
    if not verify_password(password, user.password_hash) or not _totp(user).verify(code.strip(), valid_window=1):
        raise Unauthorized("Invalid password or verification code")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    audit.record(db, Action.MFA_DISABLED, tenant_id=user.default_tenant_id, user_id=user.id, actor=user.email)
    db.commit()


# ---------------------------------------------------------------- API tokens
def create_api_token(db: Session, *, tenant_id: uuid.UUID, user: User, name: str, role: Role,
                     expires_at: datetime | None) -> tuple[ApiToken, str]:
    raw = API_TOKEN_PREFIX + new_token(32)
    token = ApiToken(tenant_id=tenant_id, user_id=user.id, name=name, role=role, token_prefix=raw[:12],
                     token_hash=hash_token(raw), expires_at=expires_at)
    db.add(token)
    db.flush()
    audit.record(db, Action.API_TOKEN_CREATED, tenant_id=tenant_id, user_id=user.id, object_type="api_token",
                 object_id=token.id, new={"name": name, "role": role.value})
    return token, raw


def resolve_api_token(db: Session, raw: str) -> tuple[ApiToken, User] | None:
    token = db.execute(select(ApiToken).where(ApiToken.token_hash == hash_token(raw))).scalar_one_or_none()
    now = _now()
    if not token or token.revoked_at or (token.expires_at and token.expires_at <= now):
        return None
    user = db.get(User, token.user_id)
    if not user or not user.is_active:
        return None
    token.last_used_at = now
    return token, user
