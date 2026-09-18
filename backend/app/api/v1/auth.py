"""Authentication endpoints.

Access tokens are short-lived JWTs held in memory by the SPA. Refresh tokens
are opaque, rotated on every use, stored hashed server-side and delivered as
an ``HttpOnly; SameSite=Strict`` cookie scoped to ``/api/v1/auth``. The refresh
endpoint additionally requires a double-submit CSRF token.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_principal, get_system_db, require
from app.auth import service as auth
from app.auth.permissions import Permission, can_assign
from app.core.config import get_settings
from app.core.context import get_context
from app.core.errors import Forbidden, NotFound, RateLimited, Unauthorized
from app.core.rate_limit import get_rate_limiter
from app.core.security import new_token
from app.models import ApiToken, Tenant, TenantMembership, User
from app.models.enums import Role, TenantStatus
from app.schemas.auth import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenOut,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    LoginRequest,
    Membership,
    MeResponse,
    MfaCodeRequest,
    MfaDisableRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    ResetPasswordRequest,
    SwitchTenantRequest,
    TenantRef,
    TokenResponse,
    UserOut,
)
from app.schemas.common import Message
from app.services import audit
from app.services.audit import Action

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger(__name__)

REFRESH_COOKIE = "asm_refresh"
CSRF_COOKIE = "asm_csrf"
COOKIE_PATH = "/api/v1/auth"


def _set_session_cookies(response: Response, tokens: auth.SessionTokens) -> None:
    s = get_settings()
    max_age = int((tokens.refresh_expires_at - datetime.now(UTC)).total_seconds())
    response.set_cookie(REFRESH_COOKIE, tokens.refresh_token, max_age=max_age, httponly=True, secure=s.cookie_secure,
                        samesite="strict", path=COOKIE_PATH, domain=s.cookie_domain)
    # Readable by the SPA, echoed in X-CSRF-Token (double submit).
    response.set_cookie(CSRF_COOKIE, new_token(16), max_age=max_age, httponly=False, secure=s.cookie_secure,
                        samesite="strict", path="/", domain=s.cookie_domain)


def _clear_cookies(response: Response) -> None:
    s = get_settings()
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH, domain=s.cookie_domain)
    response.delete_cookie(CSRF_COOKIE, path="/", domain=s.cookie_domain)


def _token_response(tokens: auth.SessionTokens) -> TokenResponse:
    return TokenResponse(access_token=tokens.access_token,
                         expires_in=int((tokens.access_expires_at - datetime.now(UTC)).total_seconds()))


def _limit(key: str, limit: int) -> None:
    if not get_rate_limiter().hit(key, limit, 60):
        raise RateLimited("Too many attempts. Try again in a minute.")


@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, response: Response, db: Session = Depends(get_system_db)) -> TokenResponse:
    s = get_settings()
    ip = get_context().ip or "unknown"
    _limit(f"login:ip:{ip}", s.login_rate_limit_per_minute)
    _limit(f"login:email:{body.email.lower()}", s.login_rate_limit_per_minute)
    outcome = auth.authenticate(db, body.email, body.password)
    if outcome.mfa_required:
        return TokenResponse(mfa_required=True, mfa_token=outcome.mfa_token)
    assert outcome.tokens is not None
    _set_session_cookies(response, outcome.tokens)
    return _token_response(outcome.tokens)


@router.post("/mfa/verify", response_model=TokenResponse)
def mfa_verify(body: MfaVerifyRequest, response: Response, db: Session = Depends(get_system_db)) -> TokenResponse:
    _limit(f"mfa:ip:{get_context().ip or 'unknown'}", get_settings().login_rate_limit_per_minute)
    tokens = auth.complete_mfa(db, body.mfa_token, body.code)
    _set_session_cookies(response, tokens)
    return _token_response(tokens)


@router.post("/refresh", response_model=TokenResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_system_db)) -> TokenResponse:
    raw = request.cookies.get(REFRESH_COOKIE)
    csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
    csrf_header = request.headers.get("x-csrf-token", "")
    if not raw:
        raise Unauthorized("No session")
    if not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise Forbidden("CSRF validation failed", code="csrf_failed")
    try:
        tokens = auth.refresh(db, raw)
    except Unauthorized:
        _clear_cookies(response)
        raise
    _set_session_cookies(response, tokens)
    return _token_response(tokens)


@router.post("/logout", response_model=Message)
def logout(response: Response, principal: Principal = Depends(get_principal),
           db: Session = Depends(get_system_db)) -> Message:
    if principal.session_id:
        auth.logout(db, principal.session_id, principal.user_id, principal.tenant_id)
    _clear_cookies(response)
    return Message(message="Signed out")


@router.get("/me", response_model=MeResponse)
def me(principal: Principal = Depends(get_principal), db: Session = Depends(get_system_db)) -> MeResponse:
    user = db.get(User, principal.user_id)
    assert user is not None
    rows = db.execute(select(TenantMembership, Tenant).join(Tenant, Tenant.id == TenantMembership.tenant_id).where(
        TenantMembership.user_id == user.id, TenantMembership.is_active.is_(True),
        Tenant.status == TenantStatus.ACTIVE).order_by(Tenant.name)).all()
    memberships = [Membership(tenant=TenantRef.model_validate(t), role=m.role) for m, t in rows]
    tenant = db.get(Tenant, principal.tenant_id) if principal.tenant_id else None
    return MeResponse(user=UserOut.model_validate(user), tenant=TenantRef.model_validate(tenant) if tenant else None,
                      role=principal.role, permissions=sorted(p.value for p in principal.permissions),
                      memberships=memberships)


@router.post("/switch-tenant", response_model=TokenResponse)
def switch_tenant(body: SwitchTenantRequest, response: Response, principal: Principal = Depends(get_principal),
                  db: Session = Depends(get_system_db)) -> TokenResponse:
    if not principal.session_id:
        raise Forbidden("API tokens are bound to a single tenant")
    tokens = auth.switch_tenant(db, principal.user_id, principal.session_id, body.tenant_id)
    _set_session_cookies(response, tokens)
    return _token_response(tokens)


@router.post("/password/forgot", response_model=Message, status_code=status.HTTP_202_ACCEPTED)
def forgot_password(body: ForgotPasswordRequest, db: Session = Depends(get_system_db)) -> Message:
    _limit(f"forgot:ip:{get_context().ip or 'unknown'}", 5)
    _limit(f"forgot:email:{body.email.lower()}", 3)
    created = auth.request_password_reset(db, body.email)
    if created:
        user, raw = created
        from app.integrations.mailer import send_password_reset

        try:
            send_password_reset(user.email, raw)
        except Exception:  # noqa: BLE001 - never reveal delivery problems to the requester
            log.exception("password reset email could not be sent")
    # Identical response whether or not the account exists (no enumeration).
    return Message(message="If the account exists, a password reset link has been sent.")


@router.post("/password/reset", response_model=Message)
def reset_password(body: ResetPasswordRequest, db: Session = Depends(get_system_db)) -> Message:
    _limit(f"reset:ip:{get_context().ip or 'unknown'}", 10)
    auth.reset_password(db, body.token, body.new_password)
    return Message(message="Password updated. Please sign in.")


@router.post("/password/change", response_model=Message)
def change_password(body: ChangePasswordRequest, response: Response, principal: Principal = Depends(get_principal),
                    db: Session = Depends(get_system_db)) -> Message:
    auth.change_password(db, principal.user_id, body.current_password, body.new_password)
    _clear_cookies(response)
    return Message(message="Password changed. All sessions were signed out.")


@router.post("/mfa/setup", response_model=MfaSetupResponse)
def mfa_setup(principal: Principal = Depends(get_principal), db: Session = Depends(get_system_db)) -> MfaSetupResponse:
    secret, uri = auth.mfa_begin_setup(db, principal.user_id)
    return MfaSetupResponse(secret=secret, otpauth_uri=uri)


@router.post("/mfa/enable", response_model=Message)
def mfa_enable(body: MfaCodeRequest, principal: Principal = Depends(get_principal),
               db: Session = Depends(get_system_db)) -> Message:
    auth.mfa_enable(db, principal.user_id, body.code)
    return Message(message="Two-factor authentication enabled")


@router.post("/mfa/disable", response_model=Message)
def mfa_disable(body: MfaDisableRequest, principal: Principal = Depends(get_principal),
                db: Session = Depends(get_system_db)) -> Message:
    auth.mfa_disable(db, principal.user_id, body.password, body.code)
    return Message(message="Two-factor authentication disabled")


# ------------------------------------------------------------------ API tokens
@router.get("/api-tokens", response_model=list[ApiTokenOut])
def list_api_tokens(principal: Principal = Depends(get_principal), db: Session = Depends(get_system_db)) -> list:
    tid = principal.require_tenant()
    return list(db.execute(select(ApiToken).where(ApiToken.tenant_id == tid, ApiToken.user_id == principal.user_id)
                           .order_by(ApiToken.created_at.desc())).scalars())


@router.post("/api-tokens", response_model=ApiTokenCreated, status_code=201)
def create_api_token(body: ApiTokenCreate, principal: Principal = Depends(require(Permission.ASSETS_READ)),
                     db: Session = Depends(get_system_db)) -> ApiTokenCreated:
    tid = principal.require_tenant()
    if principal.api_token_id:
        raise Forbidden("API tokens cannot create API tokens")
    if not can_assign(principal.role if principal.role != Role.PLATFORM_ADMIN else Role.TENANT_ADMIN, body.role):
        raise Forbidden("You cannot create a token with a role above your own")
    user = db.get(User, principal.user_id)
    assert user is not None
    token, raw = auth.create_api_token(db, tenant_id=tid, user=user, name=body.name, role=body.role,
                                       expires_at=body.expires_at)
    db.commit()
    return ApiTokenCreated(**ApiTokenOut.model_validate(token).model_dump(), token=raw)


@router.delete("/api-tokens/{token_id}", response_model=Message)
def revoke_api_token(token_id: uuid.UUID, principal: Principal = Depends(get_principal),
                     db: Session = Depends(get_system_db)) -> Message:
    token = db.get(ApiToken, token_id)
    if token is None or token.user_id != principal.user_id or token.tenant_id != principal.tenant_id:
        raise NotFound("API token not found")
    token.revoked_at = datetime.now(UTC)
    audit.record(db, Action.API_TOKEN_REVOKED, tenant_id=token.tenant_id, object_type="api_token", object_id=token.id)
    db.commit()
    return Message(message="Token revoked")
