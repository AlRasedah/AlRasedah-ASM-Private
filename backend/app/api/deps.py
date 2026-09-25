"""Request authentication, authorization and tenant-scoped database sessions."""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import jwt
from asm_sensors import eventlog
from fastapi import Depends, Query, Request
from sqlalchemy.orm import Session

from app.auth import service as auth_service
from app.auth.permissions import Permission, permissions_for
from app.core.context import get_context
from app.core.errors import Forbidden, Unauthorized
from app.core.security import decode_access_token
from app.db.session import new_session, system_session
from app.models import User, UserSession
from app.models.enums import Role


@dataclass
class Principal:
    user_id: uuid.UUID
    email: str
    tenant_id: uuid.UUID | None
    role: Role
    is_platform_admin: bool
    session_id: uuid.UUID | None = None
    api_token_id: uuid.UUID | None = None
    permissions: frozenset[Permission] = field(default_factory=frozenset)

    def can(self, perm: Permission) -> bool:
        return perm in self.permissions

    def require_tenant(self) -> uuid.UUID:
        if self.tenant_id is None:
            raise Forbidden("Select a tenant first")
        return self.tenant_id


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise Unauthorized("Authentication required")
    return token.strip()


def get_principal(request: Request) -> Principal:
    token = _bearer(request)
    with system_session() as db:
        if token.startswith(auth_service.API_TOKEN_PREFIX):
            found = auth_service.resolve_api_token(db, token)
            if not found:
                raise Unauthorized("Invalid API token")
            api_token, user = found
            membership = auth_service.active_membership(db, user, api_token.tenant_id)
            if membership is None and not user.is_platform_admin:
                raise Unauthorized("Invalid API token")
            # The token never grants more than its owner currently has.
            owner_role = Role.PLATFORM_ADMIN if user.is_platform_admin else membership.role  # type: ignore[union-attr]
            from app.auth.permissions import ROLE_RANK

            role = api_token.role if ROLE_RANK[api_token.role] <= ROLE_RANK[owner_role] else owner_role
            db.commit()
            principal = Principal(user.id, user.email, api_token.tenant_id, role, False, api_token_id=api_token.id,
                                  permissions=permissions_for(role))
        else:
            try:
                claims = decode_access_token(token)
            except jwt.ExpiredSignatureError as exc:
                raise Unauthorized("Access token expired", code="token_expired") from exc
            except jwt.PyJWTError as exc:
                raise Unauthorized("Invalid access token") from exc
            session = db.get(UserSession, uuid.UUID(claims["sid"]))
            now = datetime.now(UTC)
            if session is None or session.revoked_at or session.absolute_expires_at <= now:
                raise Unauthorized("Session expired")
            user = db.get(User, uuid.UUID(claims["sub"]))
            if user is None or not user.is_active:
                raise Unauthorized("Session expired")
            tenant_id = uuid.UUID(claims["tid"]) if claims.get("tid") else None
            if tenant_id != session.tenant_id:
                raise Unauthorized("Session expired")
            if user.is_platform_admin:
                role = Role.PLATFORM_ADMIN
            elif tenant_id is None:
                raise Forbidden("No tenant selected")
            else:
                membership = auth_service.active_membership(db, user, tenant_id)
                if membership is None:
                    raise Unauthorized("Session expired")
                role = membership.role  # always the *current* role, not the one in the token
            principal = Principal(user.id, user.email, tenant_id, role, user.is_platform_admin,
                                  session_id=session.id, permissions=permissions_for(role))
    ctx = get_context()
    ctx.user_id, ctx.actor, ctx.tenant_id = principal.user_id, principal.email, principal.tenant_id
    # Tenant and user in operational events come from the authenticated principal only.
    eventlog.annotate(tenant_id=principal.tenant_id, user_id=principal.user_id)
    return principal


def require(*perms: Permission) -> Callable[..., Principal]:
    def _dep(principal: Principal = Depends(get_principal)) -> Principal:
        missing = [p for p in perms if not principal.can(p)]
        if missing:
            raise Forbidden(f"Missing permission: {missing[0].value}")
        return principal

    return _dep


def get_db(principal: Principal = Depends(get_principal)) -> Iterator[Session]:
    """A session bound to the caller's tenant: RLS confines every query to it."""
    db = new_session(principal.tenant_id, user_id=principal.user_id)
    try:
        yield db
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def get_system_db() -> Iterator[Session]:
    db = system_session()
    try:
        yield db
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


class Paging:
    def __init__(self, page: int = Query(1, ge=1, le=100_000),
                 page_size: int = Query(50, ge=1, le=500)) -> None:
        self.page = page
        self.page_size = page_size

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size
