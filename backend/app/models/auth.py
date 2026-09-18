"""Users, tenant memberships, sessions, reset tokens, API tokens."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import Role


class User(UUIDPk, Timestamps, Base):
    """A global identity. Tenant access is granted through memberships."""

    __tablename__ = "users"

    # Always stored lower-cased (normalized by the service layer).
    email: Mapped[str] = mapped_column(String(320), unique=True)
    full_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(default=True)
    is_platform_admin: Mapped[bool] = mapped_column(default=False)
    # MFA (TOTP today; WebAuthn later). Secret is encrypted with app.core.crypto.
    mfa_enabled: Mapped[bool] = mapped_column(default=False)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(String(512))
    # Federation-ready (SAML/OIDC/Entra ID/Google Workspace later).
    auth_provider: Mapped[str] = mapped_column(String(32), default="local")
    external_id: Mapped[str | None] = mapped_column(String(255))
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]
    password_changed_at: Mapped[datetime | None]
    default_tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="SET NULL"))

    memberships: Mapped[list[TenantMembership]] = relationship(back_populates="user", lazy="selectin")


class TenantMembership(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "tenant_memberships"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    role: Mapped[Role] = enum_column(Role, default=Role.VIEWER)
    is_active: Mapped[bool] = mapped_column(default=True)

    user: Mapped[User] = relationship(back_populates="memberships")


class UserSession(UUIDPk, Base):
    """A login session. Refresh tokens rotate on every use; reuse of a rotated
    token revokes the whole session (token theft detection)."""

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    refresh_token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    previous_token_hash: Mapped[str | None] = mapped_column(String(128), index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    last_used_at: Mapped[datetime | None]
    expires_at: Mapped[datetime]
    absolute_expires_at: Mapped[datetime]
    revoked_at: Mapped[datetime | None]
    revoked_reason: Mapped[str | None] = mapped_column(String(64))
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    mfa_verified: Mapped[bool] = mapped_column(default=False)


class PasswordResetToken(UUIDPk, Base):
    __tablename__ = "password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    requested_ip: Mapped[str | None] = mapped_column(String(64))


class ApiToken(UUIDPk, TenantScoped, Base):
    """Long-lived personal/service API tokens for automation (SIEM, CI)."""

    __tablename__ = "api_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(128))
    token_prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(128), unique=True)
    role: Mapped[Role] = enum_column(Role, default=Role.VIEWER)
    expires_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
