"""Platform-wide configuration and per-user alert preferences.

Both exist so the product can be operated from the web interface: a platform
administrator configures mail delivery without editing ``.env`` or restarting a
container, and every user chooses what lands in their own inbox.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import Severity


class PlatformSetting(Timestamps, Base):
    """Single-row table (id = 1) with settings that apply to the whole deployment.

    Only platform administrators may read or write it; tenant sessions never
    touch it (system sessions only). The SMTP password is encrypted like every
    other stored secret.
    """

    __tablename__ = "platform_settings"
    __table_args__ = (CheckConstraint("id = 1", name="ck_platform_settings_single_row"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=False, default=1)
    # {"host", "port", "username", "sender", "starttls", "ssl"} — no secret here.
    smtp: Mapped[dict[str, Any]] = mapped_column(default=dict)
    smtp_password_ciphertext: Mapped[str | None] = mapped_column(Text)
    # Website screenshot policy (app/screenshots/service.py DEFAULT_POLICY): availability,
    # deployment-wide concurrency, per-tenant quotas, retention and capture limits.
    screenshots: Mapped[dict[str, Any]] = mapped_column(default=dict)
    updated_by:Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class UserAlertPreference(UUIDPk, TenantScoped, Timestamps, Base):
    """What a user wants emailed to their own login address, per tenant.

    No row means the default: enabled for high and critical changes. Users can
    only ever receive events from tenants they are a member of, and delivery
    uses their verified login address — never an address they typed.
    """

    __tablename__ = "user_alert_preferences"
    __table_args__ = (UniqueConstraint("tenant_id", "user_id"),)

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    enabled: Mapped[bool] = mapped_column(default=True)
    min_severity: Mapped[Severity] = enum_column(Severity, default=Severity.HIGH)
    # Empty lists mean "everything the user may see".
    event_types: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    organization_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    include_baseline: Mapped[bool] = mapped_column(default=False)
    last_sent_at: Mapped[datetime | None]
