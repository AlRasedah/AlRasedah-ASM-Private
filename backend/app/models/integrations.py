"""Integrations, notification policies and delivery log."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import DeliveryStatus, IntegrationType, Severity


class Integration(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "integrations"

    name: Mapped[str] = mapped_column(String(128))
    integration_type: Mapped[IntegrationType] = enum_column(IntegrationType)
    # Non-secret configuration only (URLs, recipients, formats). Secrets live in
    # the secrets table and are referenced by id.
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    secret_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("secrets.id", ondelete="SET NULL"))
    enabled: Mapped[bool] = mapped_column(default=True)
    last_success_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    last_error_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class NotificationPolicy(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "notification_policies"

    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(default=True)
    event_types: Mapped[list[str]] = mapped_column(ARRAY(String(48)), default=list)  # empty = all
    min_severity: Mapped[Severity] = enum_column(Severity, default=Severity.HIGH)
    organization_ids: Mapped[list[uuid.UUID] | None] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)))
    integration_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), default=list)
    include_baseline: Mapped[bool] = mapped_column(default=False)
    # Collapse bursts: at most one delivery per (policy, event_type, asset) within this window.
    throttle_minutes: Mapped[int] = mapped_column(Integer, default=0)


class NotificationDelivery(UUIDPk, TenantScoped, Base):
    __tablename__ = "notification_deliveries"
    __table_args__ = (Index("ix_deliveries_status", "tenant_id", "status"),)

    event_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("asset_events.id", ondelete="CASCADE"), index=True)
    policy_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("notification_policies.id", ondelete="SET NULL"))
    integration_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("integrations.id", ondelete="CASCADE"))
    # Set instead of `integration_id` for a personal alert: the member it was mailed to,
    # at their login address. Personal mail needs a durable row like any other delivery,
    # or a momentary SMTP failure loses a high-severity alert with nothing to retry.
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    status: Mapped[DeliveryStatus] = enum_column(DeliveryStatus, default=DeliveryStatus.PENDING)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    sent_at: Mapped[datetime | None]
