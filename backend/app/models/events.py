"""Change events: the heart of continuous ASM."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, UUIDPk, enum_column

from .enums import AssetType, EventType, Severity


class AssetEvent(UUIDPk, TenantScoped, Base):
    __tablename__ = "asset_events"
    __table_args__ = (
        Index("ix_events_tenant_time", "tenant_id", "occurred_at"),
        Index("ix_events_asset_time", "asset_id", "occurred_at"),
        Index("ix_events_org_type", "organization_id", "event_type"),
        Index("ix_events_unnotified", "tenant_id", "notified", "is_baseline"),
    )

    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    # Denormalized for display even if the asset is later deleted.
    asset_type: Mapped[AssetType | None] = enum_column(AssetType, nullable=True)
    asset_value: Mapped[str | None] = mapped_column(String(2048))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)

    event_type: Mapped[EventType] = enum_column(EventType, length=48)
    severity: Mapped[Severity] = enum_column(Severity, default=Severity.INFO)
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str | None] = mapped_column(Text)
    previous_state: Mapped[dict[str, Any] | None]
    new_state: Mapped[dict[str, Any] | None]
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    occurred_at: Mapped[datetime]

    # Events from an organization's first (baseline) scan are recorded but not alerted.
    is_baseline: Mapped[bool] = mapped_column(default=False)
    acknowledged: Mapped[bool] = mapped_column(default=False)
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at: Mapped[datetime | None]
    notified: Mapped[bool] = mapped_column(default=False)
    notified_at: Mapped[datetime | None]
