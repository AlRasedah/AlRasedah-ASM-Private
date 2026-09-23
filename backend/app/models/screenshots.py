"""Website screenshots: one row per capture attempt; the image itself lives in private
object storage under a key the platform derives from the row id."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Index, Integer, SmallInteger, String, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import ScreenshotStatus


class ScreenshotCapture(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "screenshot_captures"
    __table_args__ = (
        Index("ix_screenshots_asset_time", "asset_id", "created_at"),
        Index("ix_screenshots_tenant_time", "tenant_id", "created_at"),
        # The dispatcher's question, across tenants: what is queued or running?
        Index("ix_screenshots_active", "status", "created_at",
              postgresql_where=text("status IN ('queued', 'running')")),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    url: Mapped[str] = mapped_column(String(2048))
    trigger: Mapped[str] = mapped_column(String(16), default="manual")  # manual | scheduled
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[ScreenshotStatus] = enum_column(ScreenshotStatus, default=ScreenshotStatus.QUEUED)
    # Human-readable, sanitized reason for failed/blocked (never a raw tool message or a query string).
    error: Mapped[str | None] = mapped_column(String(500))

    # Job binding: a submitted result is accepted only for this job, from this pool.
    task_id: Mapped[str | None] = mapped_column(String(64))
    worker_pool: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None]
    dispatched_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]

    # Filled on success.
    captured_at: Mapped[datetime | None]
    final_url: Mapped[str | None] = mapped_column(String(2048))
    page_title: Mapped[str | None] = mapped_column(String(300))
    http_status: Mapped[int | None] = mapped_column(SmallInteger)
    storage_key: Mapped[str | None] = mapped_column(String(512))
    content_type: Mapped[str | None] = mapped_column(String(64))
    size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    width: Mapped[int | None] = mapped_column(Integer)
    height: Mapped[int | None] = mapped_column(Integer)
