"""Operational records: recent warnings/errors, export cursors, support bundles, setup tokens."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Identity, Index, Integer, String, Text, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, Timestamps, UUIDPk


class OpsEvent(Base):
    """A redacted WARNING-or-above operational event (platform-only; system sessions)."""

    __tablename__ = "ops_events"
    __table_args__ = (Index("ix_ops_events_ts", "ts"), Index("ix_ops_events_tenant_ts", "tenant_id", "ts"))

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(80), unique=True)
    ts: Mapped[datetime]
    level: Mapped[str] = mapped_column(String(16))
    service: Mapped[str] = mapped_column(String(32))
    event: Mapped[str] = mapped_column(String(120))
    error_code: Mapped[str | None] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text)
    logger: Mapped[str] = mapped_column(String(120))
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    request_id: Mapped[str | None] = mapped_column(String(128))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    stage_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    job_id: Mapped[str | None] = mapped_column(String(128))
    pool: Mapped[str | None] = mapped_column(String(64))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class EventExportState(Base):
    """Where an append-only export (audit) has got to, and the ids it is still waiting for."""

    __tablename__ = "event_export_state"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    cursor: Mapped[int] = mapped_column(BigInteger, default=0)
    gaps: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime | None]


class SupportBundle(UUIDPk, Timestamps, Base):
    """A generated diagnostics archive. ``tenant_id`` NULL = a platform bundle (platform
    administrators only); otherwise tenant-owned and tenant-isolated by RLS."""

    __tablename__ = "support_bundles"
    __table_args__ = (Index("ix_support_bundles_tenant", "tenant_id", "created_at"),
                      Index("ix_support_bundles_active", "status", postgresql_where=text("status IN ('queued', 'running')")))

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"))
    scope: Mapped[str] = mapped_column(String(16))  # platform | tenant
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    window_start: Mapped[datetime]
    window_end: Mapped[datetime]
    scan_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    organization_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|ready|failed
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(String(500))
    storage_key: Mapped[str | None] = mapped_column(String(512))
    filename: Mapped[str | None] = mapped_column(String(200))
    size: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    expires_at: Mapped[datetime]


class SetupToken(Base):
    """The one-time token the installer prints for creating the first administrator.
    Stored hashed; single use; short-lived. Platform-only table."""

    __tablename__ = "setup_tokens"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=text("now()"))
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
