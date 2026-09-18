"""Scan profiles, scans, stages, schedules, authorization decisions, artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import DecisionResult, ScanStatus, ScanTrigger, StageStatus, StageType


class ScanProfile(UUIDPk, Timestamps, Base):
    """Reusable pipeline definition. ``tenant_id`` NULL = built-in/global profile.

    ``stages`` is an ordered list of ``{"stage": <StageType>, "engine": <adapter>,
    "config": {...}, "enabled": bool}``. Engines are an implementation detail;
    the UI presents stages in Exteriq terms.
    """

    __tablename__ = "scan_profiles"
    __table_args__ = (UniqueConstraint("tenant_id", "slug"),)

    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    slug: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    stages: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list)
    is_builtin: Mapped[bool] = mapped_column(default=False)
    is_active_scanning: Mapped[bool] = mapped_column(default=False)
    retain_raw_output: Mapped[bool] = mapped_column(default=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Scan(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_tenant_status", "tenant_id", "status"),
                      Index("ix_scans_org_created", "organization_id", "created_at"))

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    profile_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_profiles.id", ondelete="SET NULL"))
    profile_name: Mapped[str] = mapped_column(String(128))
    # The profile as it was when the scan was created (profiles may change later).
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[ScanStatus] = enum_column(ScanStatus, default=ScanStatus.PENDING)
    trigger: Mapped[ScanTrigger] = enum_column(ScanTrigger, default=ScanTrigger.MANUAL)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_schedules.id", ondelete="SET NULL"))
    # Optional explicit subset of targets (must still be in scope).
    target_override: Mapped[list[str] | None] = mapped_column(
        ARRAY(String(255)))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    is_baseline: Mapped[bool] = mapped_column(default=False)

    stages: Mapped[list[ScanStage]] = relationship(
        back_populates="scan", order_by="ScanStage.position", lazy="selectin", cascade="all, delete-orphan")


class ScanStage(UUIDPk, TenantScoped, Base):
    __tablename__ = "scan_stages"
    __table_args__ = (UniqueConstraint("scan_id", "position"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(SmallInteger)
    stage_type: Mapped[StageType] = enum_column(StageType)
    engine: Mapped[str] = mapped_column(String(64))
    config: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[StageStatus] = enum_column(StageStatus, default=StageStatus.PENDING)
    is_active: Mapped[bool] = mapped_column(default=False)
    target_count: Mapped[int] = mapped_column(Integer, default=0)
    rejected_count: Mapped[int] = mapped_column(Integer, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, default=0)
    task_id: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    tool_version: Mapped[str | None] = mapped_column(String(64))
    stats: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[Scan] = relationship(back_populates="stages")


class ScopeDecision(TenantScoped, Base):
    """Audit trail of every target authorization decision made before scanning."""

    __tablename__ = "scope_decisions"
    __table_args__ = (Index("ix_scope_decisions_scan", "scan_id", "decision"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    stage_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_stages.id", ondelete="CASCADE"))
    target: Mapped[str] = mapped_column(String(2048))
    decision: Mapped[DecisionResult] = enum_column(DecisionResult)
    reason: Mapped[str] = mapped_column(String(255))
    matched_entry_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scope_entries.id", ondelete="SET NULL"))
    active: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class ScanSchedule(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "scan_schedules"

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    profile_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scan_profiles.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    cron: Mapped[str] = mapped_column(String(64))
    timezone: Mapped[str] = mapped_column(String(64), default="Asia/Riyadh")
    enabled: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(index=True)
    last_run_at: Mapped[datetime | None]
    last_scan_id: Mapped[uuid.UUID | None]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ScanArtifact(UUIDPk, TenantScoped, Base):
    """Raw sensor output retained in object storage for troubleshooting."""

    __tablename__ = "scan_artifacts"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    stage_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_stages.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(128))
    storage_key: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[str] = mapped_column(String(128), default="application/gzip")
    size: Mapped[int] = mapped_column(BigInteger)
    sha256: Mapped[str] = mapped_column(String(64))
    truncated: Mapped[bool] = mapped_column(default=False)
    expires_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
