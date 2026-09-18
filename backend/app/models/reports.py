from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import JobStatus, ReportFormat, ReportType


class Report(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "reports"

    organization_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    report_type: Mapped[ReportType] = enum_column(ReportType)
    report_format: Mapped[ReportFormat] = enum_column(ReportFormat)
    title: Mapped[str] = mapped_column(String(256))
    parameters: Mapped[dict[str, Any]] = mapped_column(default=dict)
    status: Mapped[JobStatus] = enum_column(JobStatus, default=JobStatus.PENDING)
    storage_key: Mapped[str | None] = mapped_column(String(512))
    size: Mapped[int | None] = mapped_column(BigInteger)
    error: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    completed_at: Mapped[datetime | None]
