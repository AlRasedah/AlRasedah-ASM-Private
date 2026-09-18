"""Normalized, de-duplicated findings with workflow history."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Float, ForeignKey, Index, Integer, SmallInteger, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import FindingCategory, FindingStatus, RiskLevel, Severity


class Finding(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "findings"
    __table_args__ = (
        # Deduplication: one row per (tenant, fingerprint) for the lifetime of the issue.
        UniqueConstraint("tenant_id", "fingerprint"),
        Index("ix_findings_tenant_status_sev", "tenant_id", "status", "severity"),
        Index("ix_findings_asset", "asset_id"),
        Index("ix_findings_risk", "tenant_id", "risk_score"),
        Index("ix_findings_cve", "cve", postgresql_using="gin"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(64))

    source: Mapped[str] = mapped_column(String(64))  # sensor or detection rule engine (internal)
    source_finding_id: Mapped[str] = mapped_column(String(512))  # e.g. template/rule id
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    category: Mapped[FindingCategory] = enum_column(FindingCategory, default=FindingCategory.VULNERABILITY)
    severity: Mapped[Severity] = enum_column(Severity, default=Severity.INFO)
    location: Mapped[str | None] = mapped_column(String(1024))

    cve: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    cwe: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    kev: Mapped[bool] = mapped_column(default=False)
    kev_due_date: Mapped[datetime | None]
    exploit_available: Mapped[bool] = mapped_column(default=False)

    evidence: Mapped[dict[str, Any]] = mapped_column(default=dict)
    remediation: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(ARRAY(String(1024)), default=list)
    confidence: Mapped[int] = mapped_column(SmallInteger, default=90)

    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    resolved_at: Mapped[datetime | None]
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    missed_count: Mapped[int] = mapped_column(SmallInteger, default=0)

    status: Mapped[FindingStatus] = enum_column(FindingStatus, default=FindingStatus.NEW)
    false_positive: Mapped[bool] = mapped_column(default=False)
    accepted_until: Mapped[datetime | None]  # risk acceptance expiry
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    notes: Mapped[str | None] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)

    risk_score: Mapped[int] = mapped_column(SmallInteger, default=0)
    risk_level: Mapped[RiskLevel] = enum_column(RiskLevel, default=RiskLevel.INFO)
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)


class FindingActivity(UUIDPk, TenantScoped, Base):
    """Immutable history: detection, re-detection, status changes, comments."""

    __tablename__ = "finding_activities"
    __table_args__ = (Index("ix_finding_activities_finding", "finding_id", "created_at"),)

    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # detected | resolved | reopened | status | assignment | comment | tags
    activity_type: Mapped[str] = mapped_column(String(32))
    previous: Mapped[dict[str, Any] | None]
    new: Mapped[dict[str, Any] | None]
    comment: Mapped[str | None] = mapped_column(Text)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
