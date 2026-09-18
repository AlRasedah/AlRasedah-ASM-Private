"""Tenants, subscription plans (billing-ready, no payments), organizations, usage."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import BigInteger, Date, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import TenantStatus


class Plan(UUIDPk, Timestamps, Base):
    """Subscription plan / quota envelope. Global (not tenant scoped)."""

    __tablename__ = "plans"

    code: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)
    max_organizations: Mapped[int | None] = mapped_column(Integer)
    max_assets: Mapped[int | None] = mapped_column(Integer)
    max_users: Mapped[int | None] = mapped_column(Integer)
    max_scans_per_day: Mapped[int | None] = mapped_column(Integer)
    max_concurrent_scans: Mapped[int] = mapped_column(Integer, default=2)
    allow_active_scanning: Mapped[bool] = mapped_column(default=True)
    features: Mapped[dict[str, Any]] = mapped_column(default=dict)
    is_default: Mapped[bool] = mapped_column(default=False)
    # Billing placeholders for a future SaaS offering.
    billing_interval: Mapped[str | None] = mapped_column(String(16))
    price_minor_units: Mapped[int | None] = mapped_column(BigInteger)
    currency: Mapped[str | None] = mapped_column(String(3))


class Tenant(UUIDPk, Timestamps, Base):
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    status: Mapped[TenantStatus] = enum_column(TenantStatus, default=TenantStatus.ACTIVE)
    plan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("plans.id", ondelete="SET NULL"))
    # Dedicated sensor pool (queue suffix) for isolation/throughput in SaaS.
    worker_pool: Mapped[str] = mapped_column(String(64), default="default")
    data_region: Mapped[str | None] = mapped_column(String(64))
    # Tenant-level configuration: risk weights, inactivity rules, detection rules...
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Future: billing customer id, subscription state.
    billing: Mapped[dict[str, Any]] = mapped_column(default=dict)

    plan: Mapped[Plan | None] = relationship(lazy="joined")


class Organization(UUIDPk, TenantScoped, Timestamps, Base):
    """A monitored organization (company, subsidiary, or an MSSP's customer)."""

    __tablename__ = "organizations"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    industry: Mapped[str | None] = mapped_column(String(100))
    # e.g. {"derived_ip_scanning": true, "skip_cdn_ips": true}
    settings: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Set once the first complete scan finished; events before it are "baseline".
    baseline_completed_at: Mapped[datetime | None]
    is_active: Mapped[bool] = mapped_column(default=True)


class UsageRecord(UUIDPk, TenantScoped, Base):
    """Metered usage for quotas and future billing."""

    __tablename__ = "usage_records"

    metric: Mapped[str] = mapped_column(String(64), index=True)  # scans, sensor_seconds, assets, reports
    quantity: Mapped[int] = mapped_column(BigInteger, default=1)
    period: Mapped[date] = mapped_column(Date, server_default=func.current_date(), index=True)
    reference_id: Mapped[uuid.UUID | None]
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    recorded_at: Mapped[datetime] = mapped_column(server_default=func.now())


class MetricSnapshot(UUIDPk, TenantScoped, Base):
    """Daily attack-surface metrics per organization, for trends."""

    __tablename__ = "metric_snapshots"
    __table_args__ = (UniqueConstraint("tenant_id", "organization_id", "day"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    day: Mapped[date] = mapped_column(Date)
    total_assets: Mapped[int] = mapped_column(Integer, default=0)
    active_assets: Mapped[int] = mapped_column(Integer, default=0)
    new_assets: Mapped[int] = mapped_column(Integer, default=0)
    unknown_assets: Mapped[int] = mapped_column(Integer, default=0)
    open_findings: Mapped[dict[str, Any]] = mapped_column(default=dict)  # severity -> count
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    details: Mapped[dict[str, Any]] = mapped_column(default=dict)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
