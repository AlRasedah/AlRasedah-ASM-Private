"""Normalized asset inventory, the relationship graph and observation history."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Identity, Index, Integer, SmallInteger, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import ApprovalStatus, AssetStatus, AssetType, Criticality, RelationType, RiskLevel, ScopeStatus


class Asset(UUIDPk, TenantScoped, Timestamps, Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "organization_id", "asset_type", "normalized_value"),
        Index("ix_assets_tenant_type_status", "tenant_id", "asset_type", "status"),
        Index("ix_assets_org_status", "organization_id", "status"),
        Index("ix_assets_risk", "tenant_id", "risk_score"),
        Index("ix_assets_first_seen", "tenant_id", "first_seen"),
        Index("ix_assets_tags", "tags", postgresql_using="gin"),
        Index("ix_assets_value_trgm", "normalized_value", postgresql_using="gin",
              postgresql_ops={"normalized_value": "gin_trgm_ops"}),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    asset_type: Mapped[AssetType] = enum_column(AssetType)
    value: Mapped[str] = mapped_column(String(2048))
    normalized_value: Mapped[str] = mapped_column(String(2048))
    status: Mapped[AssetStatus] = enum_column(AssetStatus, default=AssetStatus.ACTIVE)
    scope_status: Mapped[ScopeStatus] = enum_column(ScopeStatus, default=ScopeStatus.IN_SCOPE)

    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    discovered_at: Mapped[datetime]
    last_scanned_at: Mapped[datetime | None]
    inactive_since: Mapped[datetime | None]
    missed_count: Mapped[int] = mapped_column(SmallInteger, default=0)

    source: Mapped[str | None] = mapped_column(String(64))  # first sensor that reported it
    sources: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    discovery_method: Mapped[str | None] = mapped_column(String(64))  # stage type / "scope" / "manual"
    confidence: Mapped[int] = mapped_column(SmallInteger, default=80)

    owner: Mapped[str | None] = mapped_column(String(200))
    business_unit: Mapped[str | None] = mapped_column(String(200))
    criticality: Mapped[Criticality] = enum_column(Criticality, default=Criticality.MEDIUM)
    approval_status: Mapped[ApprovalStatus] = enum_column(ApprovalStatus, default=ApprovalStatus.UNVERIFIED)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    notes: Mapped[str | None] = mapped_column(Text)

    risk_score: Mapped[int] = mapped_column(SmallInteger, default=0)
    risk_level: Mapped[RiskLevel] = enum_column(RiskLevel, default=RiskLevel.INFO)
    risk_factors: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list)
    open_findings: Mapped[int] = mapped_column(Integer, default=0)

    # Latest merged attributes reported by sensors (DNS records, HTTP title, cert fields...).
    meta: Mapped[dict[str, Any]] = mapped_column("metadata", default=dict)


class AssetRelationship(UUIDPk, TenantScoped, Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint("source_asset_id", "target_asset_id", "relation_type"),
        Index("ix_asset_rel_target", "target_asset_id", "relation_type"),
        Index("ix_asset_rel_source", "source_asset_id", "relation_type", "active"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    source_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    target_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    relation_type: Mapped[RelationType] = enum_column(RelationType)
    active: Mapped[bool] = mapped_column(default=True)
    missed_count: Mapped[int] = mapped_column(SmallInteger, default=0)
    first_seen: Mapped[datetime]
    last_seen: Mapped[datetime]
    source: Mapped[str | None] = mapped_column(String(64))
    attributes: Mapped[dict[str, Any]] = mapped_column(default=dict)


class AssetObservation(TenantScoped, Base):
    """Every sighting of an asset by a sensor, preserving historical state."""

    __tablename__ = "asset_observations"
    __table_args__ = (Index("ix_asset_obs_asset_time", "asset_id", "observed_at"),)

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    stage_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_stages.id", ondelete="SET NULL"))
    source: Mapped[str] = mapped_column(String(64))
    observed_at: Mapped[datetime]
    data: Mapped[dict[str, Any]] = mapped_column(default=dict)
