from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.models.enums import (
    ApprovalStatus,
    AssetStatus,
    AssetType,
    Criticality,
    EventType,
    RelationType,
    RiskLevel,
    ScopeStatus,
    Severity,
)

from .common import ORM, Input


class AssetOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_type: AssetType
    value: str
    status: AssetStatus
    scope_status: ScopeStatus
    approval_status: ApprovalStatus
    owner: str | None
    business_unit: str | None
    criticality: Criticality
    tags: list[str]
    first_seen: datetime
    last_seen: datetime
    risk_score: int
    risk_level: RiskLevel
    open_findings: int
    confidence: int
    ips: list[str] = []
    source_label: str | None = None
    title: str | None = None


class AssetRef(ORM):
    id: uuid.UUID
    asset_type: AssetType
    value: str
    status: AssetStatus
    risk_score: int
    scope_status: ScopeStatus


class RelatedAsset(BaseModel):
    relation: RelationType
    direction: str  # "out" (this -> other) or "in" (other -> this)
    active: bool
    first_seen: datetime
    last_seen: datetime
    attributes: dict[str, Any]
    asset: AssetRef


class AssetDetail(AssetOut):
    normalized_value: str
    meta: dict[str, Any]
    notes: str | None
    risk_factors: list[dict[str, Any]]
    discovered_at: datetime
    last_scanned_at: datetime | None
    inactive_since: datetime | None
    missed_count: int
    discovery_method: str | None
    # Capability labels ("Web fingerprinting"), not engine names — see app/scans/engines.py.
    sources: list[str]
    relationships: list[RelatedAsset] = []


class AssetUpdate(Input):
    owner: str | None = Field(default=None, max_length=200)
    business_unit: str | None = Field(default=None, max_length=200)
    criticality: Criticality | None = None
    approval_status: ApprovalStatus | None = None
    tags: list[str] | None = Field(default=None, max_length=30)
    notes: str | None = Field(default=None, max_length=10_000)

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return v
        return sorted({t.strip().lower()[:64] for t in v if t and t.strip()})


class AssetBulkUpdate(Input):
    asset_ids: list[uuid.UUID] = Field(min_length=1, max_length=1000)
    changes: AssetUpdate
    add_tags: list[str] | None = Field(default=None, max_length=30)


class ObservationOut(ORM):
    id: int
    scan_id: uuid.UUID | None
    # Capability label only; the engine behind it is not disclosed.
    source_label: str | None = None
    observed_at: datetime
    data: dict[str, Any]


class EventOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    asset_type: AssetType | None
    asset_value: str | None
    finding_id: uuid.UUID | None
    scan_id: uuid.UUID | None
    event_type: EventType
    severity: Severity
    title: str
    summary: str | None
    previous_state: dict[str, Any] | None
    new_state: dict[str, Any] | None
    details: dict[str, Any]
    occurred_at: datetime
    is_baseline: bool
    acknowledged: bool
    acknowledged_at: datetime | None
    notified: bool


class FacetCount(BaseModel):
    value: str
    count: int


class AssetFacets(BaseModel):
    asset_types: list[FacetCount]
    statuses: list[FacetCount]
    approval: list[FacetCount]
    technologies: list[FacetCount]
    asns: list[FacetCount]
    owners: list[FacetCount]
    business_units: list[FacetCount]
    tags: list[FacetCount]
