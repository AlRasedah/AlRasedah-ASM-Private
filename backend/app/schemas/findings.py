from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import FindingCategory, FindingStatus, RiskLevel, Severity

from .assets import AssetRef
from .common import ORM, Input


class FindingOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    category: FindingCategory
    severity: Severity
    status: FindingStatus
    cve: list[str]
    cvss_score: float | None
    epss_score: float | None
    kev: bool
    risk_score: int
    risk_level: RiskLevel
    first_seen: datetime
    last_seen: datetime
    resolved_at: datetime | None
    assigned_to: uuid.UUID | None
    tags: list[str]
    false_positive: bool
    location: str | None
    source: str  # detection engine (internal id); source_label is the display name
    source_label: str | None = None
    # Reported by a third-party database, never tested (see findings/service.upsert_observation).
    unverified: bool = False
    asset: AssetRef | None = None


class FindingDetail(FindingOut):
    description: str | None
    remediation: str | None
    references: list[str]
    evidence: dict[str, Any]
    cwe: list[str]
    cvss_vector: str | None
    epss_percentile: float | None
    kev_due_date: datetime | None
    exploit_available: bool
    confidence: int
    occurrence_count: int
    notes: str | None
    accepted_until: datetime | None
    risk_factors: list[dict[str, Any]]
    source_finding_id: str


class FindingUpdate(Input):
    status: FindingStatus | None = None
    assigned_to: uuid.UUID | None = None
    tags: list[str] | None = Field(default=None, max_length=30)
    notes: str | None = Field(default=None, max_length=10_000)
    comment: str | None = Field(default=None, max_length=10_000)
    accepted_until: datetime | None = None


class CommentCreate(Input):
    comment: str = Field(min_length=1, max_length=10_000)


class ActivityOut(ORM):
    id: uuid.UUID
    user_id: uuid.UUID | None
    user_email: str | None = None
    activity_type: str
    summary: str | None = None  # human-readable one-liner where the raw values are IDs
    previous: dict[str, Any] | None
    new: dict[str, Any] | None
    comment: str | None
    scan_id: uuid.UUID | None
    created_at: datetime


class FindingStats(BaseModel):
    by_severity: dict[str, int]
    by_status: dict[str, int]
    by_category: dict[str, int]
    kev_open: int
