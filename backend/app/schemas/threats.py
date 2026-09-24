from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import (
    AdvisoryStatus,
    Assessment,
    CheckOutcome,
    CheckRunStatus,
    MatchBasis,
    MatchStatus,
    RemediationStatus,
    Severity,
)
from app.schemas.assets import AssetRef
from app.schemas.common import ORM, Input
from app.threats.content import AdvisoryContent


class ThreatCounts(BaseModel):
    affected: int = 0  # every asset that may be affected (confirmed or not)
    confirmed: int = 0
    not_detected: int = 0  # a completed check found nothing — not proof of safety
    inconclusive: int = 0
    unchecked: int = 0
    check_pending: int = 0
    reported_unverified: int = 0
    version_unknown: int = 0
    not_affected_version: int = 0
    no_longer_observed: int = 0
    remediated: int = 0  # remediation workflow marked resolved / accepted / not applicable


class AdvisorySummary(BaseModel):
    id: uuid.UUID
    slug: str
    title: str
    severity: Severity
    cves: list[str]
    status: AdvisoryStatus
    published_version: int | None
    source_published_at: datetime | None
    source_updated_at: datetime | None
    version_published_at: datetime | None
    counts: ThreatCounts
    # Freshness of *this tenant's* assessment.
    last_evaluated_at: datetime | None = None
    evaluated_version: int | None = None
    stale: bool = False  # evaluated against an older version than the one published
    # Organizations whose last evaluation hit a bound: their assessment covers part of the
    # inventory, and nothing was marked "no longer observed" from it.
    incomplete: list[str] = []
    # "feed": written automatically from CISA KEV / NVD; "manual": by a platform administrator.
    origin: str = "manual"
    kev: bool = False  # one of its CVEs is in CISA's known-exploited catalog
    has_check: bool = False


class CveIntel(BaseModel):
    cve: str
    kev: bool = False
    kev_due_date: str | None = None
    epss_score: float | None = None
    cvss_score: float | None = None


class CheckInfo(BaseModel):
    key: str
    name: str
    description: str | None = None


class CheckRunOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID
    advisory_version: int
    check_key: str
    scan_id: uuid.UUID | None
    asset_ids: list[uuid.UUID]
    status: CheckRunStatus
    created_at: datetime
    finished_at: datetime | None
    summary: dict[str, Any]


class AdvisoryDetail(AdvisorySummary):
    summary: str
    remediation: str
    references: list[str]
    affected_products: list[dict[str, Any]]
    intel: list[CveIntel] = Field(default_factory=list)
    check: CheckInfo | None = None
    check_runs: list[CheckRunOut] = Field(default_factory=list)


class FindingRef(BaseModel):
    id: uuid.UUID
    title: str
    severity: Severity
    status: str
    unverified: bool


class MatchOut(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset: AssetRef | None
    owner: str | None = None
    business_unit: str | None = None
    basis: MatchBasis
    match_status: MatchStatus
    assessment: Assessment
    evidence: dict[str, Any]
    findings: list[FindingRef] = Field(default_factory=list)
    check_outcome: CheckOutcome
    check_detail: str | None
    checked_at: datetime | None
    remediation_status: RemediationStatus
    assigned_to: uuid.UUID | None
    remediation_note: str | None
    first_matched_at: datetime
    last_evaluated_at: datetime
    advisory_version: int


class MatchUpdate(Input):
    remediation_status: RemediationStatus | None = None
    assigned_to: uuid.UUID | None = None
    remediation_note: str | None = Field(default=None, max_length=4000)


class CheckRequest(Input):
    match_ids: list[uuid.UUID] = Field(min_length=1, max_length=50)


# ------------------------------------------------------------------ catalog (platform)
class AdvisoryCreate(Input):
    slug: str = Field(min_length=3, max_length=64)
    content: AdvisoryContent


class AdvisoryAdminOut(BaseModel):
    id: uuid.UUID
    slug: str
    title: str
    severity: Severity
    status: AdvisoryStatus
    published_version: int | None
    version_published_at: datetime | None
    updated_at: datetime
    has_draft: bool
    origin: str = "manual"
    draft: dict[str, Any] | None = None
    draft_version: int | None = None
    published: dict[str, Any] | None = None
    versions: list[dict[str, Any]] = Field(default_factory=list)


class FeedSettingsIn(Input):
    enabled: bool | None = None
    publish: str | None = Field(default=None, pattern="^(kev|all|none)$")
    include_critical: bool | None = None
    critical_days: int | None = Field(default=None, ge=1, le=110)
    auto_checks: bool | None = None
    aliases: dict[str, list[str]] | None = None
    # Write-only. Empty/absent keeps the stored key; clear_nvd_api_key removes it.
    nvd_api_key: str | None = Field(default=None, max_length=100)
    clear_nvd_api_key: bool = False


class CheckAdminIn(Input):
    key: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    template_id: str = Field(min_length=1, max_length=64)
    enabled: bool = True


class CheckAdminOut(ORM):
    key: str
    name: str
    description: str | None
    kind: str
    template_id: str
    enabled: bool
    updated_at: datetime
