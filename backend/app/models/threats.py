"""Threat Center: a curated advisory catalog (global) and each tenant's assessment of it.

The catalog is shared: platform administrators write advisories once and every
tenant sees the published versions. Everything an advisory *means for a tenant* —
which of its assets match, what checks said, who is fixing what — lives in
tenant-scoped tables under the usual Row-Level Security.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import (
    AdvisoryStatus,
    Assessment,
    CheckOutcome,
    CheckRunStatus,
    MatchBasis,
    MatchStatus,
    RemediationStatus,
    Severity,
)


class ThreatAdvisory(UUIDPk, Timestamps, Base):
    """One advisory. The columns mirror its *published* version (for listing); the
    content itself lives in :class:`ThreatAdvisoryVersion` rows.

    Tenant sessions see a row only once a version has been published (RLS).
    """

    __tablename__ = "threat_advisories"

    slug: Mapped[str] = mapped_column(String(80), unique=True)
    status: Mapped[AdvisoryStatus] = enum_column(AdvisoryStatus, default=AdvisoryStatus.DRAFT)
    published_version: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[Severity] = enum_column(Severity, default=Severity.HIGH)
    cves: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    # Dates from the advisory's source (vendor / CERT), not from this platform.
    source_published_at: Mapped[datetime | None]
    source_updated_at: Mapped[datetime | None]
    # When a version was last published here — drives "is my assessment stale?".
    version_published_at: Mapped[datetime | None]
    # "manual" (a platform administrator wrote it) or "feed" (generated from public
    # vulnerability data by app/threats/feed.py, which never edits a manual advisory).
    origin: Mapped[str] = mapped_column(String(16), default="manual", server_default="manual")
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ThreatAdvisoryVersion(UUIDPk, Base):
    """Immutable once published. At most one draft per advisory (partial unique index)."""

    __tablename__ = "threat_advisory_versions"
    __table_args__ = (
        UniqueConstraint("advisory_id", "version"),
        Index("uq_threat_advisory_versions_one_draft", "advisory_id", unique=True,
              postgresql_where=text("state = 'draft'")),
    )

    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threat_advisories.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(16), default="draft")  # draft | published
    # Validated AdvisoryContent (app.threats.content): data only — no commands, no templates.
    content: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(server_default=text("now()"))
    published_at: Mapped[datetime | None]


class ThreatCheck(UUIDPk, Timestamps, Base):
    """A platform-approved detection check an advisory may reference.

    This table *is* the allowlist: advisories name a check by ``key`` and can
    carry nothing executable themselves. ``template_id`` identifies one detection
    in the deployment's vetted template set; the scanner still applies its safe
    defaults (no intrusive or denial-of-service classes, no out-of-band callbacks).
    """

    __tablename__ = "threat_checks"

    key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(32), default="detection_template")
    template_id: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(default=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ThreatCampaign(UUIDPk, TenantScoped, Timestamps, Base):
    """One tenant's standing with one advisory (freshness and bookkeeping)."""

    __tablename__ = "threat_campaigns"
    __table_args__ = (UniqueConstraint("tenant_id", "advisory_id"),)

    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threat_advisories.id", ondelete="CASCADE"), index=True)
    evaluated_version: Mapped[int | None] = mapped_column(Integer)
    last_evaluated_at: Mapped[datetime | None]
    # {organization id: reason} for organizations whose last evaluation hit a bound and saw
    # only part of the inventory. Nothing is retired as "no longer observed" from those.
    incomplete_orgs: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict, server_default=text("'{}'"))


class ThreatMatch(UUIDPk, TenantScoped, Timestamps, Base):
    """An asset of this tenant that an advisory may concern, and everything known about it.

    Three separate axes, deliberately not merged:
    * ``match_status``/``evidence`` — what the inventory says;
    * ``check_outcome`` — what an approved check said (never proof of safety);
    * ``remediation_status`` — the tenant's own workflow.
    ``assessment`` is derived from the first two plus linked findings, and stored
    only so counts are cheap.
    """

    __tablename__ = "threat_matches"
    __table_args__ = (
        UniqueConstraint("tenant_id", "advisory_id", "asset_id"),
        Index("ix_threat_matches_advisory", "tenant_id", "advisory_id", "assessment"),
        Index("ix_threat_matches_org", "organization_id", "advisory_id"),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threat_advisories.id", ondelete="CASCADE"))
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    advisory_version: Mapped[int] = mapped_column(Integer)

    basis: Mapped[MatchBasis] = enum_column(MatchBasis)
    match_status: Mapped[MatchStatus] = enum_column(MatchStatus)
    # {"product", "matched_name", "version", "source", "observed_at", "reason", "third_party": bool, ...}
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # References to existing findings — never copies of them.
    finding_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    unverified_finding_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)

    check_outcome: Mapped[CheckOutcome] = enum_column(CheckOutcome, default=CheckOutcome.NONE)
    check_detail: Mapped[str | None] = mapped_column(String(500))
    checked_at: Mapped[datetime | None]
    last_check_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threat_check_runs.id", ondelete="SET NULL"))

    assessment: Mapped[Assessment] = enum_column(Assessment)

    remediation_status: Mapped[RemediationStatus] = enum_column(RemediationStatus, default=RemediationStatus.OPEN)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    remediation_note: Mapped[str | None] = mapped_column(Text)

    first_matched_at: Mapped[datetime]
    last_evaluated_at: Mapped[datetime]


class ThreatCheckRun(UUIDPk, TenantScoped, Timestamps, Base):
    """"Check selected assets": one scan through the normal pipeline, per organization."""

    __tablename__ = "threat_check_runs"
    __table_args__ = (
        # One active run per advisory per organization: a second click never starts a second job.
        Index("uq_threat_check_runs_active", "tenant_id", "organization_id", "advisory_id", unique=True,
              postgresql_where=text("status IN ('queued', 'running')")),
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"))
    advisory_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("threat_advisories.id", ondelete="CASCADE"),
                                                   index=True)
    advisory_version: Mapped[int] = mapped_column(Integer)
    check_key: Mapped[str] = mapped_column(String(64))
    # What was actually dispatched: the result is read against these, never against the
    # advisory's or the check's current definition (both may change while it runs).
    template_id: Mapped[str | None] = mapped_column(String(64))
    cves: Mapped[list[str] | None] = mapped_column(ARRAY(String(32)))
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"), index=True)
    asset_ids: Mapped[list[uuid.UUID]] = mapped_column(ARRAY(UUID(as_uuid=True)), default=list)
    status: Mapped[CheckRunStatus] = enum_column(CheckRunStatus, default=CheckRunStatus.QUEUED)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    finished_at: Mapped[datetime | None]
    # {"detected": n, "not_detected": n, "inconclusive": n, "reason": "..."}
    summary: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


class ThreatFeedItem(Timestamps, Base):
    """One CVE the automatic feed has seen, and what it parsed from NVD. Platform-only."""

    __tablename__ = "threat_feed_items"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    source: Mapped[str] = mapped_column(String(16))  # kev | critical
    kev: Mapped[bool] = mapped_column(default=False)
    nvd_last_modified: Mapped[datetime | None]
    # The NVD version the advisory was last generated from.
    applied_last_modified: Mapped[datetime | None]
    record: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # pending | published | draft | no_products | manual | failed
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    detail: Mapped[str | None] = mapped_column(String(300))
    advisory_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("threat_advisories.id", ondelete="SET NULL"))
