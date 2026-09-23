"""Threat Center: advisory catalog, approved checks and per-tenant assessments

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-23 14:00:00

The catalog (advisories, their versions and the approved-check allowlist) is
global: tenants read what is published, only system sessions write. Matches,
check runs and campaign bookkeeping are tenant-owned and get the standard
tenant-isolation policy. No existing table changes.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import catalog_policy, tenant_isolation

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def _enum(name: str, *values: str, length: int = 32) -> sa.Enum:
    return sa.Enum(*values, name=name, native_enum=False, length=length)


SEVERITY = ("info", "low", "medium", "high", "critical")


def _now() -> sa.TextClause:
    return sa.text("now()")


def _tenant_col() -> sa.Column:
    return sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)


def _stamps() -> list[sa.Column]:
    return [sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False)]


def upgrade() -> None:
    op.create_table(
        "threat_advisories",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("slug", sa.String(80), nullable=False, unique=True),
        sa.Column("status", _enum("advisorystatus", "draft", "published", "archived"), nullable=False),
        sa.Column("published_version", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("severity", _enum("severity", *SEVERITY), nullable=False),
        sa.Column("cves", postgresql.ARRAY(sa.String(32)), nullable=False, server_default="{}"),
        sa.Column("source_published_at", sa.DateTime(timezone=True)),
        sa.Column("source_updated_at", sa.DateTime(timezone=True)),
        sa.Column("version_published_at", sa.DateTime(timezone=True)),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("updated_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        *_stamps(),
    )
    op.create_table(
        "threat_advisory_versions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("advisory_id", UUID, sa.ForeignKey("threat_advisories.id", ondelete="CASCADE"), nullable=False,
                  index=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=_now(), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("advisory_id", "version"),
        sa.CheckConstraint("state IN ('draft', 'published')", name="ck_threat_advisory_versions_state"),
    )
    op.create_index("uq_threat_advisory_versions_one_draft", "threat_advisory_versions", ["advisory_id"],
                    unique=True, postgresql_where=sa.text("state = 'draft'"))
    op.create_table(
        "threat_checks",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("key", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("template_id", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        *_stamps(),
        sa.CheckConstraint("kind = 'detection_template'", name="ck_threat_checks_kind"),
    )
    op.create_table(
        "threat_campaigns",
        sa.Column("id", UUID, primary_key=True),
        _tenant_col(),
        sa.Column("advisory_id", UUID, sa.ForeignKey("threat_advisories.id", ondelete="CASCADE"), nullable=False,
                  index=True),
        sa.Column("evaluated_version", sa.Integer()),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True)),
        *_stamps(),
        sa.UniqueConstraint("tenant_id", "advisory_id"),
    )
    op.create_table(
        "threat_check_runs",
        sa.Column("id", UUID, primary_key=True),
        _tenant_col(),
        sa.Column("organization_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("advisory_id", UUID, sa.ForeignKey("threat_advisories.id", ondelete="CASCADE"), nullable=False,
                  index=True),
        sa.Column("advisory_version", sa.Integer(), nullable=False),
        sa.Column("check_key", sa.String(64), nullable=False),
        sa.Column("scan_id", UUID, sa.ForeignKey("scans.id", ondelete="SET NULL"), index=True),
        sa.Column("asset_ids", postgresql.ARRAY(UUID), nullable=False, server_default="{}"),
        sa.Column("status", _enum("checkrunstatus", "queued", "running", "completed", "inconclusive", "cancelled"),
                  nullable=False),
        sa.Column("requested_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        *_stamps(),
    )
    op.create_index("uq_threat_check_runs_active", "threat_check_runs",
                    ["tenant_id", "organization_id", "advisory_id"], unique=True,
                    postgresql_where=sa.text("status IN ('queued', 'running')"))
    op.create_table(
        "threat_matches",
        sa.Column("id", UUID, primary_key=True),
        _tenant_col(),
        sa.Column("organization_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("advisory_id", UUID, sa.ForeignKey("threat_advisories.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", UUID, sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("advisory_version", sa.Integer(), nullable=False),
        sa.Column("basis", _enum("matchbasis", "product", "finding", "third_party"), nullable=False),
        sa.Column("match_status", _enum("matchstatus", "potentially_affected", "version_unknown",
                                        "not_affected_version", "no_longer_observed"), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("finding_ids", postgresql.ARRAY(UUID), nullable=False, server_default="{}"),
        sa.Column("unverified_finding_ids", postgresql.ARRAY(UUID), nullable=False, server_default="{}"),
        sa.Column("check_outcome", _enum("checkoutcome", "none", "pending", "detected", "not_detected",
                                         "inconclusive"), nullable=False, server_default="none"),
        sa.Column("check_detail", sa.String(500)),
        sa.Column("checked_at", sa.DateTime(timezone=True)),
        sa.Column("last_check_run_id", UUID, sa.ForeignKey("threat_check_runs.id", ondelete="SET NULL")),
        sa.Column("assessment", _enum("assessment", "confirmed", "check_pending", "not_detected", "inconclusive",
                                      "potentially_affected", "version_unknown", "reported_unverified",
                                      "not_affected_version", "no_longer_observed"), nullable=False),
        sa.Column("remediation_status", _enum("remediationstatus", "open", "in_progress", "resolved",
                                              "accepted_risk", "not_applicable"), nullable=False,
                  server_default="open"),
        sa.Column("assigned_to", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("remediation_note", sa.Text()),
        sa.Column("first_matched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_evaluated_at", sa.DateTime(timezone=True), nullable=False),
        *_stamps(),
        sa.UniqueConstraint("tenant_id", "advisory_id", "asset_id"),
    )
    op.create_index("ix_threat_matches_advisory", "threat_matches", ["tenant_id", "advisory_id", "assessment"])
    op.create_index("ix_threat_matches_org", "threat_matches", ["organization_id", "advisory_id"])

    for stmt in catalog_policy("threat_advisories", "published_version IS NOT NULL"):
        op.execute(stmt)
    for stmt in catalog_policy("threat_advisory_versions", "state = 'published'"):
        op.execute(stmt)
    for stmt in catalog_policy("threat_checks", "true"):
        op.execute(stmt)
    for table in ("threat_campaigns", "threat_check_runs", "threat_matches"):
        for stmt in tenant_isolation(table):
            op.execute(stmt)


def downgrade() -> None:
    op.drop_table("threat_matches")
    op.drop_table("threat_check_runs")
    op.drop_table("threat_campaigns")
    op.drop_table("threat_checks")
    op.drop_table("threat_advisory_versions")
    op.drop_table("threat_advisories")
