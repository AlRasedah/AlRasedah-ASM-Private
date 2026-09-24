"""Automatic advisories from CISA KEV and NVD

Revision ID: 0011
Revises: 0010
Create Date: 2026-09-24 14:00:00

* threat_advisories.origin — 'manual' (written by a platform administrator) or
  'feed' (generated from public vulnerability data). The feed never edits a
  manual advisory.
* threat_feed_items — one row per CVE the feed has seen, with what it parsed
  from NVD. Platform-only (system sessions), like the rest of the feed state.
* platform_settings.threat_feed (JSONB, defaults in code) and the optional NVD
  API key, encrypted like every other stored secret.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import private_tables_policy

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.add_column("threat_advisories", sa.Column("origin", sa.String(16), nullable=False, server_default="manual"))
    op.add_column("platform_settings", sa.Column("threat_feed", JSONB, nullable=False, server_default="{}"))
    op.add_column("platform_settings", sa.Column("nvd_api_key_ciphertext", sa.Text()))
    op.create_table(
        "threat_feed_items",
        sa.Column("cve_id", sa.String(32), primary_key=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("kev", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("nvd_last_modified", sa.DateTime(timezone=True)),
        sa.Column("applied_last_modified", sa.DateTime(timezone=True)),
        sa.Column("record", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String(24), nullable=False, server_default="pending"),
        sa.Column("detail", sa.String(300)),
        sa.Column("advisory_id", UUID, sa.ForeignKey("threat_advisories.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_threat_feed_items_status", "threat_feed_items", ["status"])
    for stmt in private_tables_policy("threat_feed_items"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("threat_feed_items")
    op.drop_column("platform_settings", "nvd_api_key_ciphertext")
    op.drop_column("platform_settings", "threat_feed")
    op.drop_column("threat_advisories", "origin")
