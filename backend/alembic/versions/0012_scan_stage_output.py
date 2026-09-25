"""Verbose scan output per stage

Revision ID: 0012
Revises: 0011
Create Date: 2026-09-25 10:00:00

One tenant-owned row per stage with its cleaned, bounded verbose output (standard
tenant isolation). Deleted with the stage and the scan.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import tenant_isolation

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())


def upgrade() -> None:
    op.create_table(
        "scan_stage_outputs",
        sa.Column("stage_id", UUID, sa.ForeignKey("scan_stages.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("scan_id", UUID, sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("head", JSONB, nullable=False, server_default="[]"),
        sa.Column("tail", JSONB, nullable=False, server_default="[]"),
        sa.Column("total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("omitted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_seq", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("final", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    for stmt in tenant_isolation("scan_stage_outputs"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("scan_stage_outputs")
