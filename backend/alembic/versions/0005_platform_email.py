"""platform email settings and per-user alert preferences

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-20 12:00:00

Mail delivery becomes configurable from the web interface (platform
administrators) instead of `.env` plus a restart, and every user can have alerts
sent to their own login address.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import private_tables_policy, tenant_isolation

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "platform_settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=False),
        sa.Column("smtp", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default="{}"),
        sa.Column("smtp_password_ciphertext", sa.Text(), nullable=True),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.CheckConstraint("id = 1", name="ck_platform_settings_single_row"),
    )
    for stmt in private_tables_policy("platform_settings"):
        op.execute(stmt)

    op.create_table(
        "user_alert_preferences",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False, index=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("min_severity", sa.Enum("info", "low", "medium", "high", "critical", name="severity",
                                          native_enum=False, length=32), nullable=False, server_default="high"),
        sa.Column("event_types", postgresql.ARRAY(sa.String(64)), nullable=False, server_default="{}"),
        sa.Column("organization_ids", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False,
                  server_default="{}"),
        sa.Column("include_baseline", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("tenant_id", "user_id"),
    )
    for stmt in tenant_isolation("user_alert_preferences"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("user_alert_preferences")
    op.drop_table("platform_settings")
