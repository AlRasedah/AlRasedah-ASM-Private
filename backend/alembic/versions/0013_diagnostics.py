"""Diagnostics: operational events, export state, support bundles, setup tokens, alert outbox

Revision ID: 0013
Revises: 0012
Create Date: 2026-09-25 16:00:00

* finding_activities.exported_at — the alerts log's transactional outbox marker. Existing
  activities are marked exported (they predate the alerts stream; exporting years of
  history on upgrade would flood the new log).
* ops_events, event_export_state, setup_tokens — platform-only (system sessions).
* support_bundles — tenant-isolated; a NULL tenant is a platform bundle, invisible to
  every tenant session.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import private_tables_policy, tenant_isolation

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)
JSONB = postgresql.JSONB(astext_type=sa.Text())
TS = sa.DateTime(timezone=True)


def upgrade() -> None:
    op.add_column("finding_activities", sa.Column("exported_at", TS))
    op.execute("UPDATE finding_activities SET exported_at = now()")
    op.create_index("ix_finding_activities_unexported", "finding_activities", ["created_at"],
                    postgresql_where=sa.text("exported_at IS NULL"))

    op.create_table(
        "ops_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("event_id", sa.String(80), nullable=False, unique=True),
        sa.Column("ts", TS, nullable=False),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("service", sa.String(32), nullable=False),
        sa.Column("event", sa.String(120), nullable=False),
        sa.Column("error_code", sa.String(32)),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("logger", sa.String(120), nullable=False),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id", ondelete="CASCADE")),
        sa.Column("request_id", sa.String(128)),
        sa.Column("scan_id", UUID),
        sa.Column("stage_id", UUID),
        sa.Column("job_id", sa.String(128)),
        sa.Column("pool", sa.String(64)),
        sa.Column("data", JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("ix_ops_events_ts", "ops_events", ["ts"])
    op.create_index("ix_ops_events_tenant_ts", "ops_events", ["tenant_id", "ts"])

    op.create_table(
        "event_export_state",
        sa.Column("name", sa.String(32), primary_key=True),
        sa.Column("cursor", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("gaps", JSONB, nullable=False, server_default="{}"),
        sa.Column("updated_at", TS),
    )
    # The audit export starts at the current end of the log, for the same reason as above.
    op.execute("INSERT INTO event_export_state (name, cursor, gaps, updated_at) "
               "SELECT 'audit', COALESCE(max(id), 0), '{}', now() FROM audit_logs")

    op.create_table(
        "setup_tokens",
        sa.Column("id", sa.BigInteger(), sa.Identity(), primary_key=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", TS, nullable=False, server_default=sa.text("now()")),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("used_at", TS),
    )

    op.create_table(
        "support_bundles",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id", ondelete="CASCADE")),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("requested_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("window_start", TS, nullable=False),
        sa.Column("window_end", TS, nullable=False),
        sa.Column("scan_ids", postgresql.ARRAY(UUID), nullable=False, server_default="{}"),
        sa.Column("organization_ids", postgresql.ARRAY(UUID), nullable=False, server_default="{}"),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error", sa.String(500)),
        sa.Column("storage_key", sa.String(512)),
        sa.Column("filename", sa.String(200)),
        sa.Column("size", sa.BigInteger()),
        sa.Column("sha256", sa.String(64)),
        sa.Column("manifest", JSONB, nullable=False, server_default="{}"),
        sa.Column("started_at", TS),
        sa.Column("finished_at", TS),
        sa.Column("expires_at", TS, nullable=False),
        sa.Column("created_at", TS, nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("ix_support_bundles_tenant", "support_bundles", ["tenant_id", "created_at"])
    op.create_index("ix_support_bundles_active", "support_bundles", ["status"],
                    postgresql_where=sa.text("status IN ('queued', 'running')"))

    for table in ("ops_events", "event_export_state", "setup_tokens"):
        for stmt in private_tables_policy(table):
            op.execute(stmt)
    for stmt in tenant_isolation("support_bundles"):
        op.execute(stmt)


def downgrade() -> None:
    op.drop_table("support_bundles")
    op.drop_table("setup_tokens")
    op.drop_table("event_export_state")
    op.drop_table("ops_events")
    op.drop_index("ix_finding_activities_unexported", table_name="finding_activities")
    op.drop_column("finding_activities", "exported_at")
