"""Lean-feature audit fixes: coverage, check snapshots, capture slots, usage ledger, deletions

Revision ID: 0010
Revises: 0009
Create Date: 2026-09-24 10:00:00

* threat_campaigns.incomplete_orgs — organizations whose last evaluation hit a bound
  (and why); such an evaluation retires nothing.
* threat_check_runs.template_id / cves — what a check actually ran, so its result is
  read against that and not against a later advisory version.
* screenshot_captures.slot_until and one active capture per endpoint (unique).
* screenshot_usage — the daily allowance, independent of capture rows that
  retention and users delete.
* storage_deletions — objects whose records are gone (organization deleted) and
  that maintenance keeps trying to delete.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import tenant_isolation

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def _tenant_table(name: str, *columns: sa.Column) -> None:
    op.create_table(
        name,
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        *columns,
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    for stmt in tenant_isolation(name):
        op.execute(stmt)


def upgrade() -> None:
    op.add_column("threat_campaigns", sa.Column("incomplete_orgs", postgresql.JSONB(astext_type=sa.Text()),
                                                nullable=False, server_default="{}"))
    op.add_column("threat_check_runs", sa.Column("template_id", sa.String(64)))
    op.add_column("threat_check_runs", sa.Column("cves", postgresql.ARRAY(sa.String(32))))

    op.add_column("screenshot_captures", sa.Column("slot_until", sa.DateTime(timezone=True)))
    # Captures already running keep their slot for the longest a job could still take.
    op.execute("UPDATE screenshot_captures SET slot_until = started_at + interval '20 minutes' "
               "WHERE status = 'running' AND started_at IS NOT NULL")
    # Before the unique index: an endpoint with several active captures keeps its newest.
    op.execute("""
        UPDATE screenshot_captures SET status = 'failed', finished_at = now(),
               error = 'superseded by a newer capture of the same endpoint'
        WHERE id IN (SELECT id FROM (
            SELECT id, row_number() OVER (PARTITION BY asset_id ORDER BY created_at DESC) AS rn
            FROM screenshot_captures WHERE status IN ('queued', 'running')) ranked WHERE rn > 1)""")
    op.create_index("uq_screenshots_one_active", "screenshot_captures", ["asset_id"], unique=True,
                    postgresql_where=sa.text("status IN ('queued', 'running')"))

    _tenant_table("screenshot_usage",
                  sa.Column("day", sa.Date(), nullable=False),
                  sa.Column("requested", sa.Integer(), nullable=False, server_default="0"))
    op.create_unique_constraint("uq_screenshot_usage_tenant_id_day", "screenshot_usage", ["tenant_id", "day"])
    # Today's captures so far, so the upgrade does not hand out a fresh allowance.
    op.execute("""
        INSERT INTO screenshot_usage (id, tenant_id, day, requested)
        SELECT gen_random_uuid(), tenant_id, (now() AT TIME ZONE 'UTC')::date, count(*)
        FROM screenshot_captures
        WHERE created_at >= date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
          AND status <> 'cancelled'
        GROUP BY tenant_id""")

    _tenant_table("storage_deletions",
                  sa.Column("storage_key", sa.String(512), nullable=False),
                  sa.Column("size", sa.BigInteger(), nullable=False, server_default="0"),
                  sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
                  sa.Column("last_error", sa.String(300)))


def downgrade() -> None:
    op.drop_table("storage_deletions")
    op.drop_table("screenshot_usage")
    op.drop_index("uq_screenshots_one_active", table_name="screenshot_captures")
    op.drop_column("screenshot_captures", "slot_until")
    op.drop_column("threat_check_runs", "cves")
    op.drop_column("threat_check_runs", "template_id")
    op.drop_column("threat_campaigns", "incomplete_orgs")
