"""audit log: gapless per-chain sequence number

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-18 18:00:00

``audit_logs.id`` comes from one table-wide identity shared by every tenant chain and the
platform chain, and rolled-back transactions also consume values, so a tenant's view of
``id`` always has gaps even when nothing is missing. ``chain_seq`` numbers each chain
1, 2, 3, … under the chain's advisory lock; ``verify_chain`` requires it to be contiguous,
so a removed entry now shows up as a sequence gap as well as a broken hash link.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audit_logs", sa.Column("chain_seq", sa.BigInteger(), nullable=True))
    # Backfill existing rows. audit_logs is append-only (statement trigger, no UPDATE policy);
    # this one-time, schema-level backfill lifts both inside the migration transaction only.
    op.execute("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_immutable")
    op.execute("CREATE POLICY audit_backfill ON audit_logs FOR UPDATE USING (true) WITH CHECK (true)")
    op.execute("""
        UPDATE audit_logs a SET chain_seq = s.rn
        FROM (SELECT id, row_number() OVER (PARTITION BY tenant_id ORDER BY id) AS rn FROM audit_logs) s
        WHERE a.id = s.id
    """)
    op.execute("DROP POLICY audit_backfill ON audit_logs")
    op.execute("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_immutable")
    op.alter_column("audit_logs", "chain_seq", nullable=False)
    op.execute("CREATE UNIQUE INDEX ux_audit_logs_chain_seq ON audit_logs (tenant_id, chain_seq) NULLS NOT DISTINCT")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ux_audit_logs_chain_seq")
    op.drop_column("audit_logs", "chain_seq")
