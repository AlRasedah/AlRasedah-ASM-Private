"""scan stages: persisted dispatch binding

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-19 12:00:00

A sensor result is accepted only for the job the platform dispatched: the stage's
``task_id`` holds the job id, ``worker_pool`` the pool it was sent to (results from
any other pool are rejected), and ``dispatched_at`` records that the job actually
reached the broker — the watchdog fails running stages that never got that far.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scan_stages", sa.Column("worker_pool", sa.String(64), nullable=True))
    op.add_column("scan_stages", sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_stages", "dispatched_at")
    op.drop_column("scan_stages", "worker_pool")
