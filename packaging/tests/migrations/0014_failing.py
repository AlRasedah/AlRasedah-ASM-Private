"""TEST BUILDS ONLY (packaging/tests): a migration that fails half way, for the recovery test.

Revision ID: 0014
Revises: 0013
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # First a change that must be rolled back with the rest...
    op.create_table("failed_migration_probe", sa.Column("id", sa.Integer, primary_key=True))
    # ...then a failure.
    op.execute("SELECT 1 / 0")


def downgrade() -> None:
    op.drop_table("failed_migration_probe")
