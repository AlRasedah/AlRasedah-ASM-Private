"""TEST BUILDS ONLY (packaging/tests): a harmless schema change for the upgrade test.

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
    op.create_table("upgrade_probe", sa.Column("id", sa.Integer, primary_key=True),
                    sa.Column("note", sa.Text, nullable=False, server_default="native upgrade test"))
    op.execute("INSERT INTO upgrade_probe (id) VALUES (1)")


def downgrade() -> None:
    op.drop_table("upgrade_probe")
