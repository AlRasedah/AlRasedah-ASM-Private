"""findings: unverified third-party reports

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-20 10:00:00

Findings that come from a third-party database matching a service version against
a CVE list (Shodan) are not test results. They are kept out of the main findings
list, risk scores, reports and alerts until a scanner confirms the same issue.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("unverified", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_index("ix_findings_unverified", "findings", ["tenant_id", "unverified"])


def downgrade() -> None:
    op.drop_index("ix_findings_unverified", table_name="findings")
    op.drop_column("findings", "unverified")
