"""scans: per-scan sign-in secret for authenticated web application scanning

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-20 15:00:00

A tester can paste a logged-in session cookie (or token) when starting a scan, so
the web application scanner tests pages behind the login without anyone storing a
long-lived tenant credential. The value is encrypted (AAD-bound to the scan) and
erased as soon as the scan ends.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("auth_secret_encrypted", sa.Text(), nullable=True))
    op.add_column("scans", sa.Column("auth_header_name", sa.String(64), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "auth_header_name")
    op.drop_column("scans", "auth_secret_encrypted")
