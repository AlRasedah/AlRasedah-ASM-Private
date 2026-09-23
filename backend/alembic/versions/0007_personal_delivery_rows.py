"""notification_deliveries: record personal alerts too

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-23 10:00:00

Integration deliveries have had a durable row each, with attempts and a retry
schedule; personal alerts — mailed to a member's login address — had none. A
momentary SMTP failure therefore lost a high-severity alert permanently: the
event was already marked notified, nothing recorded the failure, and
`retry_failed` had nothing to find. This adds the recipient so a personal
delivery is tracked, retried and visible like any other.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("notification_deliveries",
                  sa.Column("recipient_user_id", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_notification_deliveries_recipient_user_id_users", "notification_deliveries",
                          "users", ["recipient_user_id"], ["id"], ondelete="CASCADE")
    op.create_index("ix_deliveries_recipient", "notification_deliveries",
                    ["tenant_id", "recipient_user_id"])


def downgrade() -> None:
    op.drop_index("ix_deliveries_recipient", table_name="notification_deliveries")
    op.drop_constraint("fk_notification_deliveries_recipient_user_id_users", "notification_deliveries",
                       type_="foreignkey")
    op.drop_column("notification_deliveries", "recipient_user_id")
