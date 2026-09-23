"""Website screenshots: capture records and the platform screenshot policy

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-23 16:00:00

One tenant-owned row per capture attempt (standard tenant isolation); the image
lives in private object storage under a key derived from the row id. The
platform policy is a JSONB column on the single-row platform_settings table
(system sessions only), empty = defaults = feature unavailable until a platform
administrator enables it.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op
from app.db.rls import tenant_isolation

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UUID = postgresql.UUID(as_uuid=True)


def upgrade() -> None:
    op.add_column("platform_settings", sa.Column("screenshots", postgresql.JSONB(astext_type=sa.Text()),
                                                 nullable=False, server_default="{}"))
    op.create_table(
        "screenshot_captures",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("tenant_id", UUID, sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("organization_id", UUID, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("asset_id", UUID, sa.ForeignKey("assets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("trigger", sa.String(16), nullable=False, server_default="manual"),
        sa.Column("requested_by", UUID, sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("status", sa.Enum("queued", "running", "succeeded", "failed", "blocked", "cancelled",
                                    name="screenshotstatus", native_enum=False, length=32), nullable=False),
        sa.Column("error", sa.String(500)),
        sa.Column("task_id", sa.String(64)),
        sa.Column("worker_pool", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("dispatched_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column("captured_at", sa.DateTime(timezone=True)),
        sa.Column("final_url", sa.String(2048)),
        sa.Column("page_title", sa.String(300)),
        sa.Column("http_status", sa.SmallInteger()),
        sa.Column("storage_key", sa.String(512)),
        sa.Column("content_type", sa.String(64)),
        sa.Column("size", sa.BigInteger()),
        sa.Column("sha256", sa.String(64)),
        sa.Column("width", sa.Integer()),
        sa.Column("height", sa.Integer()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
    )
    op.create_index("ix_screenshots_asset_time", "screenshot_captures", ["asset_id", "created_at"])
    op.create_index("ix_screenshots_tenant_time", "screenshot_captures", ["tenant_id", "created_at"])
    op.create_index("ix_screenshots_active", "screenshot_captures", ["status", "created_at"],
                    postgresql_where=sa.text("status IN ('queued', 'running')"))
    for stmt in tenant_isolation("screenshot_captures"):
        op.execute(stmt)


def downgrade() -> None:
    # Stored images are not deleted by a downgrade; remove tenants/*/screenshots/ from
    # object storage separately if the feature is being withdrawn.
    op.drop_table("screenshot_captures")
    op.drop_column("platform_settings", "screenshots")
