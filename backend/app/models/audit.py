"""Append-only, hash-chained audit log.

UPDATE/DELETE are blocked by a database trigger (see migration). Each row
stores ``hash = sha256(prev_hash || canonical(row))`` per tenant chain and a
gapless ``chain_seq``, so tampering with or removing historical rows is
detectable with ``verify_chain``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, ForeignKey, Identity, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tenant_created", "tenant_id", "created_at"),
        Index("ux_audit_logs_chain_seq", "tenant_id", "chain_seq", unique=True, postgresql_nulls_not_distinct=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    # Position in this row's chain (tenant, or platform when tenant_id is NULL): 1, 2, 3, …
    # without gaps. `id` is table-wide and has gaps by design; show chain_seq to people.
    chain_seq: Mapped[int] = mapped_column(BigInteger)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tenants.id", ondelete="SET NULL"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor: Mapped[str | None] = mapped_column(String(320))  # email/service name at the time
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str | None] = mapped_column(String(64))
    object_id: Mapped[str | None] = mapped_column(String(64))
    previous: Mapped[dict[str, Any] | None]
    new: Mapped[dict[str, Any] | None]
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    prev_hash: Mapped[str | None] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))
