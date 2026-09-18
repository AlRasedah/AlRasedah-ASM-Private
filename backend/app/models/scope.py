"""Authorized scope and secrets."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScoped, Timestamps, UUIDPk, enum_column

from .enums import ScopeEntryType, VerificationStatus


class ScopeEntry(UUIDPk, TenantScoped, Timestamps, Base):
    """An explicitly authorized (or explicitly excluded) target.

    Active scanning is only ever performed against targets that match an
    inclusion entry with ``allow_active_scanning`` and no exclusion entry.
    """

    __tablename__ = "scope_entries"
    __table_args__ = (UniqueConstraint("tenant_id", "organization_id", "entry_type", "value", "is_exclusion"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    entry_type: Mapped[ScopeEntryType] = enum_column(ScopeEntryType)
    value: Mapped[str] = mapped_column(String(255))
    include_subdomains: Mapped[bool] = mapped_column(default=True)
    is_exclusion: Mapped[bool] = mapped_column(default=False)
    allow_active_scanning: Mapped[bool] = mapped_column(default=True)
    verification_status: Mapped[VerificationStatus] = enum_column(VerificationStatus,
                                                                  default=VerificationStatus.NOT_REQUIRED)
    verification_token: Mapped[str | None] = mapped_column(String(128))
    verified_at: Mapped[datetime | None]
    notes: Mapped[str | None] = mapped_column(Text)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Secret(UUIDPk, TenantScoped, Timestamps, Base):
    """Encrypted secret (scanner API keys, integration credentials).

    Only the database secrets backend uses this table; Vault/cloud KMS backends
    store a reference in ``external_ref`` instead of ciphertext.
    """

    __tablename__ = "secrets"
    __table_args__ = (UniqueConstraint("tenant_id", "name"),)

    name: Mapped[str] = mapped_column(String(200))
    kind: Mapped[str] = mapped_column(String(32), default="generic")  # scanner_credential | integration | generic
    provider: Mapped[str | None] = mapped_column(String(64))
    backend: Mapped[str] = mapped_column(String(32), default="database")
    ciphertext: Mapped[str | None] = mapped_column(Text)
    external_ref: Mapped[str | None] = mapped_column(String(512))
    key_id: Mapped[str | None] = mapped_column(String(32))
    last_four: Mapped[str | None] = mapped_column(String(8))
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
