from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, MetaData, String, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)
    type_annotation_map = {
        dict[str, Any]: JSONB,
        list[str]: ARRAY(String),
        datetime: DateTime(timezone=True),
        uuid.UUID: UUID(as_uuid=True),
    }


class UUIDPk:
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class Timestamps:
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now(), nullable=False)


class TenantScoped:
    """Mixin for every tenant-owned table. RLS policies key on ``tenant_id``."""

    @declared_attr
    def tenant_id(cls) -> Mapped[uuid.UUID]:  # noqa: N805
        return mapped_column(ForeignKey("tenants.id", ondelete="CASCADE"), index=True, nullable=False)


def enum_column(enum_cls: type, length: int = 32, **kw: Any) -> Any:
    """Store enums as VARCHAR: new members never require a migration."""
    from sqlalchemy import Enum

    return mapped_column(
        Enum(enum_cls, native_enum=False, create_constraint=False, length=length,
             values_callable=lambda e: [m.value for m in e], validate_strings=True),
        **kw,
    )
