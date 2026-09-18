"""Database engine/session management with PostgreSQL Row-Level Security context.

Every transaction starts by setting transaction-local GUCs that the RLS
policies read:

* ``app.tenant_id``  – the tenant whose rows are visible/writable;
* ``app.user_id``    – the acting user (used by the ``users`` policy);
* ``app.bypass_rls`` – ``on`` only for platform/system sessions
  (schedulers, migrations, authentication lookups, platform admin tools).

A session with no context sees **no** tenant rows: forgetting to scope a
query fails closed rather than leaking data across tenants.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    s = get_settings()
    return create_engine(
        s.database_url,
        pool_pre_ping=True,
        pool_size=s.db_pool_size,
        max_overflow=s.db_max_overflow,
        echo=s.db_echo,
        future=True,
    )


@lru_cache
def get_sessionmaker() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), expire_on_commit=False, autoflush=True)


_SET_CONTEXT = text(
    "SELECT set_config('app.tenant_id', :tenant_id, true), "
    "set_config('app.user_id', :user_id, true), "
    "set_config('app.bypass_rls', :bypass, true)"
)


@event.listens_for(Session, "after_begin")
def _apply_rls_context(session: Session, transaction, connection) -> None:  # type: ignore[no-untyped-def]
    info = session.info
    tenant_id = info.get("tenant_id")
    user_id = info.get("user_id")
    connection.execute(
        _SET_CONTEXT,
        {
            "tenant_id": str(tenant_id) if tenant_id else "",
            "user_id": str(user_id) if user_id else "",
            "bypass": "on" if info.get("bypass_rls") else "off",
        },
    )


def new_session(
    tenant_id: uuid.UUID | None = None, *, user_id: uuid.UUID | None = None, system: bool = False
) -> Session:
    session = get_sessionmaker()()
    session.info["tenant_id"] = tenant_id
    session.info["user_id"] = user_id
    session.info["bypass_rls"] = system
    return session


def set_session_context(
    session: Session, *, tenant_id: uuid.UUID | None, user_id: uuid.UUID | None = None, system: bool = False
) -> None:
    """Change the RLS context. Takes effect from the next transaction."""
    if session.in_transaction():
        session.commit()
    session.info.update({"tenant_id": tenant_id, "user_id": user_id, "bypass_rls": system})


@contextmanager
def session_scope(
    tenant_id: uuid.UUID | None = None, *, user_id: uuid.UUID | None = None, system: bool = False
) -> Iterator[Session]:
    session = new_session(tenant_id, user_id=user_id, system=system)
    try:
        yield session
        session.commit()
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()


def system_session() -> Session:
    return new_session(system=True)
