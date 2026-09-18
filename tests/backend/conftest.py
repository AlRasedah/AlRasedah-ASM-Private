from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg import sql

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

ADMIN_URL = os.environ["ASM_TEST_ADMIN_URL"]
DB_NAME = os.environ["ASM_TEST_DB_NAME"]
DB_ROLE = os.environ["ASM_TEST_DB_ROLE"]

# Tables wiped between tests (global reference data such as plans, built-in
# profiles and vulnerability intelligence is kept).
TRUNCATE = [
    "tenants", "users", "audit_logs", "user_sessions", "password_reset_tokens", "vuln_intel", "intel_feed_state",
]


def _db_available() -> bool:
    try:
        with psycopg.connect(ADMIN_URL, connect_timeout=3):
            return True
    except psycopg.Error:
        return False


DB_AVAILABLE = _db_available()


def _admin_test_db_url() -> str:
    return ADMIN_URL.rsplit("/", 1)[0] + "/" + DB_NAME


@pytest.fixture(scope="session")
def database():
    if not DB_AVAILABLE:
        pytest.skip("PostgreSQL not available (set ASM_TEST_ADMIN_URL)")
    from dev_db import ensure  # scripts/dev_db.py

    ensure(ADMIN_URL, DB_ROLE, DB_ROLE, DB_NAME, recreate=True)
    with psycopg.connect(ADMIN_URL, autocommit=True) as conn:
        row = conn.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = %s", (DB_ROLE,)).fetchone()
        assert row == (False, False), "test role must not bypass RLS"

    from alembic import command
    from alembic.config import Config

    cfg = Config(str(ROOT / "backend" / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "backend" / "alembic"))
    command.upgrade(cfg, "head")

    from app.db.session import system_session
    from app.tenants.service import bootstrap

    with system_session() as db:
        bootstrap(db)
    yield
    from app.db.session import get_engine

    get_engine().dispose()


@pytest.fixture
def db_clean(database):
    with psycopg.connect(_admin_test_db_url(), autocommit=True) as conn:
        conn.execute("SET session_replication_role = replica")  # bypass the audit append-only trigger
        conn.execute(sql.SQL("TRUNCATE {} CASCADE").format(sql.SQL(", ").join(sql.Identifier(t) for t in TRUNCATE)))
    from app.core.rate_limit import get_rate_limiter
    from app.db.session import system_session
    from app.scans.profiles import ensure_builtin_profiles

    with system_session() as db:  # TRUNCATE ... CASCADE also empties scan_profiles
        ensure_builtin_profiles(db)
        db.commit()

    get_rate_limiter.cache_clear()
    yield


@pytest.fixture
def system_db(db_clean):
    from app.db.session import system_session

    s = system_session()
    yield s
    s.close()


# ------------------------------------------------------------------ factories
class Factory:
    def __init__(self) -> None:
        from app.db.session import system_session

        self.system_session = system_session

    def tenant(self, name: str | None = None):
        from app.tenants.service import create_tenant

        with self.system_session() as db:
            t = create_tenant(db, name or f"Tenant {uuid.uuid4().hex[:6]}")
            db.commit()
            db.refresh(t)
            return t

    def user(self, tenant_id, role="tenant_admin", email: str | None = None, password="Sup3r-Secret-Passw0rd!",
             platform_admin: bool = False):
        from app.auth.service import set_password
        from app.models import TenantMembership, User
        from app.models.enums import Role

        with self.system_session() as db:
            u = User(email=(email or f"user-{uuid.uuid4().hex[:8]}@example.org").lower(), full_name="Test User",
                     default_tenant_id=tenant_id, is_platform_admin=platform_admin)
            db.add(u)
            db.flush()
            set_password(db, u, password)
            if tenant_id:
                db.add(TenantMembership(tenant_id=tenant_id, user_id=u.id, role=Role(role)))
            db.commit()
            db.refresh(u)
            return u

    def org(self, tenant_id, name: str = "Example Corp", domains=("example.com",), ips=(), cidrs=(), exclusions=()):
        from app.db.session import new_session
        from app.models import Organization
        from app.models.enums import ScopeEntryType
        from app.scope.service import add_entry

        with new_session(tenant_id) as db:
            org = Organization(tenant_id=tenant_id, name=name, settings={})
            db.add(org)
            db.flush()
            for d in domains:
                add_entry(db, tenant_id=tenant_id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN, value=d)
            for ip in ips:
                add_entry(db, tenant_id=tenant_id, organization_id=org.id, entry_type=ScopeEntryType.IP, value=ip)
            for c in cidrs:
                add_entry(db, tenant_id=tenant_id, organization_id=org.id, entry_type=ScopeEntryType.CIDR, value=c)
            for d in exclusions:
                add_entry(db, tenant_id=tenant_id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN, value=d,
                          is_exclusion=True)
            db.commit()
            db.refresh(org)
            return org


@pytest.fixture
def factory(db_clean) -> Factory:
    return Factory()


@pytest.fixture
def tenant_db():
    """Open tenant-scoped sessions: ``with tenant_db(tenant_id) as db: ...``."""
    from app.db.session import new_session

    opened = []

    def _open(tenant_id):
        s = new_session(tenant_id)
        opened.append(s)
        return s

    yield _open
    for s in opened:
        s.close()
