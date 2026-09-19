"""The demo-seed / demo-reset admin commands (customer demo environments)."""

from __future__ import annotations

import argparse

from sqlalchemy import func, select

from app.cli import cmd_demo_reset, cmd_demo_seed
from app.db.session import system_session
from app.models import AuditLog, Organization, ScopeEntry, Tenant, User


def _seed(**kw):
    args = {"email": "demo-admin@demo.test", "password": "Demo-Passw0rd!", "tenant": "CLI Demo Co", "org": "CLI Demo Org"}
    args.update(kw)
    cmd_demo_seed(argparse.Namespace(**args))


def test_demo_seed_creates_tenant_admin_org_scope(db_clean):
    _seed()
    with system_session() as db:
        tenant = db.execute(select(Tenant).where(Tenant.name == "CLI Demo Co")).scalar_one()
        assert db.execute(select(User).where(User.email == "demo-admin@demo.test")).scalar_one().is_platform_admin
        assert db.scalar(select(func.count()).select_from(Organization).where(Organization.tenant_id == tenant.id)) == 1
        # inclusion + exclusion scope entries were created
        assert db.scalar(select(func.count()).select_from(ScopeEntry).where(ScopeEntry.tenant_id == tenant.id)) == 2


def test_demo_seed_is_idempotent(db_clean):
    _seed()
    _seed()  # second run must not raise or duplicate
    with system_session() as db:
        assert db.scalar(select(func.count()).select_from(Tenant).where(Tenant.name == "CLI Demo Co")) == 1


def test_demo_reset_deletes_everything_and_keeps_audit_immutable(db_clean):
    _seed()
    cmd_demo_reset(argparse.Namespace(tenant="CLI Demo Co"))
    with system_session() as db:
        assert db.execute(select(Tenant).where(Tenant.name == "CLI Demo Co")).scalar_one_or_none() is None
        assert db.execute(select(User).where(User.email == "demo-admin@demo.test")).scalar_one_or_none() is None
        # the append-only trigger and FORCE RLS are restored: a stray audit UPDATE still fails
        import pytest
        from sqlalchemy.exc import DatabaseError
        with pytest.raises(DatabaseError):
            db.execute(AuditLog.__table__.update().values(action="tampered"))
            db.flush()


def test_demo_reset_missing_tenant_is_noop(db_clean):
    cmd_demo_reset(argparse.Namespace(tenant="Does Not Exist"))  # must not raise
