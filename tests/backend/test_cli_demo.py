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


def _reset(tenant="CLI Demo Co", force=False):
    cmd_demo_reset(argparse.Namespace(tenant=tenant, force=force))


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
    _reset()
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
    _reset(tenant="Does Not Exist")  # must not raise


def test_demo_reset_refuses_tenant_with_a_non_demo_org(factory):
    _seed()
    with system_session() as db:
        tid = db.execute(select(Tenant.id).where(Tenant.name == "CLI Demo Co")).scalar_one()
    factory.org(tid, name="Real Corp", domains=("real-corp.com",))  # a real org, not demo-seeded
    _reset()  # no --force: must refuse
    with system_session() as db:
        assert db.execute(select(Tenant).where(Tenant.name == "CLI Demo Co")).scalar_one_or_none() is not None
        assert db.scalar(select(func.count()).select_from(Organization).where(Organization.tenant_id == tid)) == 2


def test_demo_reset_force_deletes_tenant_with_a_non_demo_org(factory):
    _seed()
    with system_session() as db:
        tid = db.execute(select(Tenant.id).where(Tenant.name == "CLI Demo Co")).scalar_one()
    factory.org(tid, name="Real Corp", domains=("real-corp.com",))
    _reset(force=True)  # --force: deletes everything
    with system_session() as db:
        assert db.execute(select(Tenant).where(Tenant.name == "CLI Demo Co")).scalar_one_or_none() is None
