"""Tenant isolation enforced by PostgreSQL Row-Level Security (defense in depth)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from sqlalchemy import select, text

from app.models import TENANT_TABLES, Asset, AuditLog, Organization, ScopeEntry, User
from app.models.enums import AssetType, ScopeStatus


def _asset(tenant_id, org_id, value):
    now = datetime.now(UTC)
    return Asset(tenant_id=tenant_id, organization_id=org_id, asset_type=AssetType.SUBDOMAIN, value=value,
                 normalized_value=value, scope_status=ScopeStatus.IN_SCOPE, first_seen=now, last_seen=now,
                 discovered_at=now, meta={}, tags=[], sources=[], risk_factors=[])


@pytest.fixture
def two_tenants(factory, tenant_db):
    a, b = factory.tenant("Alpha"), factory.tenant("Bravo")
    org_a = factory.org(a.id, "Alpha Org", domains=("alpha-corp.com",))
    org_b = factory.org(b.id, "Bravo Org", domains=("bravo-corp.com",))
    ua = factory.user(a.id)
    ub = factory.user(b.id)
    with tenant_db(a.id) as db:
        db.add(_asset(a.id, org_a.id, "secret.alpha-corp.com"))
        db.commit()
    with tenant_db(b.id) as db:
        db.add(_asset(b.id, org_b.id, "secret.bravo-corp.com"))
        db.commit()
    return a, b, org_a, org_b, ua, ub


def test_every_tenant_table_has_forced_rls(database):
    from app.db.session import system_session

    with system_session() as db:
        rows = dict(db.execute(text(
            "SELECT relname, relrowsecurity AND relforcerowsecurity FROM pg_class "
            "WHERE relname = ANY(:t)"), {"t": TENANT_TABLES + ["users", "tenants", "audit_logs", "scan_profiles"]}).all())
    missing = [t for t in TENANT_TABLES if not rows.get(t)]
    assert not missing, f"tables without forced RLS: {missing}"


def test_reads_are_isolated(two_tenants, tenant_db):
    a, b, org_a, org_b, *_ = two_tenants
    with tenant_db(a.id) as db:
        values = {v for (v,) in db.execute(select(Asset.normalized_value).where(Asset.asset_type == AssetType.SUBDOMAIN))}
        assert values == {"secret.alpha-corp.com"}
        assert db.get(Organization, org_b.id) is None
        assert db.execute(select(ScopeEntry).where(ScopeEntry.organization_id == org_b.id)).first() is None
        # even an explicit filter on the other tenant returns nothing
        assert db.execute(select(Asset).where(Asset.tenant_id == b.id)).first() is None


def test_writes_to_other_tenant_are_rejected(two_tenants, tenant_db):
    a, b, org_a, org_b, *_ = two_tenants
    with tenant_db(a.id) as db:
        db.add(_asset(b.id, org_b.id, "injected.bravo-corp.com"))
        with pytest.raises(sa.exc.ProgrammingError, match="row-level security"):
            db.commit()
        db.rollback()
        # UPDATE/DELETE of invisible rows silently affect nothing
        res = db.execute(sa.update(Asset).where(Asset.tenant_id == b.id).values(notes="pwned"))
        assert res.rowcount == 0
        res = db.execute(sa.delete(Asset).where(Asset.tenant_id == b.id))
        assert res.rowcount == 0
        db.commit()
    with tenant_db(b.id) as db:
        assert db.execute(select(Asset.notes).where(Asset.normalized_value == "secret.bravo-corp.com")).scalar() is None


def test_session_without_context_sees_nothing(two_tenants):
    from app.db.session import new_session

    with new_session() as db:
        assert db.execute(select(sa.func.count()).select_from(Asset)).scalar() == 0
        assert db.execute(select(sa.func.count()).select_from(Organization)).scalar() == 0


def test_users_visible_only_within_tenant(two_tenants, tenant_db):
    a, b, _, _, ua, ub = two_tenants
    with tenant_db(a.id) as db:
        emails = {e for (e,) in db.execute(select(User.email))}
        assert ua.email in emails and ub.email not in emails


def test_audit_log_is_append_only(two_tenants):
    from app.db.session import system_session

    with system_session() as db:
        assert db.execute(select(sa.func.count()).select_from(AuditLog)).scalar() > 0
        with pytest.raises(sa.exc.DBAPIError, match="append-only"):
            db.execute(sa.update(AuditLog).values(action="tampered"))
        db.rollback()
        with pytest.raises(sa.exc.DBAPIError, match="append-only"):
            db.execute(sa.delete(AuditLog))
        db.rollback()


def test_audit_hash_chain_verifies(two_tenants):
    from app.db.session import system_session
    from app.services.audit import verify_chain

    a = two_tenants[0]
    with system_session() as db:
        ok, bad = verify_chain(db, a.id)
        assert ok and bad is None
