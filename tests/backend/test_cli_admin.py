"""``create-admin`` must not invent a tenant when the name is slightly wrong.

Reported from a real deployment: a second administrator was created with
``--tenant "Your Org"`` while the tenant was named something else. The command
used to get-or-create, so it silently built a second, empty tenant and made the
new account its administrator. They could sign in, saw every menu, and found no
scans, no assets and nothing saying why — the data was in the other tenant, and
RLS confines every query to the tenant of the session.
"""

from __future__ import annotations

import argparse

import pytest
from sqlalchemy import func, select

from app import cli
from app.db.session import system_session
from app.models import Tenant, TenantMembership, User

PW = "Sup3r-Secret-Passw0rd!"


def _args(**over) -> argparse.Namespace:
    base = {"email": "second.admin@corp.internal", "tenant": "Acme Corp", "create_tenant": False,
            "name": "Second Admin", "password": PW, "platform_admin": False}
    return argparse.Namespace(**{**base, **over})


def _tenant_names() -> list[str]:
    with system_session() as db:
        return list(db.execute(select(Tenant.name).order_by(Tenant.name)).scalars().all())


def _membership_tenants(email: str) -> list[str]:
    with system_session() as db:
        return list(db.execute(
            select(Tenant.name).join(TenantMembership, TenantMembership.tenant_id == Tenant.id)
            .join(User, User.id == TenantMembership.user_id).where(User.email == email)).scalars().all())


class TestTenantResolution:
    def test_a_name_that_does_not_exist_is_refused(self, db_clean, factory):
        factory.tenant("Acme Corp")
        with pytest.raises(SystemExit) as exc:
            cli.cmd_create_admin(_args(tenant="Acme"))
        message = str(exc.value)
        assert "No tenant is named 'Acme'" in message
        assert "'Acme Corp'" in message, "the operator must be told which names exist"
        assert "--create-tenant" in message, "and how to create one deliberately"
        assert _tenant_names() == ["Acme Corp"], "nothing may be created by a refused run"

    def test_a_near_miss_suggests_the_right_name(self, db_clean, factory):
        factory.tenant("Acme Corp")
        with pytest.raises(SystemExit) as exc:
            cli.cmd_create_admin(_args(tenant="  acme corp "))
        assert "Did you mean --tenant 'Acme Corp'?" in str(exc.value)

    def test_an_exact_name_joins_the_existing_tenant(self, db_clean, factory):
        t = factory.tenant("Acme Corp")
        cli.cmd_create_admin(_args(tenant="Acme Corp"))
        assert _tenant_names() == ["Acme Corp"]
        assert _membership_tenants("second.admin@corp.internal") == ["Acme Corp"]
        with system_session() as db:
            user = db.execute(select(User).where(User.email == "second.admin@corp.internal")).scalar_one()
            assert user.default_tenant_id == t.id, "and they sign in to it"

    def test_a_new_tenant_only_when_asked_for(self, db_clean, factory):
        factory.tenant("Acme Corp")
        cli.cmd_create_admin(_args(tenant="Side Project", create_tenant=True))
        assert _tenant_names() == ["Acme Corp", "Side Project"]
        assert _membership_tenants("second.admin@corp.internal") == ["Side Project"]

    def test_the_first_admin_of_an_empty_deployment_still_works(self, db_clean):
        # Nothing to typo against, so the bootstrap path must not need the flag.
        cli.cmd_create_admin(_args(tenant="Acme Corp"))
        assert _tenant_names() == ["Acme Corp"]
        assert _membership_tenants("second.admin@corp.internal") == ["Acme Corp"]


class TestExistingAccounts:
    def test_an_account_keeps_the_tenant_it_signs_in_to_and_the_operator_is_told(self, db_clean, factory, capsys):
        home = factory.tenant("Acme Corp")
        other = factory.tenant("Beta Holding")
        user = factory.user(home.id, email="shared@corp.internal")
        cli.cmd_create_admin(_args(email=user.email, tenant="Beta Holding"))

        assert sorted(_membership_tenants(user.email)) == ["Acme Corp", "Beta Holding"]
        with system_session() as db:
            refreshed = db.execute(select(User).where(User.email == user.email)).scalar_one()
            assert refreshed.default_tenant_id == home.id, "an existing sign-in is not repointed behind their back"
        out = capsys.readouterr().out
        assert "already signs in to tenant 'Acme Corp'" in out
        assert "Beta Holding" in out and "tenant selector" in out
        assert other.id != home.id

    def test_adding_the_same_admin_twice_is_harmless(self, db_clean, factory):
        factory.tenant("Acme Corp")
        cli.cmd_create_admin(_args(tenant="Acme Corp"))
        cli.cmd_create_admin(_args(tenant="Acme Corp"))
        with system_session() as db:
            count = db.scalar(select(func.count()).select_from(TenantMembership)
                              .join(User, User.id == TenantMembership.user_id)
                              .where(User.email == "second.admin@corp.internal"))
        assert count == 1
