"""Wildcard scope entries (*.example.com), the way authorizations are usually written."""

from __future__ import annotations

import pytest
from asm_sensors.targets import Target, TargetKind
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.errors import Conflict, ValidationFailed
from app.db.session import new_session
from app.models import Organization, ScopeEntry
from app.models.enums import ScopeEntryType
from app.scope.service import add_entry, load_checker, parse_domain

PW = "Sup3r-Secret-Passw0rd!"


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


class TestParsing:
    def test_a_wildcard_is_the_domain_plus_everything_under_it(self):
        assert parse_domain("*.example.com") == ("example.com", True)
        assert parse_domain(" *.Example.COM. ") == ("example.com", True)
        assert parse_domain("*.dev.example.com") == ("dev.example.com", True)
        assert parse_domain("example.com") == ("example.com", False)

    @pytest.mark.parametrize("bad", ["a.*.example.com", "*example.com", "ex*mple.com", "*.*.example.com", "*."])
    def test_a_wildcard_anywhere_else_is_refused_not_guessed(self, bad):
        with pytest.raises(ValidationFailed):
            parse_domain(bad)


class TestScopeEntries:
    def test_adding_a_wildcard_covers_the_subdomains(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=())
        with new_session(tenant.id) as db:
            entry = add_entry(db, tenant_id=tenant.id, organization_id=org.id,
                              entry_type=ScopeEntryType.DOMAIN, value="*.ifmi.com.sa")
            db.commit()
            assert entry.value == "ifmi.com.sa" and entry.include_subdomains is True
            checker = load_checker(db, db.get(Organization, org.id))
            for host in ("ifmi.com.sa", "www.ifmi.com.sa", "api.dev.ifmi.com.sa"):
                assert checker.check(Target(kind=TargetKind.HOSTNAME, value=host), active=True).allowed, host
            assert not checker.check(Target(kind=TargetKind.HOSTNAME, value="ifmi.sa"), active=True).allowed

    def test_a_wildcard_overrides_subdomains_off(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=())
        with new_session(tenant.id) as db:
            # The wildcard in the text is explicit, so it wins over the form default.
            entry = add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                              value="*.example.com", include_subdomains=False)
            assert entry.include_subdomains is True

    def test_pasting_both_forms_widens_one_entry(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=())
        with new_session(tenant.id) as db:
            plain = add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                              value="example.com", include_subdomains=False)
            widened = add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                                value="*.example.com")
            db.commit()
            assert widened.id == plain.id and widened.include_subdomains is True
            assert len(db.scalars(select(ScopeEntry).where(ScopeEntry.organization_id == org.id)).all()) == 1

    def test_an_exact_duplicate_is_still_refused(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=())
        with new_session(tenant.id) as db:
            add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                      value="*.example.com")
            with pytest.raises(Conflict):
                add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                          value="*.example.com")

    def test_a_wildcard_exclusion_shuts_out_the_whole_branch(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=("example.com",))
        with new_session(tenant.id) as db:
            add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                      value="*.dev.example.com", is_exclusion=True)
            db.commit()
            checker = load_checker(db, db.get(Organization, org.id))
            assert not checker.check(Target(kind=TargetKind.HOSTNAME, value="dev.example.com"), active=True).allowed
            assert not checker.check(Target(kind=TargetKind.HOSTNAME, value="api.dev.example.com"), active=True).allowed
            assert checker.check(Target(kind=TargetKind.HOSTNAME, value="www.example.com"), active=True).allowed

    def test_a_wildcard_on_a_public_suffix_is_still_refused(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=())
        with new_session(tenant.id) as db:
            with pytest.raises(ValidationFailed, match="public suffix"):
                add_entry(db, tenant_id=tenant.id, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                          value="*.com.sa")


class TestApi:
    def _auth(self, client, factory):
        tenant = factory.tenant()
        user = factory.user(tenant.id)
        org = factory.org(tenant.id, domains=())
        r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
        return org, {"Authorization": f"Bearer {r.json()['access_token']}"}

    def test_the_bulk_box_accepts_wildcards(self, client, factory):
        org, h = self._auth(client, factory)
        r = client.post("/api/v1/scopes/bulk", headers=h, json={
            "organization_id": str(org.id), "entries": ["ifmi.com.sa", "*.ifmi.sa", "203.0.113.0/24"]})
        assert r.status_code == 201, r.text
        assert {e["value"] for e in r.json()} == {"ifmi.com.sa", "ifmi.sa", "203.0.113.0/24"}
        assert next(e for e in r.json() if e["value"] == "ifmi.sa")["include_subdomains"] is True

    def test_a_bad_wildcard_explains_itself(self, client, factory):
        org, h = self._auth(client, factory)
        r = client.post("/api/v1/scopes/bulk", headers=h, json={
            "organization_id": str(org.id), "entries": ["a.*.example.com"]})
        assert r.status_code == 422 and "*.example.com" in r.text

    def test_the_scope_checker_understands_a_wildcard(self, client, factory):
        org, h = self._auth(client, factory)
        client.post("/api/v1/scopes/bulk", headers=h, json={
            "organization_id": str(org.id), "entries": ["*.example.com"]})
        r = client.post("/api/v1/scopes/check", headers=h, json={
            "organization_id": str(org.id), "target": "*.example.com", "active": True})
        assert r.status_code == 200 and r.json()["allowed"] is True
        assert r.json()["target"] == "example.com"
