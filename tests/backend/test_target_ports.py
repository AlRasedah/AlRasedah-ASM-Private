"""Limiting a scan to an application on a non-default port (`host:8580`).

Reported from a real environment: starting a Web Application Scan against
`hrp.example.sa:8580` was refused with "Invalid target". The parser classified
anything containing a colon as an IP address, so `host:port` could never be
typed — and even once accepted it had to reach the HTTP stages, because the DAST
profile sweeps the "web" port set only and would never find 8580 by itself.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from asm_sensors.targets import TargetKind
from sqlalchemy import select

from app.core.errors import ScopeViolation, ValidationFailed
from app.db.session import new_session
from app.models import Asset, Organization, Scan, ScanProfile
from app.models.enums import AssetStatus, AssetType, ScopeStatus, StageType
from app.scans import orchestrator
from app.scans.targets import build_targets

HOST = "app.example.com"


def _profile(db, slug: str):
    return db.scalar(select(ScanProfile.id).where(ScanProfile.slug == slug, ScanProfile.tenant_id.is_(None)))


def _scan(db, tenant_id, org_id, targets: list[str], slug: str = "web-app-scan") -> Scan:
    scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id,
                                    profile_id=_profile(db, slug), target_override=targets)
    db.commit()
    return scan


def _asset(db, tenant_id, org_id, asset_type: AssetType, value: str) -> None:
    now = datetime.now(UTC)
    db.add(Asset(tenant_id=tenant_id, organization_id=org_id, asset_type=asset_type, value=value,
                 normalized_value=value, status=AssetStatus.ACTIVE, scope_status=ScopeStatus.IN_SCOPE,
                 first_seen=now, last_seen=now, discovered_at=now))


class TestParsing:
    @pytest.mark.parametrize(("raw", "kind", "value"), [
        ("app.example.com", TargetKind.HOSTNAME, "app.example.com"),
        ("app.example.com:8580", TargetKind.HOST_PORT, "app.example.com:8580"),
        ("  App.Example.com:8580 ", TargetKind.HOST_PORT, "app.example.com:8580"),
        ("192.0.2.10", TargetKind.IP, "192.0.2.10"),
        ("192.0.2.10:8443", TargetKind.HOST_PORT, "192.0.2.10:8443"),
        ("2001:db8::1", TargetKind.IP, "2001:db8::1"),  # colons, but not a port
        ("[2001:db8::1]:8443", TargetKind.HOST_PORT, "[2001:db8::1]:8443"),
        ("192.0.2.0/24", TargetKind.CIDR, "192.0.2.0/24"),
        ("https://app.example.com:8580/admin", TargetKind.URL, "https://app.example.com:8580/admin"),
    ])
    def test_what_a_user_may_type(self, raw, kind, value):
        t = orchestrator.parse_target(raw)
        assert (t.kind, t.value) == (kind, value)

    @pytest.mark.parametrize("raw", ["app.example.com:0", "app.example.com:99999", "app.example.com:http",
                                     "app.example.com:", ":8580", "", "   "])
    def test_what_is_still_refused(self, raw):
        with pytest.raises(ValueError):
            orchestrator.parse_target(raw)


class TestScopeStillApplies:
    def test_a_port_on_an_out_of_scope_host_is_refused(self, db_clean, factory):
        tenant, = (factory.tenant(),)
        org = factory.org(tenant.id, domains=("example.com",))
        with new_session(tenant.id) as db, pytest.raises(ScopeViolation):
            _scan(db, tenant.id, org.id, ["intranet.other-company.com:8580"])

    def test_a_malformed_port_names_the_accepted_forms(self, db_clean, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=("example.com",))
        with new_session(tenant.id) as db, pytest.raises(ValidationFailed) as exc:
            _scan(db, tenant.id, org.id, ["app.example.com:99999"])
        assert "host:port" in str(exc.value)


class TestTheStagesUseIt:
    def _org(self, factory):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=("example.com",))
        return tenant, org

    def test_the_named_port_is_probed_without_the_sweep_finding_it(self, db_clean, factory):
        tenant, org = self._org(factory)
        with new_session(tenant.id) as db:
            scan = _scan(db, tenant.id, org.id, [f"{HOST}:8580"])
            o = db.get(Organization, org.id)
            targets = build_targets(db, o, scan, StageType.HTTP_DISCOVERY, limit=500)
        values = {t.value for t in targets.targets}
        assert values == {f"{HOST}:8580"}, "the host is not even in inventory yet; it must still be probed"
        assert all(t.kind == TargetKind.HOST_PORT for t in targets.targets)

    def test_other_ports_on_that_host_are_left_alone(self, db_clean, factory):
        tenant, org = self._org(factory)
        with new_session(tenant.id) as db:
            o = db.get(Organization, org.id)
            for url in (f"https://{HOST}", f"https://{HOST}:8580", "https://other.example.com"):
                _asset(db, tenant.id, org.id, AssetType.HTTP_ENDPOINT, url)
            db.flush()
            scan = _scan(db, tenant.id, org.id, [f"{HOST}:8580"])
            crawl = build_targets(db, o, scan, StageType.WEB_CRAWL, limit=500)
            attack = build_targets(db, o, scan, StageType.VULNERABILITY_DETECTION, limit=500)
        assert {t.value for t in crawl.targets} == {f"https://{HOST}:8580"}
        assert {t.value for t in attack.targets} == {f"https://{HOST}:8580"}

    def test_naming_the_host_without_a_port_keeps_every_port(self, db_clean, factory):
        tenant, org = self._org(factory)
        with new_session(tenant.id) as db:
            o = db.get(Organization, org.id)
            for url in (f"https://{HOST}", f"https://{HOST}:8580"):
                _asset(db, tenant.id, org.id, AssetType.HTTP_ENDPOINT, url)
            db.flush()
            scan = _scan(db, tenant.id, org.id, [HOST])
            crawl = build_targets(db, o, scan, StageType.WEB_CRAWL, limit=500)
        assert {t.value for t in crawl.targets} == {f"https://{HOST}", f"https://{HOST}:8580"}

    def test_the_earlier_stages_still_select_by_host(self, db_clean, factory):
        tenant, org = self._org(factory)
        with new_session(tenant.id) as db:
            o = db.get(Organization, org.id)
            for name in (HOST, "other.example.com"):
                _asset(db, tenant.id, org.id, AssetType.SUBDOMAIN, name)
            db.flush()
            scan = _scan(db, tenant.id, org.id, [f"{HOST}:8580"], slug="standard-asm")
            dns = build_targets(db, o, scan, StageType.DNS_RESOLUTION, limit=500)
        assert {t.value for t in dns.targets} == {HOST}, "DNS resolves the host, port and all"
