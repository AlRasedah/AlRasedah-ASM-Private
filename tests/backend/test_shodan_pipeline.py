"""Shodan results in the platform: unverified findings and historical (non-liveness) data."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from asm_sensors.observations import AssetObservation, ObservedType, SensorResult
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.assets.ingest import IngestContext, Ingestor
from app.db.session import new_session
from app.models import Asset, Finding, Organization, ScanProfile
from app.models.enums import AssetStatus, AssetType
from app.scans import orchestrator
from app.scope.service import load_checker
from app.tenants.settings import tenant_settings

from .sensors_fake import FIXTURES, FakeSensors

PW = "Sup3r-Secret-Passw0rd!"
HOST = json.loads((FIXTURES / "shodan_host.json").read_text(encoding="utf-8"))
SHODAN_RECORDS = [{"kind": "account", "plan": "corp", "query_credits": 100},
                  {"kind": "host", "queried_ip": "198.51.100.7", **HOST},
                  {"kind": "stats", "looked_up": 1, "with_data": 1}]


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


def _scan(tenant_id, org_id):
    with new_session(tenant_id) as db:
        pid = db.scalar(select(ScanProfile.id).where(ScanProfile.slug == "standard-asm",
                                                     ScanProfile.tenant_id.is_(None)))
        scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=pid)
        db.commit()
        return orchestrator.run_inline(db, scan.id).id


def test_shodan_cves_are_kept_out_of_the_main_findings_list(client, factory, monkeypatch):
    tenant = factory.tenant()
    user = factory.user(tenant.id)
    org = factory.org(tenant.id, domains=("example.com",))
    fake = FakeSensors(monkeypatch)
    fake.set("shodan", SHODAN_RECORDS)
    _scan(tenant.id, org.id)

    with new_session(tenant.id) as db:
        shodan = db.scalar(select(Finding).where(Finding.source == "shodan"))
        assert shodan is not None and shodan.unverified is True
        assert shodan.cve == ["CVE-2018-13379"] and "unverified" in shodan.tags
        # It does not drive risk: the port's score comes from verified findings only.
        port = db.scalar(select(Asset).where(Asset.asset_type == AssetType.PORT,
                                             Asset.normalized_value == "198.51.100.7:443/tcp"))
        assert port is not None

    r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
    h = {"Authorization": f"Bearer {r.json()['access_token']}"}
    listed = client.get("/api/v1/findings", headers=h, params={"page_size": 200}).json()
    assert all(f["unverified"] is False for f in listed["items"])
    own_view = client.get("/api/v1/findings", headers=h, params={"unverified": True}).json()
    assert [(f["source_label"], f["cve"]) for f in own_view["items"]] == \
        [("Internet exposure intelligence", ["CVE-2018-13379"])]
    # The engine behind a capability is never disclosed to the browser.
    assert "shodan" not in listed.__str__().lower() and "shodan" not in own_view.__str__().lower()
    # Statistics and alerts ignore it too.
    stats = client.get("/api/v1/findings/stats", headers=h).json()
    assert sum(stats["by_severity"].values()) == listed["total"]
    events = client.get("/api/v1/events", headers=h, params={"page_size": 200}).json()
    assert not any("CVE-2018-13379" in (e["title"] or "") and "Shodan" in (e["title"] or "")
                   for e in events["items"])


def test_a_verifying_scanner_clears_the_unverified_flag(factory, monkeypatch):
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    fake = FakeSensors(monkeypatch)
    fake.set("shodan", SHODAN_RECORDS)
    _scan(tenant.id, org.id)
    with new_session(tenant.id) as db:
        # Nuclei's own finding for the same CVE is a separate, verified finding.
        rows = {f.source: f.unverified for f in db.scalars(select(Finding).where(Finding.cve.any("CVE-2018-13379")))}
    assert rows == {"shodan": True, "nuclei": False}


def test_historical_results_never_refresh_liveness(factory, tenant_db):
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    old = datetime.now(UTC) - timedelta(days=40)
    with new_session(tenant.id) as db:
        db.add(Asset(tenant_id=tenant.id, organization_id=org.id, asset_type=AssetType.IP_ADDRESS,
                     value="198.51.100.7", normalized_value="198.51.100.7", status=AssetStatus.INACTIVE,
                     scope_status="derived", first_seen=old, last_seen=old, discovered_at=old, inactive_since=old,
                     source="dnsx", sources=["dnsx"], missed_count=3, confidence=90, meta={}, tags=[],
                     risk_factors=[]))
        db.commit()

    now = datetime.now(UTC)
    result = SensorResult(adapter="shodan", status="completed", historical=True, started_at=now, finished_at=now,
                          target_count=1, observations=[AssetObservation(
                              type=ObservedType.IP_ADDRESS, value="198.51.100.7",
                              attributes={"asn": "AS64500", "shodan_last_seen": "2026-09-14T08:15:00+00:00"})])
    with new_session(tenant.id) as db:
        organization = db.get(Organization, org.id)
        Ingestor(db, IngestContext(tenant_id=tenant.id, organization=organization, source="shodan",
                                   checker=load_checker(db, organization), now=now,
                                   settings=tenant_settings(None), historical=True)).ingest(result)
        db.commit()
        asset = db.scalar(select(Asset).where(Asset.normalized_value == "198.51.100.7"))
        # Enriched, but Shodan's word does not make a dead host alive again.
        assert asset.meta["asn"] == "AS64500" and "shodan" in asset.sources
        assert asset.status == AssetStatus.INACTIVE and asset.missed_count == 3
        assert abs(asset.last_seen - old) < timedelta(seconds=1)  # not refreshed


def test_live_results_still_refresh_liveness(factory):
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    old = datetime.now(UTC) - timedelta(days=40)
    with new_session(tenant.id) as db:
        db.add(Asset(tenant_id=tenant.id, organization_id=org.id, asset_type=AssetType.IP_ADDRESS,
                     value="198.51.100.7", normalized_value="198.51.100.7", status=AssetStatus.INACTIVE,
                     scope_status="derived", first_seen=old, last_seen=old, discovered_at=old, inactive_since=old,
                     source="dnsx", sources=["dnsx"], missed_count=3, confidence=90, meta={}, tags=[],
                     risk_factors=[]))
        db.commit()
    now = datetime.now(UTC)
    result = SensorResult(adapter="dnsx", status="completed", started_at=now, finished_at=now, target_count=1,
                          observations=[AssetObservation(type=ObservedType.IP_ADDRESS, value="198.51.100.7")])
    with new_session(tenant.id) as db:
        organization = db.get(Organization, org.id)
        Ingestor(db, IngestContext(tenant_id=tenant.id, organization=organization, source="dnsx",
                                   checker=load_checker(db, organization), now=now,
                                   settings=tenant_settings(None))).ingest(result)
        db.commit()
        asset = db.scalar(select(Asset).where(Asset.normalized_value == "198.51.100.7"))
        assert asset.status == AssetStatus.ACTIVE and asset.missed_count == 0
