"""End-to-end scan pipeline (inline mode) with recorded sensor output."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from app.core.errors import Conflict, ScopeViolation
from app.models import Asset, AssetEvent, Finding, MetricSnapshot, Organization, Scan, ScanProfile, ScopeDecision
from app.models.enums import (
    AssetType,
    DecisionResult,
    EventType,
    ScanStatus,
    ScopeStatus,
    StageStatus,
)
from app.scans import orchestrator

from .sensors_fake import FakeSensors


@pytest.fixture
def env(factory, tenant_db, monkeypatch):
    t = factory.tenant()
    org = factory.org(t.id, domains=("example.com",), exclusions=("dev-api.example.com",))
    fake = FakeSensors(monkeypatch)
    return t, org, fake


def profile_id(db, slug):
    return db.execute(select(ScanProfile.id).where(ScanProfile.slug == slug, ScanProfile.tenant_id.is_(None))).scalar_one()


def run(tenant_db, tenant_id, org_id, slug="standard-asm"):
    with tenant_db(tenant_id) as db:
        scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=profile_id(db, slug))
        db.commit()
        scan = orchestrator.run_inline(db, scan.id)
        return scan.id


def test_standard_scan_end_to_end(env, tenant_db):
    t, org, fake = env
    scan_id = run(tenant_db, t.id, org.id)
    with tenant_db(t.id) as db:
        scan = db.get(Scan, scan_id)
        assert scan.status == ScanStatus.COMPLETED, [(s.engine, s.status, s.error) for s in scan.stages]
        assert scan.is_baseline
        assert all(s.status in (StageStatus.COMPLETED, StageStatus.SKIPPED) for s in scan.stages)

        # --- scope enforcement: excluded host never reached any sensor
        for engine, calls in fake.calls.items():
            for targets in calls:
                assert not any("dev-api.example.com" in x for x in targets), engine
        rejected = db.execute(select(ScopeDecision).where(ScopeDecision.scan_id == scan_id,
                                                          ScopeDecision.decision == DecisionResult.REJECTED)).scalars().all()
        allowed = db.scalar(select(func.count()).select_from(ScopeDecision).where(
            ScopeDecision.scan_id == scan_id, ScopeDecision.decision == DecisionResult.ALLOWED))
        assert allowed > 0
        assert all(r.reason for r in rejected)
        # active port scan only hit authorized (derived) IPs
        naabu_targets = set(fake.calls["naabu"][0])
        assert "198.51.100.7" in naabu_targets and "203.0.113.5" not in naabu_targets

        # --- inventory
        def get(t_, v):
            return db.execute(select(Asset).where(Asset.organization_id == org.id, Asset.asset_type == t_,
                                                  Asset.normalized_value == v)).scalar_one_or_none()

        assert get(AssetType.SUBDOMAIN, "api.example.com").scope_status == ScopeStatus.IN_SCOPE
        assert get(AssetType.SUBDOMAIN, "dev-api.example.com") is None
        assert get(AssetType.PORT, "198.51.100.7:10443/tcp") is not None
        vpn = get(AssetType.HTTP_ENDPOINT, "https://vpn.example.com:10443")
        assert vpn is not None and vpn.meta["title"] == "Fortinet SSL VPN Login"
        assert get(AssetType.CLOUD_RESOURCE, "aws:cloudfront:d111111abcdef8.cloudfront.net") is not None
        assert get(AssetType.TECHNOLOGY, "nginx") is not None
        assert get(AssetType.IP_ADDRESS, "192.0.2.20").meta.get("asn") == "AS64500"

        # --- findings from the vulnerability sensor and from platform rules
        findings = {f.source_finding_id: f for f in db.execute(select(Finding)).scalars()}
        cve = findings["CVE-2018-13379"]
        assert cve.asset_id == vpn.id and cve.cvss_score == 9.8
        assert cve.risk_score >= 80 and cve.risk_level.value == "critical"
        assert {f["key"] for f in cve.risk_factors} >= {"severity", "epss", "exposure"}
        assert "exposed-service:3389/tcp" in findings  # RDP rule
        assert "weak-tls-protocol" in findings and "certificate-self-signed" in findings
        assert any(k.startswith("management-interface:") for k in findings)
        assert findings["certificate-expiring"].severity.value in ("medium", "low")

        # --- risk rolled up to hosts; metrics snapshot written; baseline recorded
        assert get(AssetType.SUBDOMAIN, "vpn.example.com").risk_score >= cve.risk_score
        assert db.get(Organization, org.id).baseline_completed_at is not None
        assert db.execute(select(MetricSnapshot).where(MetricSnapshot.organization_id == org.id)).scalar_one().risk_score > 0
        events = db.execute(select(AssetEvent).where(AssetEvent.scan_id == scan_id)).scalars().all()
        assert events and all(e.is_baseline for e in events if e.event_type != EventType.SCAN_COMPLETED)


def test_second_scan_detects_changes(env, tenant_db):
    t, org, fake = env
    run(tenant_db, t.id, org.id)
    # Next day: a new port appears on the VPN and the Swagger exposure is fixed.
    naabu = (b'{"ip":"198.51.100.7","port":443}\n{"ip":"198.51.100.7","port":10443}\n'
             b'{"ip":"198.51.100.7","port":8443}\n{"ip":"192.0.2.20","port":443}\n{"ip":"192.0.2.20","port":3389}\n')
    fake.set("naabu", naabu)
    scan2 = run(tenant_db, t.id, org.id)
    with tenant_db(t.id) as db:
        scan = db.get(Scan, scan2)
        assert scan.status == ScanStatus.COMPLETED and not scan.is_baseline
        evs = db.execute(select(AssetEvent).where(AssetEvent.scan_id == scan2)).scalars().all()
        opened = [e for e in evs if e.event_type == EventType.PORT_OPENED]
        assert [e.new_state["port"] for e in opened] == [8443]
        assert not opened[0].is_baseline
        # nothing from the first (baseline) inventory is reported as new again
        assert not [e for e in evs if e.event_type == EventType.NEW_SUBDOMAIN]


def test_scan_requires_scope_and_prevents_duplicates(factory, tenant_db, monkeypatch):
    FakeSensors(monkeypatch)
    t = factory.tenant()
    org_no_scope = factory.org(t.id, name="Empty", domains=())
    org = factory.org(t.id, name="Scoped", domains=("example.com",))
    with tenant_db(t.id) as db:
        pid = profile_id(db, "standard-asm")
        with pytest.raises(ScopeViolation):
            orchestrator.create_scan(db, tenant_id=t.id, organization_id=org_no_scope.id, profile_id=pid)
        with pytest.raises(ScopeViolation):
            orchestrator.create_scan(db, tenant_id=t.id, organization_id=org.id, profile_id=pid,
                                     target_override=["evil.org"])
        orchestrator.create_scan(db, tenant_id=t.id, organization_id=org.id, profile_id=pid)
        db.commit()
        with pytest.raises(Conflict):
            orchestrator.create_scan(db, tenant_id=t.id, organization_id=org.id, profile_id=pid)


def test_failed_optional_stage_is_skipped_and_required_failure_is_partial(env, tenant_db):
    t, org, fake = env

    def boom(targets):
        raise RuntimeError("sensor crashed")

    fake.set("amass", boom)  # optional stage
    fake.set("naabu", boom)  # required stage
    scan_id = run(tenant_db, t.id, org.id)
    with tenant_db(t.id) as db:
        scan = db.get(Scan, scan_id)
        by_engine = {s.engine: s for s in scan.stages}
        assert by_engine["amass"].status == StageStatus.SKIPPED
        assert by_engine["naabu"].status == StageStatus.FAILED
        assert scan.status == ScanStatus.PARTIAL


def test_global_concurrency_limit_spans_tenants(factory, tenant_db, monkeypatch):
    """A scan running in tenant A must count against the platform-wide limit seen by tenant B."""
    from app.core.config import get_settings

    FakeSensors(monkeypatch)
    monkeypatch.setattr(get_settings(), "max_concurrent_scans_global", 1)
    a, b = factory.tenant("A"), factory.tenant("B")
    org_a, org_b = factory.org(a.id, domains=("alpha-corp.com",)), factory.org(b.id, domains=("bravo-corp.com",))
    with tenant_db(a.id) as db:
        scan_a = orchestrator.create_scan(db, tenant_id=a.id, organization_id=org_a.id,
                                          profile_id=profile_id(db, "passive-discovery"))
        assert orchestrator.try_start(db, scan_a)
        db.commit()
    with tenant_db(b.id) as db:
        scan_b = orchestrator.create_scan(db, tenant_id=b.id, organization_id=org_b.id,
                                          profile_id=profile_id(db, "passive-discovery"))
        assert not orchestrator.try_start(db, scan_b)
        assert scan_b.status == ScanStatus.QUEUED


def test_passive_profile_never_runs_active_sensors(env, tenant_db):
    t, org, fake = env
    run(tenant_db, t.id, org.id, slug="passive-discovery")
    assert not {"naabu", "httpx", "nuclei"} & set(fake.calls)
