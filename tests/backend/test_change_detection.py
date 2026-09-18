"""Historical state & change detection through the ingestion engine."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from asm_sensors.observations import (
    AssetObservation,
    AssetRef,
    FindingCoverage,
    FindingObservation,
    LivenessCoverage,
    ObservedType as O,
    RelationCoverage,
    RelationObservation,
    RelationType as R,
    SensorResult,
    Severity,
)
from sqlalchemy import select

from app.assets.ingest import IngestContext, Ingestor
from app.models import Asset, AssetEvent, AssetRelationship, Finding, Organization, Tenant
from app.models.enums import AssetStatus, AssetType, EventType, FindingStatus, ScopeStatus
from app.scope.service import load_checker
from app.tenants.settings import tenant_settings


def a(t, v, **attrs):
    return AssetObservation(type=t, value=v, attributes=attrs)


def rel(st, sv, r, tt, tv, **attrs):
    return RelationObservation(source=AssetRef(type=st, value=sv), target=AssetRef(type=tt, value=tv), relation=r,
                               attributes=attrs)


def result(adapter, obs, cov=()):
    now = datetime.now(UTC)
    return SensorResult(adapter=adapter, started_at=now, finished_at=now, observations=list(obs), coverage=list(cov))


class World:
    def __init__(self, tenant_id, org_id, tenant_db):
        self.tenant_id, self.org_id, self.tenant_db = tenant_id, org_id, tenant_db
        self.clock = datetime.now(UTC)
        self.baseline = True

    def ingest(self, res, baseline=None):
        self.clock += timedelta(hours=1)
        with self.tenant_db(self.tenant_id) as db:
            org = db.get(Organization, self.org_id)
            ts = tenant_settings(db.get(Tenant, self.tenant_id))
            out = Ingestor(db, IngestContext(
                tenant_id=self.tenant_id, organization=org, source=res.adapter, checker=load_checker(db, org),
                now=self.clock, settings=ts, discovery_method="test",
                baseline=self.baseline if baseline is None else baseline)).ingest(res)
            db.commit()
            return [(e.event_type, e.title) for e in out.events], out

    def asset(self, t, v):
        with self.tenant_db(self.tenant_id) as db:
            return db.execute(select(Asset).where(Asset.organization_id == self.org_id, Asset.asset_type == t,
                                                  Asset.normalized_value == v)).scalar_one_or_none()

    def rows(self, model, *where):
        with self.tenant_db(self.tenant_id) as db:
            return db.execute(select(model).where(*where)).scalars().all()


@pytest.fixture
def world(factory, tenant_db):
    t = factory.tenant()
    org = factory.org(t.id, domains=("example.com",), exclusions=("excluded.example.com",))
    return World(t.id, org.id, tenant_db)


def dns(host, *ips, cname=None):
    records = {"a": list(ips)}
    obs = [a(O.HOSTNAME, host, dns=records, resolves=True)]
    for ip in ips:
        obs += [a(O.IP_ADDRESS, ip), rel(O.HOSTNAME, host, R.RESOLVES_TO, O.IP_ADDRESS, ip)]
    return obs


def dns_cov(*hosts):
    return [LivenessCoverage(asset_type=O.HOSTNAME, values=list(hosts)),
            RelationCoverage(parent_type=O.HOSTNAME, parents=list(hosts), relation=R.RESOLVES_TO,
                             child_type=O.IP_ADDRESS)]


def ports(ip, *nums, spec="1-65535"):
    obs = [a(O.IP_ADDRESS, ip)]
    for p in nums:
        v = f"{ip}:{p}/tcp"
        obs += [a(O.PORT, v, port=p, protocol="tcp", ip=ip), rel(O.IP_ADDRESS, ip, R.HAS_PORT, O.PORT, v)]
    return obs, [RelationCoverage(parent_type=O.IP_ADDRESS, parents=[ip], relation=R.HAS_PORT, child_type=O.PORT,
                                  constraints={"port_spec": spec})]


def types(events):
    return [t for t, _ in events]


def test_new_assets_scope_and_baseline(world):
    evs, _ = world.ingest(result("dnsx", dns("api.example.com", "192.0.2.20") + dns("excluded.example.com", "192.0.2.99")
                                 + [a(O.HOSTNAME, "unrelated.org")], dns_cov("api.example.com")))
    sub = world.asset(AssetType.SUBDOMAIN, "api.example.com")
    assert sub and sub.scope_status == ScopeStatus.IN_SCOPE and sub.approval_status.value == "unverified"
    ip = world.asset(AssetType.IP_ADDRESS, "192.0.2.20")
    assert ip.scope_status == ScopeStatus.DERIVED  # resolved from an in-scope name
    # excluded names and unrelated third parties are not kept
    assert world.asset(AssetType.SUBDOMAIN, "excluded.example.com") is None
    assert world.asset(AssetType.DOMAIN, "unrelated.org") is None
    assert world.asset(AssetType.IP_ADDRESS, "192.0.2.99") is None
    assert EventType.NEW_SUBDOMAIN in types(evs)
    events = world.rows(AssetEvent)
    assert events and all(e.is_baseline for e in events)
    # subdomain linked to its root domain
    root = world.asset(AssetType.ROOT_DOMAIN, "example.com")
    links = world.rows(AssetRelationship, AssetRelationship.source_asset_id == sub.id,
                       AssetRelationship.target_asset_id == root.id)
    assert links and links[0].relation_type.value == "subdomain_of"


def test_ip_change_and_old_ip_retired(world):
    world.ingest(result("dnsx", dns("api.example.com", "192.0.2.20"), dns_cov("api.example.com")))
    world.baseline = False
    evs, _ = world.ingest(result("dnsx", dns("api.example.com", "192.0.2.21"), dns_cov("api.example.com")))
    ip_ev = [t for t in evs if t[0] == EventType.IP_CHANGED]
    assert ip_ev and "api.example.com" in ip_ev[0][1]
    assert world.asset(AssetType.IP_ADDRESS, "192.0.2.20").status == AssetStatus.ACTIVE  # 1 miss < threshold 2
    world.ingest(result("dnsx", dns("api.example.com", "192.0.2.21"), dns_cov("api.example.com")))
    old = world.asset(AssetType.IP_ADDRESS, "192.0.2.20")
    assert old.status == AssetStatus.INACTIVE and old.inactive_since is not None
    assert world.asset(AssetType.IP_ADDRESS, "192.0.2.21").status == AssetStatus.ACTIVE


def test_new_port_then_port_closed(world):
    world.ingest(result("dnsx", dns("vpn.example.com", "198.51.100.7"), dns_cov("vpn.example.com")))
    world.baseline = False
    obs, cov = ports("198.51.100.7", 443)
    world.ingest(result("naabu", obs, cov))
    obs, cov = ports("198.51.100.7", 443, 10443)
    evs, _ = world.ingest(result("naabu", obs, cov))
    opened = [title for t, title in evs if t == EventType.PORT_OPENED]
    assert opened == ["New externally exposed service: 10443/tcp on 198.51.100.7"]
    # 10443 disappears; after two covered misses it is closed
    obs, cov = ports("198.51.100.7", 443)
    evs1, _ = world.ingest(result("naabu", obs, cov))
    assert EventType.PORT_CLOSED not in types(evs1)
    evs2, _ = world.ingest(result("naabu", obs, cov))
    assert EventType.PORT_CLOSED in types(evs2)
    port = world.asset(AssetType.PORT, "198.51.100.7:10443/tcp")
    assert port.status == AssetStatus.INACTIVE
    assert port.first_seen < port.inactive_since  # history preserved, never deleted
    # port re-opens
    obs, cov = ports("198.51.100.7", 443, 10443)
    evs3, _ = world.ingest(result("naabu", obs, cov))
    assert any("re-opened" in title for _, title in evs3)
    assert world.asset(AssetType.PORT, "198.51.100.7:10443/tcp").status == AssetStatus.ACTIVE


def test_uncovered_ports_are_not_closed(world):
    world.ingest(result("dnsx", dns("vpn.example.com", "198.51.100.7"), dns_cov("vpn.example.com")))
    obs, cov = ports("198.51.100.7", 443, 8443, spec="1-65535")
    world.ingest(result("naabu", obs, cov))
    # A later scan probing only web ports 80,443 must not close 8443
    for _ in range(3):
        obs, cov = ports("198.51.100.7", 443, spec="80,443")
        world.ingest(result("naabu", obs, cov))
    assert world.asset(AssetType.PORT, "198.51.100.7:8443/tcp").status == AssetStatus.ACTIVE
    # And a failed/partial run (no coverage) never closes anything
    for _ in range(3):
        world.ingest(result("naabu", ports("198.51.100.7", 443)[0], []))
    assert world.asset(AssetType.PORT, "198.51.100.7:443/tcp").status == AssetStatus.ACTIVE


def test_host_disappears_and_reappears(world):
    world.ingest(result("dnsx", dns("old.example.com", "192.0.2.30"), dns_cov("old.example.com")))
    world.baseline = False
    events = []
    for _ in range(3):
        evs, _ = world.ingest(result("dnsx", [], dns_cov("old.example.com")))
        events += evs
    gone = [title for t, title in events if t == EventType.ASSET_DISAPPEARED]
    assert gone.count("old.example.com no longer resolves") == 1  # emitted once, not on every miss
    # its derived IP also left the attack surface
    assert world.asset(AssetType.IP_ADDRESS, "192.0.2.30").status == AssetStatus.INACTIVE
    host = world.asset(AssetType.SUBDOMAIN, "old.example.com")
    assert host.status == AssetStatus.INACTIVE
    evs, _ = world.ingest(result("dnsx", dns("old.example.com", "192.0.2.30"), dns_cov("old.example.com")))
    assert EventType.ASSET_REAPPEARED in types(evs)
    assert world.asset(AssetType.SUBDOMAIN, "old.example.com").status == AssetStatus.ACTIVE


def test_disappearing_host_retires_its_web_endpoints(world):
    world.ingest(result("dnsx", dns("shop.example.com", "192.0.2.40"), dns_cov("shop.example.com")))
    world.ingest(result("httpx", [a(O.HTTP_ENDPOINT, "https://shop.example.com", title="Shop", port=443),
                                  rel(O.HOSTNAME, "shop.example.com", R.SERVES, O.HTTP_ENDPOINT, "https://shop.example.com")]))
    for _ in range(3):
        world.ingest(result("dnsx", [], dns_cov("shop.example.com")))
    assert world.asset(AssetType.HTTP_ENDPOINT, "https://shop.example.com").status == AssetStatus.INACTIVE


def _nuclei_finding(url, rule="CVE-2018-13379", sev=Severity.CRITICAL):
    return FindingObservation(asset=AssetRef(type=O.HTTP_ENDPOINT, value=url), rule_id=rule, title="FortiOS path traversal",
                              severity=sev, cve=["CVE-2018-13379"], cvss_score=9.8, location=url + "/remote/x",
                              tags=["cve"])


def test_finding_dedup_resolve_and_reopen(world):
    url = "https://vpn.example.com:10443"
    world.ingest(result("dnsx", dns("vpn.example.com", "198.51.100.7"), dns_cov("vpn.example.com")))
    base = [a(O.HTTP_ENDPOINT, url), rel(O.HOSTNAME, "vpn.example.com", R.SERVES, O.HTTP_ENDPOINT, url)]
    world.ingest(result("httpx", base))
    world.baseline = False
    cov = [FindingCoverage(assets=[AssetRef(type=O.HTTP_ENDPOINT, value=url)], severities=list(Severity))]
    evs, _ = world.ingest(result("nuclei", [_nuclei_finding(url)], cov))
    assert EventType.VULNERABILITY_DETECTED in types(evs)
    evs, _ = world.ingest(result("nuclei", [_nuclei_finding(url)], cov))
    assert EventType.VULNERABILITY_DETECTED not in types(evs)
    findings = world.rows(Finding)
    assert len(findings) == 1 and findings[0].occurrence_count == 2  # de-duplicated
    world.ingest(result("nuclei", [], cov))
    assert world.rows(Finding)[0].status == FindingStatus.NEW  # 1 miss < threshold
    evs, _ = world.ingest(result("nuclei", [], cov))
    f = world.rows(Finding)[0]
    assert f.status == FindingStatus.REMEDIATED and f.resolved_at is not None
    assert EventType.VULNERABILITY_RESOLVED in types(evs)
    evs, _ = world.ingest(result("nuclei", [_nuclei_finding(url)], cov))
    assert world.rows(Finding)[0].status == FindingStatus.REOPENED
    assert EventType.VULNERABILITY_REOPENED in types(evs)
    # a scan with a narrower filter (critical excluded) does not resolve it
    narrow = [FindingCoverage(assets=[AssetRef(type=O.HTTP_ENDPOINT, value=url)], severities=[Severity.LOW])]
    for _ in range(3):
        world.ingest(result("nuclei", [], narrow))
    assert world.rows(Finding)[0].status == FindingStatus.REOPENED


def test_service_version_technology_and_certificate_changes(world):
    url = "https://api.example.com"
    world.ingest(result("dnsx", dns("api.example.com", "192.0.2.20"), dns_cov("api.example.com")))

    def http(version, tech_version, cert_fp, issuer):
        svc = "192.0.2.20:443/tcp"
        return [
            a(O.HTTP_ENDPOINT, url, port=443, scheme="https"),
            rel(O.HOSTNAME, "api.example.com", R.SERVES, O.HTTP_ENDPOINT, url),
            a(O.PORT, svc, port=443), rel(O.IP_ADDRESS, "192.0.2.20", R.HAS_PORT, O.PORT, svc),
            a(O.SERVICE, svc, name="https", product="nginx", version=version),
            rel(O.PORT, svc, R.RUNS_SERVICE, O.SERVICE, svc),
            a(O.TECHNOLOGY, "wordpress", name="WordPress"),
            rel(O.HTTP_ENDPOINT, url, R.USES_TECHNOLOGY, O.TECHNOLOGY, "wordpress", version=tech_version),
            a(O.CERTIFICATE, cert_fp, subject_cn="api.example.com", issuer_cn=issuer, not_after="2027-01-01T00:00:00Z"),
            rel(O.HTTP_ENDPOINT, url, R.PRESENTS_CERTIFICATE, O.CERTIFICATE, cert_fp),
        ]

    world.ingest(result("httpx", http("1.24.0", "6.1", "aaaaaaaa11", "CA One")))
    world.baseline = False
    evs, _ = world.ingest(result("httpx", http("1.25.3", "6.4", "bbbbbbbb22", "CA Two")))
    got = set(types(evs))
    assert {EventType.SERVICE_CHANGED, EventType.TECHNOLOGY_CHANGED, EventType.CERTIFICATE_CHANGED} <= got
    cert_ev = next(title for t, title in evs if t == EventType.CERTIFICATE_CHANGED)
    assert url in cert_ev
    # technology removed after covered misses
    tech_cov = [RelationCoverage(parent_type=O.HTTP_ENDPOINT, parents=[url], relation=R.USES_TECHNOLOGY,
                                 child_type=O.TECHNOLOGY)]
    events = []
    for _ in range(2):
        e, _ = world.ingest(result("httpx", [a(O.HTTP_ENDPOINT, url)], tech_cov))
        events += e
    assert EventType.TECHNOLOGY_REMOVED in [t for t, _ in events]


def test_cloud_resource_from_cname(world):
    obs = dns("cdn.example.com", "203.0.113.80") + [
        a(O.HOSTNAME, "d111111abcdef8.cloudfront.net"),
        rel(O.HOSTNAME, "cdn.example.com", R.CNAME, O.HOSTNAME, "d111111abcdef8.cloudfront.net")]
    world.ingest(result("dnsx", obs, dns_cov("cdn.example.com")))
    cr = world.asset(AssetType.CLOUD_RESOURCE, "aws:cloudfront:d111111abcdef8.cloudfront.net")
    assert cr is not None and cr.meta["provider"] == "aws"
    target = world.asset(AssetType.DOMAIN, "cloudfront.net") or world.asset(AssetType.SUBDOMAIN, "d111111abcdef8.cloudfront.net")
    assert target is not None and target.scope_status == ScopeStatus.OUT_OF_SCOPE  # third-party, never scanned


def test_hosting_change_via_asn_enrichment(world):
    world.ingest(result("dnsx", dns("api.example.com", "192.0.2.20"), dns_cov("api.example.com")))
    world.ingest(result("asnlookup", [a(O.IP_ADDRESS, "192.0.2.20", asn="AS64500", as_name="OLD-NET")]))
    world.baseline = False
    evs, _ = world.ingest(result("asnlookup", [a(O.IP_ADDRESS, "192.0.2.20", asn="AS13335", as_name="CLOUDFLARENET")]))
    assert EventType.HOSTING_CHANGED in types(evs)
    ip = world.asset(AssetType.IP_ADDRESS, "192.0.2.20")
    assert ip.meta["hosting_provider"] == "cloudflare" and ip.meta["cdn"] is True
