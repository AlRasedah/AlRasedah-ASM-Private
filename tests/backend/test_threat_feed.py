"""Automatic advisories from CISA KEV / NVD, on PostgreSQL with RLS.

NVD is replaced by a local fake (respx); nothing leaves the machine. The inventory
comes from the same fake scan as the Threat Center tests: https://api.example.com
runs nginx 1.24.0.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import respx
from sqlalchemy import func, select

from .test_threat_center import _assets, _scan, world  # noqa: F401  (fixture)

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OLD = "2023-01-10"


def cve(cve_id, *, cpes=(), kev_added=None, modified="2026-09-01T00:00:00.000", score=9.8, name=None):
    matches = []
    for c in cpes:
        crit, *bounds = c if isinstance(c, tuple) else (c,)
        m = {"vulnerable": True, "criteria": crit, "matchCriteriaId": "x"}
        for b in bounds:
            m.update(b)
        matches.append(m)
    rec = {"id": cve_id, "published": "2023-01-01T00:00:00.000", "lastModified": modified, "vulnStatus": "Analyzed",
           "descriptions": [{"lang": "en", "value": f"{cve_id} lets an attacker do bad things."}],
           "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score}}]},
           "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}] if matches else [],
           "references": [{"url": f"https://vendor.example.org/{cve_id}"}]}
    if kev_added:
        rec.update(cisaExploitAdd=kev_added, cisaVulnerabilityName=name or f"Example {cve_id} vulnerability",
                   cisaRequiredAction="Apply mitigations per vendor instructions.")
    return rec


NGINX_RANGE = ("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", {"versionStartIncluding": "1.20.0", "versionEndExcluding": "1.25.0"})


class FakeNvd:
    def __init__(self) -> None:
        self.kev: list[dict] = []
        self.critical: list[dict] = []
        self.status = 200
        self.calls: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        raw = urlsplit(str(request.url)).query
        q = {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}
        flags = [p for p in raw.split("&") if p and "=" not in p]
        self.calls.append({"q": q, "flags": flags, "key": request.headers.get("apiKey")})
        if self.status != 200:
            return httpx.Response(self.status)
        if "cveId" in q:
            items = [c for c in self.kev + self.critical if c["id"] == q["cveId"]]
        elif "hasKev" in flags:
            items = self.kev
        else:
            items = self.critical
        return httpx.Response(200, json={"totalResults": len(items), "resultsPerPage": 2000, "startIndex": 0,
                                         "vulnerabilities": [{"cve": c} for c in items]})


@pytest.fixture
def nvd(monkeypatch):
    from app.threats import feed

    monkeypatch.setattr(feed, "_sleep", lambda s: None)
    fake = FakeNvd()
    with respx.mock(assert_all_called=False) as router:
        router.get(url__startswith=NVD).mock(side_effect=fake)
        yield fake


def _run(c, root):
    r = c.post("/api/v1/threat-catalog/feed/run", headers=root)
    assert r.status_code == 202, r.text


def _listed(c, h, **q):
    return {i["cves"][0]: i for i in c.get("/api/v1/threats", headers=h, params={"page_size": 100, **q}).json()["items"]}


def test_exploited_vulnerabilities_become_published_advisories_matched_to_inventory(world, nvd, system_db):
    from app.models import AssetEvent

    c, root, analyst = world["c"], world["root"], world["analyst"]
    _scan(c, analyst, admin=root)
    today = datetime.now(UTC).date().isoformat()
    nvd.kev = [cve("CVE-2099-0001", cpes=[NGINX_RANGE], kev_added=OLD),
               cve("CVE-2099-0002", cpes=[("cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",)], kev_added=today),
               cve("CVE-2099-0004", cpes=["cpe:2.3:a:acme:widget_server:*:*:*:*:*:*:*:*"], kev_added=OLD)]
    _run(c, root)
    everything = _listed(c, analyst)
    assert set(everything) == {"CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0004"}
    assert all(a["origin"] == "feed" for a in everything.values())
    mine = _listed(c, analyst, relevant=True)
    assert set(mine) == {"CVE-2099-0001", "CVE-2099-0002"}  # nothing runs acme widget here
    adv = mine["CVE-2099-0001"]
    m = _assets(c, analyst, adv["id"])["https://api.example.com"]
    assert m["assessment"] == "potentially_affected" and "1.24.0" in m["evidence"]["observations"][0]["reason"]
    detail = c.get(f"/api/v1/threats/{adv['id']}", headers=analyst).json()
    assert detail["check"]["key"] == "cve-2099-0001" and detail["severity"] == "critical"
    assert any(r.startswith("https://vendor.example.org/") for r in detail["references"])
    assert "not endorsed or certified by the NVD" in detail["remediation"]
    # The long-known one is inventory, not news: only the newly exploited one notifies.
    events = system_db.execute(select(AssetEvent.title).where(
        AssetEvent.event_type == "threat_advisory_matched")).scalars().all()
    assert len(events) == 1 and "CVE-2099-0002" in events[0]
    # One summary audit entry, not one per advisory.
    from app.models import AuditLog

    actions = system_db.execute(select(AuditLog.action).where(AuditLog.action.like("threat_%"))).scalars().all()
    assert actions.count("threat_feed.run") == 1 and "threat_advisory.published" not in actions


def test_the_feed_is_incremental_and_publishes_only_real_changes(world, nvd, system_db):
    from app.models import ThreatAdvisory

    c, root, analyst = world["c"], world["root"], world["analyst"]
    _scan(c, analyst, admin=root)
    nvd.kev = [cve("CVE-2099-0001", cpes=[NGINX_RANGE], kev_added=OLD)]
    _run(c, root)
    first = nvd.calls[-1]
    assert "hasKev" in first["flags"] and "lastModStartDate" not in first["q"]
    _run(c, root)  # nothing changed
    assert "lastModStartDate" in nvd.calls[-1]["q"]
    adv = system_db.execute(select(ThreatAdvisory).where(ThreatAdvisory.slug == "cve-2099-0001")).scalar_one()
    assert adv.published_version == 1
    # NVD revises the range: the fix is now 1.24.0, so 1.24.0 is no longer affected.
    nvd.kev = [cve("CVE-2099-0001", modified="2026-09-20T00:00:00.000", kev_added=OLD, cpes=[(
        "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", {"versionStartIncluding": "1.20.0", "versionEndExcluding": "1.24.0"})])]
    _run(c, root)
    system_db.expire_all()
    assert system_db.get(ThreatAdvisory, adv.id).published_version == 2
    m = _assets(c, analyst, str(adv.id))["https://api.example.com"]
    assert m["assessment"] == "not_affected_version"


def test_the_feed_never_touches_an_advisory_written_by_an_administrator(world, nvd):
    from .test_threat_center import NGINX, _approve_check, _publish

    c, root, analyst = world["c"], world["root"], world["analyst"]
    _approve_check(c, root)
    manual_id = _publish(c, root, slug="cve-2099-0001", content={**NGINX, "title": "Our own words"})
    nvd.kev = [cve("CVE-2099-0001", cpes=[NGINX_RANGE], kev_added=OLD)]
    _run(c, root)
    detail = c.get(f"/api/v1/threats/{manual_id}", headers=analyst).json()
    assert detail["title"] == "Our own words" and detail["origin"] == "manual" and detail["published_version"] == 1
    status = c.get("/api/v1/threat-catalog/feed", headers=root).json()["status"]
    assert status["by_status"] == {"manual": 1}


def test_publishing_modes_and_recent_critical_cves(world, nvd):
    c, root, analyst = world["c"], world["root"], world["analyst"]
    _scan(c, analyst, admin=root)
    nvd.kev = [cve("CVE-2099-0001", cpes=[NGINX_RANGE], kev_added=OLD)]
    nvd.critical = [cve("CVE-2099-0003", cpes=[NGINX_RANGE])]
    r = c.put("/api/v1/threat-catalog/feed", headers=root, json={"include_critical": True})
    assert r.status_code == 200, r.text
    _run(c, root)
    # KEV published automatically; the not-yet-exploited one waits as a draft tenants cannot see.
    assert set(_listed(c, analyst)) == {"CVE-2099-0001"}
    drafts = c.get("/api/v1/threat-catalog", headers=root, params={"drafts": True, "origin": "feed"}).json()
    assert [d["slug"] for d in drafts] == ["cve-2099-0003"]
    assert any(call["q"].get("cvssV3Severity") == "CRITICAL" for call in nvd.calls)
    c.put("/api/v1/threat-catalog/feed", headers=root, json={"publish": "all"})
    nvd.critical = [cve("CVE-2099-0003", cpes=[NGINX_RANGE], modified="2026-09-21T00:00:00.000")]
    _run(c, root)
    assert set(_listed(c, analyst)) == {"CVE-2099-0001", "CVE-2099-0003"}


def test_settings_are_platform_admin_only_and_the_nvd_key_is_never_shown(world, nvd, system_db):
    from app.models import AuditLog, PlatformSetting

    c, root, analyst, bravo = world["c"], world["root"], world["analyst"], world["bravo"]
    assert c.get("/api/v1/threat-catalog/feed", headers=analyst).status_code == 403
    assert c.put("/api/v1/threat-catalog/feed", headers=bravo, json={"enabled": False}).status_code == 403
    assert c.post("/api/v1/threat-catalog/feed/run", headers=analyst).status_code == 403
    key = "0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"
    r = c.put("/api/v1/threat-catalog/feed", headers=root, json={
        "nvd_api_key": key, "aliases": {"Acme:Widget_Server": ["Acme Widget", "widgetd"]}})
    assert r.status_code == 200, r.text
    assert key not in r.text and r.json()["status"]["has_api_key"] is True
    assert r.json()["settings"]["aliases"] == {"acme:widget_server": ["acme widget", "widgetd"]}
    system_db.expire_all()
    assert key not in (system_db.get(PlatformSetting, 1).nvd_api_key_ciphertext or "")
    assert all(key not in f"{a.new}{a.previous}" for a in system_db.execute(select(AuditLog)).scalars())
    nvd.kev = []
    _run(c, root)
    assert nvd.calls and all(call["key"] == key for call in nvd.calls)
    bad = c.put("/api/v1/threat-catalog/feed", headers=root, json={"aliases": {"no-colon": ["x"]}})
    assert bad.status_code == 422
    c.put("/api/v1/threat-catalog/feed", headers=root, json={"clear_nvd_api_key": True})
    assert c.get("/api/v1/threat-catalog/feed", headers=root).json()["status"]["has_api_key"] is False


def test_an_unreachable_nvd_is_reported_and_changes_nothing(world, nvd, system_db):
    from app.models import ThreatAdvisory

    c, root = world["c"], world["root"]
    nvd.status = 503
    _run(c, root)
    kev = c.get("/api/v1/threat-catalog/feed", headers=root).json()["status"]["sources"]["kev"]
    assert "503" in kev["last_error"] and kev["last_success_at"] is None
    assert system_db.scalar(select(func.count()).select_from(ThreatAdvisory)) == 0
    nvd.status = 200
    nvd.kev = [cve("CVE-2099-0001", cpes=[NGINX_RANGE], kev_added=OLD)]
    _run(c, root)  # the next run starts from scratch again
    assert "lastModStartDate" not in nvd.calls[-1]["q"]
    assert system_db.scalar(select(func.count()).select_from(ThreatAdvisory)) == 1


def test_turned_off_it_fetches_nothing(world, nvd):
    c, root = world["c"], world["root"]
    c.put("/api/v1/threat-catalog/feed", headers=root, json={"enabled": False})
    _run(c, root)
    assert nvd.calls == []


# ------------------------------------------------------------------ parsing (pure)
def test_nvd_configurations_become_affected_products_and_ranges():
    from app.threats import feed

    rec = feed.parse_record(cve("CVE-2099-0100", kev_added=OLD, cpes=[
        ("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",),
        ("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", {"versionStartExcluding": "2.4.0",
                                                          "versionEndIncluding": "2.4.50"}),
        ("cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",),  # every version
        ("cpe:2.3:h:fortinet:fortigate_60f:-:*:*:*:*:*:*:*",),  # hardware: never fingerprinted by name
        ("cpe:2.3:a:acme:tool\\:kit:1.0:*:*:*:*:*:*:*",),  # escaped ':' in the product
    ]))
    by = {(p["vendor"], p["product"]): p for p in rec["products"]}
    assert set(by) == {("apache", "http_server"), ("fortinet", "fortios"), ("acme", "tool:kit")}
    assert by[("apache", "http_server")]["ranges"] == [{"introduced": "2.4.49", "last_affected": "2.4.49"},
                                                        {"introduced": "2.4.0", "last_affected": "2.4.50"}]
    assert by[("fortinet", "fortios")]["all_versions"] is True
    content = feed.content_for(rec, {"acme:tool:kit": ["acme toolkit"]}, "cve-2099-0100", ("Apache", "HTTP Server"))
    names = {p.product: p.match_names for p in content.affected}
    assert "apache" in names["http server"] and "apache http server" in names["http server"]
    assert "http server" not in names["http server"]  # too generic on its own
    assert "fortigate" in names["fortios"] and not [p for p in content.affected if p.product == "fortios"][0].versions
    assert content.check_keys == ["cve-2099-0100"] and content.cves == ["CVE-2099-0100"]
    assert content.title == "Example CVE-2099-0100 vulnerability" and content.severity == "critical"


def test_a_platform_only_node_and_rejected_cves_are_ignored():
    from app.threats import feed

    rec = cve("CVE-2099-0101", cpes=[("cpe:2.3:a:vendor:app:1.0:*:*:*:*:*:*:*",)])
    rec["configurations"][0]["nodes"].append({"operator": "OR", "negate": False, "cpeMatch": [
        {"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]})
    assert [p["product"] for p in feed.parse_record(rec)["products"]] == ["app"]
    assert feed.parse_record({**rec, "vulnStatus": "Rejected"}) is None


def test_more_ranges_than_an_advisory_holds_collapse_to_one_wider_range():
    from app.threats import feed

    cpes = [("cpe:2.3:a:vendor:app:*:*:*:*:*:*:*:*", {"versionStartIncluding": f"1.{i}.0",
                                                     "versionEndExcluding": f"1.{i}.9"}) for i in range(25)]
    content = feed.content_for(feed.parse_record(cve("CVE-2099-0102", cpes=cpes)), {}, None)
    (p,) = content.affected
    assert [(r.introduced, r.fixed) for r in p.versions] == [("1.0.0", "1.24.9")]


def test_a_cve_without_product_data_still_matches_through_findings():
    from app.threats import feed

    content = feed.content_for(feed.parse_record(cve("CVE-2099-0103", kev_added=OLD)), {}, None)
    assert content.affected == [] and content.cves == ["CVE-2099-0103"]


def test_backfill_quiet_period_is_bounded():
    from types import SimpleNamespace

    from app.threats.service import _quiet_backfill

    now = datetime.now(UTC)
    old = now - timedelta(days=400)
    assert _quiet_backfill(SimpleNamespace(origin="feed", created_at=now, source_published_at=old), now)
    assert not _quiet_backfill(SimpleNamespace(origin="feed", created_at=now - timedelta(days=2),
                                               source_published_at=old), now)
    assert not _quiet_backfill(SimpleNamespace(origin="feed", created_at=now, source_published_at=now), now)
    assert not _quiet_backfill(SimpleNamespace(origin="manual", created_at=now, source_published_at=old), now)


def test_post_scan_matching_starts_only_after_the_outermost_commit(world, tenant_db, monkeypatch):
    """A released savepoint is not a commit: starting then would wait on the open transaction's locks."""
    import uuid

    from app.threats import service
    from app.workers import dispatch

    started: list = []
    monkeypatch.setattr(dispatch, "evaluate_organization", lambda t, o: started.append((t, o)))
    tid, org = world["ta"].id, uuid.uuid4()
    with tenant_db(tid) as db:
        with db.begin_nested():
            service._after_outer_commit(db, ("threat-evaluate", tid, org))
        assert started == []  # savepoint released, outer transaction still open
        db.commit()
        assert started == [(tid, org)]
        db.execute(select(1))
        service._after_outer_commit(db, ("threat-evaluate", tid, org))
        db.rollback()
        db.execute(select(1))
        db.commit()
        assert started == [(tid, org)]  # a rolled-back transaction starts nothing
