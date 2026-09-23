"""Threat Center on PostgreSQL with RLS: catalog, evaluation, checks, isolation."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"

NGINX = {"title": "Test nginx flaw", "severity": "critical", "cves": ["CVE-2099-0001"],
         "summary": "A test advisory.", "remediation": "Upgrade nginx.",
         "references": ["https://nvd.example.org/CVE-2099-0001"],
         "affected": [{"vendor": "F5", "product": "nginx", "match_names": ["nginx"],
                       "versions": [{"introduced": "1.20.0", "fixed": "1.25.0"}]}],
         "check_keys": ["nginx-cve-2099-0001"]}

CHECK_HIT = json.dumps({
    "template-id": "CVE-2099-0001", "info": {"name": "Test nginx flaw", "tags": ["cve"], "severity": "critical",
                                              "classification": {"cve-id": ["cve-2099-0001"]}},
    "type": "http", "host": "https://api.example.com", "matched-at": "https://api.example.com/", "ip": "192.0.2.20",
}).encode()


@pytest.fixture
def world(db_clean, factory, monkeypatch):
    from app.main import app

    fake = FakeSensors(monkeypatch)
    ta, tb = factory.tenant("Alpha"), factory.tenant("Bravo")
    pa = factory.user(ta.id, role="tenant_admin", password=PW, platform_admin=True, email="root@platform.test")
    aa = factory.user(ta.id, role="security_analyst", password=PW)
    av = factory.user(ta.id, role="viewer", password=PW)
    ba = factory.user(tb.id, role="tenant_admin", password=PW)
    with TestClient(app) as c:
        def login(u):
            r = c.post("/api/v1/auth/login", json={"email": u.email, "password": PW})
            assert r.status_code == 200, r.text
            return {"Authorization": f"Bearer {r.json()['access_token']}"}

        yield {"c": c, "fake": fake, "ta": ta, "tb": tb, "root": login(pa), "analyst": login(aa),
               "viewer": login(av), "bravo": login(ba), "bravo_user": ba}


def _scan(c, h, name="Acme", admin=None):
    admin = admin or h
    org = c.post("/api/v1/organizations", headers=admin, json={"name": name}).json()
    assert c.post("/api/v1/scopes/bulk", headers=admin, json={"organization_id": org["id"],
                                                         "entries": ["example.com"]}).status_code == 201
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=h).json()}
    r = c.post("/api/v1/scans", headers=h, json={"organization_id": org["id"],
                                                "profile_id": profiles["standard-asm"]["id"]})
    assert r.status_code == 201, r.text
    return org


def _approve_check(c, root):
    r = c.put("/api/v1/threat-catalog/checks/nginx-cve-2099-0001", headers=root, json={
        "key": "nginx-cve-2099-0001", "name": "nginx CVE-2099-0001 detection", "template_id": "CVE-2099-0001"})
    assert r.status_code == 200, r.text


def _publish(c, root, slug="nginx-2099", content=None):
    r = c.post("/api/v1/threat-catalog", headers=root, json={"slug": slug, "content": content or NGINX})
    assert r.status_code == 201, r.text
    adv = r.json()
    r = c.post(f"/api/v1/threat-catalog/{adv['id']}/publish", headers=root)
    assert r.status_code == 200, r.text
    return adv["id"]


def _assets(c, h, adv_id, **q):
    r = c.get(f"/api/v1/threats/{adv_id}/assets", headers=h, params={"page_size": 200, **q})
    assert r.status_code == 200, r.text
    return {m["asset"]["value"]: m for m in r.json()["items"]}


# ------------------------------------------------------------------- catalog
def test_catalog_is_platform_admin_only_and_drafts_are_invisible(world):
    c, root, bravo, analyst = world["c"], world["root"], world["bravo"], world["analyst"]
    _approve_check(c, root)
    assert c.post("/api/v1/threat-catalog", headers=bravo, json={"slug": "x-y-z", "content": NGINX}).status_code == 403
    assert c.put("/api/v1/threat-catalog/checks/k-k-k", headers=analyst,
                 json={"key": "k-k-k", "name": "abc", "template_id": "x"}).status_code == 403
    adv = c.post("/api/v1/threat-catalog", headers=root, json={"slug": "draft-only", "content": NGINX}).json()
    # Not published: tenants cannot see or guess it.
    assert c.get(f"/api/v1/threats/{adv['id']}", headers=bravo).status_code == 404
    assert all(i["id"] != adv["id"] for i in c.get("/api/v1/threats", headers=bravo).json()["items"])
    # A check key that is not approved cannot be referenced.
    bad = {**NGINX, "check_keys": ["not-approved"]}
    r = c.put(f"/api/v1/threat-catalog/{adv['id']}/draft", headers=root, json=bad)
    assert r.status_code == 422 and "approved" in r.json()["error"]["message"]
    # Publishing freezes a version; editing afterwards creates a new draft, the published one stays.
    c.post(f"/api/v1/threat-catalog/{adv['id']}/publish", headers=root)
    c.put(f"/api/v1/threat-catalog/{adv['id']}/draft", headers=root, json={**NGINX, "title": "Edited title"})
    item = c.get(f"/api/v1/threat-catalog/{adv['id']}", headers=root).json()
    assert item["published_version"] == 1 and item["draft_version"] == 2 and item["title"] == NGINX["title"]
    assert c.get(f"/api/v1/threats/{adv['id']}", headers=bravo).json()["title"] == NGINX["title"]
    c.post(f"/api/v1/threat-catalog/{adv['id']}/publish", headers=root)
    assert c.get(f"/api/v1/threats/{adv['id']}", headers=bravo).json()["title"] == "Edited title"
    # Archive hides it from the default list but keeps it readable.
    c.post(f"/api/v1/threat-catalog/{adv['id']}/archive", headers=root)
    assert all(i["id"] != adv["id"] for i in c.get("/api/v1/threats", headers=bravo).json()["items"])
    assert c.get("/api/v1/threats", headers=bravo, params={"status": "archived"}).json()["total"] == 1


def test_tenant_sessions_cannot_write_or_read_drafts_of_the_catalog(world, tenant_db):
    """RLS on the global tables, below the API."""
    from app.models import ThreatAdvisory

    c, root = world["c"], world["root"]
    adv = c.post("/api/v1/threat-catalog", headers=root, json={"slug": "rls-check", "content": {
        **NGINX, "check_keys": []}}).json()
    with tenant_db(world["tb"].id) as db:
        assert db.get(ThreatAdvisory, uuid.UUID(adv["id"])) is None
        assert db.execute(text("SELECT count(*) FROM threat_advisory_versions")).scalar() == 0
        with pytest.raises(Exception, match="row-level security"):
            db.execute(text("INSERT INTO threat_checks (id, key, name, kind, template_id, enabled, created_at, "
                            "updated_at) VALUES (gen_random_uuid(), 'evil-check', 'x', 'detection_template', 'x', "
                            "true, now(), now())"))
        db.rollback()


# ---------------------------------------------------------------- evaluation
def test_inventory_match_is_potential_never_confirmed_and_is_deduplicated(world, system_db):
    from app.models import AssetEvent, ThreatMatch

    c, root, analyst = world["c"], world["root"], world["analyst"]
    _approve_check(c, root)
    _scan(c, analyst, admin=root)
    adv_id = _publish(c, root)
    rows = _assets(c, analyst, adv_id)
    ep = rows["https://api.example.com"]
    assert ep["assessment"] == "potentially_affected" and ep["basis"] == "product"
    obs = ep["evidence"]["observations"][0]
    assert obs["version"] == "1.24.0" and "inside the affected range" in obs["reason"]
    assert all(m["assessment"] != "confirmed" for m in rows.values())
    detail = c.get(f"/api/v1/threats/{adv_id}", headers=analyst).json()
    assert detail["counts"]["affected"] >= 1 and detail["counts"]["confirmed"] == 0
    assert detail["last_evaluated_at"] and not detail["stale"] and detail["check"]["key"] == "nginx-cve-2099-0001"

    def counts():
        return (system_db.scalar(select(func.count()).select_from(ThreatMatch)),
                system_db.scalar(select(func.count()).select_from(AssetEvent).where(
                    AssetEvent.event_type == "threat_advisory_matched")))

    before = counts()
    assert before[1] == 1  # one notification for the organization, not one per asset
    # Evaluating again — directly, via the daily sweep and via another scan — changes nothing.
    c.post("/api/v1/threat-catalog/evaluate", headers=root)
    c.post(f"/api/v1/threat-catalog/{adv_id}/publish", headers=root)  # no draft: refused, nothing re-emitted
    org = c.get("/api/v1/organizations", headers=analyst).json()
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=analyst).json()}
    c.post("/api/v1/scans", headers=analyst, json={"organization_id": org[0]["id"],
                                                   "profile_id": profiles["standard-asm"]["id"]})
    system_db.expire_all()
    assert counts() == before


def test_versions_outside_or_missing_and_verified_findings(world):
    c, root, analyst = world["c"], world["root"], world["analyst"]
    _scan(c, analyst, admin=root)
    fixed = _publish(c, root, "nginx-old", {**NGINX, "check_keys": [], "title": "Old nginx flaw", "affected": [
        {"product": "nginx", "match_names": ["nginx"], "versions": [{"fixed": "1.22.0"}]}]})
    unknown = _publish(c, root, "ubuntu-x", {**NGINX, "check_keys": [], "cves": [], "title": "Ubuntu thing",
                                             "affected": [{"product": "Ubuntu", "match_names": ["ubuntu"],
                                                           "versions": [{"fixed": "24.04"}]}]})
    # The fixture's detection finding is a verified CVE-2018-13379 on the VPN endpoint.
    fortios = _publish(c, root, "fortios", {**NGINX, "check_keys": [], "title": "FortiOS traversal",
                                            "cves": ["CVE-2018-13379"], "affected": []})
    assert _assets(c, analyst, fixed)["https://api.example.com"]["assessment"] == "not_affected_version"
    assert c.get(f"/api/v1/threats/{fixed}", headers=analyst).json()["counts"]["affected"] == 0
    assert _assets(c, analyst, unknown)["https://api.example.com"]["assessment"] == "version_unknown"
    vpn = _assets(c, analyst, fortios)["https://vpn.example.com:10443"]
    assert vpn["assessment"] == "confirmed" and vpn["basis"] == "finding"
    assert vpn["findings"] and not vpn["findings"][0]["unverified"]


def test_third_party_reports_stay_unverified(world, tenant_db):
    """An exposure-intelligence CVE report (Shodan) never becomes a confirmed match."""
    from app.models import Asset, Finding, Organization
    from app.models.enums import AssetType, ScopeStatus

    c, root, analyst, ta = world["c"], world["root"], world["analyst"], world["ta"]
    _scan(c, analyst, admin=root)
    with tenant_db(ta.id) as db:
        org = db.execute(select(Organization)).scalar_one()
        now = datetime.now(UTC)
        svc = Asset(tenant_id=ta.id, organization_id=org.id, asset_type=AssetType.SERVICE,
                    value="192.0.2.20:22/tcp", normalized_value="192.0.2.20:22/tcp", scope_status=ScopeStatus.DERIVED,
                    first_seen=now, last_seen=now, discovered_at=now, sources=["shodan"], source="shodan",
                    meta={"product": "OpenSSH", "version": "8.2p1"}, tags=[], risk_factors=[])
        db.add(svc)
        db.flush()
        db.add(Finding(tenant_id=ta.id, organization_id=org.id, asset_id=svc.id, fingerprint=uuid.uuid4().hex,
                       source="shodan", source_finding_id="shodan:CVE-2098-0002", title="CVE-2098-0002",
                       cve=["CVE-2098-0002"], unverified=True, first_seen=now, last_seen=now, evidence={},
                       references=[], cwe=[], tags=[], risk_factors=[]))
        db.commit()
    by_cve = _publish(c, root, "ssh-cve", {**NGINX, "check_keys": [], "title": "SSH CVE", "cves": ["CVE-2098-0002"],
                                           "affected": []})
    by_product = _publish(c, root, "ssh-prod", {**NGINX, "check_keys": [], "title": "SSH product", "cves": [],
                                                "affected": [{"product": "OpenSSH", "match_names": ["openssh"],
                                                              "versions": [{"fixed": "9.0"}]}]})
    m = _assets(c, analyst, by_cve)["192.0.2.20:22/tcp"]
    assert m["assessment"] == "reported_unverified" and m["basis"] == "third_party"
    assert m["findings"][0]["unverified"] is True
    p = _assets(c, analyst, by_product)["192.0.2.20:22/tcp"]
    assert p["assessment"] == "reported_unverified" and p["evidence"]["third_party_only"] is True
    detail = c.get(f"/api/v1/threats/{by_cve}", headers=analyst).json()
    assert detail["counts"]["confirmed"] == 0 and detail["counts"]["reported_unverified"] == 1


# -------------------------------------------------------------------- checks
def test_check_runs_through_the_pipeline_and_is_deduplicated(world, system_db):
    from app.models import Scan, ThreatCheckRun

    c, root, analyst, viewer, fake = world["c"], world["root"], world["analyst"], world["viewer"], world["fake"]
    _approve_check(c, root)
    _scan(c, analyst, admin=root)
    adv_id = _publish(c, root)
    ep = _assets(c, analyst, adv_id)["https://api.example.com"]
    assert c.post(f"/api/v1/threats/{adv_id}/checks", headers=viewer, json={"match_ids": [ep["id"]]}).status_code == 403

    fake.set("nuclei", CHECK_HIT)
    fake.calls.clear()
    r = c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    assert r.status_code == 201, r.text
    run = r.json()[0]
    # One detection job, limited to the selected endpoint and to the approved detection only.
    assert fake.calls["nuclei"] == [["https://api.example.com"]]
    scan = system_db.get(Scan, uuid.UUID(run["scan_id"]))
    assert scan.profile_snapshot["slug"] == "threat-check"
    assert scan.stages[0].config["template_ids"] == ["cve-2099-0001"]
    after = _assets(c, analyst, adv_id)["https://api.example.com"]
    assert after["check_outcome"] == "detected" and after["assessment"] == "confirmed"
    assert any(f["title"] == "Test nginx flaw" for f in after["findings"])
    runs = c.get(f"/api/v1/threats/{adv_id}/checks", headers=analyst).json()
    assert runs[0]["status"] == "completed" and runs[0]["summary"]["detected"] == 1
    # The internal profile is not offered and cannot be started directly.
    profiles = c.get("/api/v1/scan-profiles", headers=analyst).json()
    assert "threat-check" not in {p["slug"] for p in profiles}
    assert c.post("/api/v1/scans", headers=analyst, json={"organization_id": run["organization_id"],
                                                         "profile_id": str(scan.profile_id)}).status_code == 404


def test_a_second_click_while_a_check_is_active_starts_nothing(world, system_db, monkeypatch):
    from app.models import Scan
    from app.workers import dispatch

    c, root, analyst = world["c"], world["root"], world["analyst"]
    _approve_check(c, root)
    _scan(c, analyst, admin=root)
    adv_id = _publish(c, root)
    ep = _assets(c, analyst, adv_id)["https://api.example.com"]
    monkeypatch.setattr(dispatch, "start_scan", lambda *a: None)  # leave the first one queued
    n = system_db.scalar(select(func.count()).select_from(Scan))
    first = c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    assert first.status_code == 201
    second = c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    assert second.status_code == 409 and second.json()["error"]["details"]["check_run_id"] == first.json()[0]["id"]
    system_db.expire_all()
    assert system_db.scalar(select(func.count()).select_from(Scan)) == n + 1
    assert _assets(c, analyst, adv_id)["https://api.example.com"]["assessment"] == "check_pending"


def test_completed_check_without_detection_is_not_proof(world):
    c, root, analyst, fake = world["c"], world["root"], world["analyst"], world["fake"]
    _approve_check(c, root)
    _scan(c, analyst, admin=root)
    adv_id = _publish(c, root)
    ep = _assets(c, analyst, adv_id)["https://api.example.com"]
    fake.set("nuclei", b"")
    c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    m = _assets(c, analyst, adv_id)["https://api.example.com"]
    assert m["check_outcome"] == "not_detected" and m["assessment"] == "not_detected"
    assert "not proof" in m["check_detail"] and m["remediation_status"] == "open"
    counts = c.get(f"/api/v1/threats/{adv_id}", headers=analyst).json()["counts"]
    # Still counted as possibly affected; nothing was marked remediated by the check.
    assert counts["not_detected"] == 1 and counts["affected"] >= 1 and counts["remediated"] == 0


@pytest.mark.parametrize("mode", ["crash", "timeout"])
def test_failed_or_incomplete_check_is_inconclusive_and_closes_nothing(world, monkeypatch, system_db, mode):
    from asm_sensors.adapters.nuclei import NucleiAdapter
    from asm_sensors.base import RawOutput
    from asm_sensors.execution import ProcessResult

    from app.models import Finding
    from app.models.enums import FindingStatus

    c, root, analyst, fake = world["c"], world["root"], world["analyst"], world["fake"]
    _approve_check(c, root)
    _scan(c, analyst, admin=root)
    adv_id = _publish(c, root)
    ep = _assets(c, analyst, adv_id)["https://api.example.com"]
    fake.set("nuclei", CHECK_HIT)  # a first, successful check leaves an open finding behind
    c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    finding = system_db.execute(select(Finding).where(Finding.source_finding_id == "CVE-2099-0001")).scalar_one()
    assert finding.status == FindingStatus.NEW

    async def broken(self, targets, config, ctx):  # noqa: ANN001
        if mode == "crash":
            raise RuntimeError("engine exploded")
        return RawOutput(process=ProcessResult(argv=["x"], returncode=None, stdout=b"", stderr=b"", duration=1,
                                               timed_out=True), files={"n.jsonl": b""})

    monkeypatch.setattr(NucleiAdapter, "execute", broken)
    r = c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    assert r.status_code == 201, r.text
    runs = c.get(f"/api/v1/threats/{adv_id}/checks", headers=analyst).json()
    assert runs[0]["status"] == "inconclusive" and runs[0]["summary"]["inconclusive"] == 1
    m = _assets(c, analyst, adv_id)["https://api.example.com"]
    assert m["check_outcome"] == "inconclusive"
    # Still confirmed by the earlier verified finding, which the broken run did not close.
    assert m["assessment"] == "confirmed"
    system_db.expire_all()
    assert system_db.get(Finding, finding.id).status == FindingStatus.NEW


def test_check_blocked_by_scope_is_refused_by_the_normal_pipeline(world):
    c, root, analyst = world["c"], world["root"], world["analyst"]
    _approve_check(c, root)
    org = _scan(c, analyst, admin=root)
    adv_id = _publish(c, root)
    ep = _assets(c, analyst, adv_id)["https://api.example.com"]
    # Withdraw active-scanning authorization from the organization's scope.
    for entry in c.get("/api/v1/scopes", headers=world["root"], params={"organization_id": org["id"]}).json():
        c.patch(f"/api/v1/scopes/{entry['id']}", headers=world["root"], json={"allow_active_scanning": False})
    r = c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst, json={"match_ids": [ep["id"]]})
    assert r.status_code == 422 and "active scanning" in r.json()["error"]["message"]
    assert _assets(c, analyst, adv_id)["https://api.example.com"]["check_outcome"] == "none"


# ---------------------------------------------------------------- remediation
def test_remediation_is_separate_from_assessment(world):
    c, root, analyst, viewer = world["c"], world["root"], world["analyst"], world["viewer"]
    _scan(c, analyst, admin=root)
    adv_id = _publish(c, root, content={**NGINX, "check_keys": []})
    ep = _assets(c, analyst, adv_id)["https://api.example.com"]
    assert c.patch(f"/api/v1/threats/matches/{ep['id']}", headers=viewer,
                   json={"remediation_status": "resolved"}).status_code == 403
    r = c.patch(f"/api/v1/threats/matches/{ep['id']}", headers=analyst,
                json={"remediation_status": "resolved", "remediation_note": "patched to 1.26"})
    assert r.status_code == 200 and r.json()["assessment"] == "potentially_affected"
    assert c.get(f"/api/v1/threats/{adv_id}", headers=analyst).json()["counts"]["remediated"] == 1
    bravo_user = world["bravo_user"]
    assert c.patch(f"/api/v1/threats/matches/{ep['id']}", headers=analyst,
                   json={"assigned_to": str(bravo_user.id)}).status_code == 422


# ------------------------------------------------------------------ isolation
def test_two_tenants_with_the_same_asset_names_never_see_each_other(world, system_db):
    from app.models import ThreatMatch

    c, root, analyst, bravo, fake = world["c"], world["root"], world["analyst"], world["bravo"], world["fake"]
    _approve_check(c, root)
    _scan(c, analyst, "Alpha Org", admin=root)
    _scan(c, bravo, "Bravo Org")  # same example.com inventory, other tenant
    adv_id = _publish(c, root)
    a_rows, b_rows = _assets(c, analyst, adv_id), _assets(c, bravo, adv_id)
    assert set(a_rows) == set(b_rows) and "https://api.example.com" in a_rows
    a_ids, b_ids = {m["id"] for m in a_rows.values()}, {m["id"] for m in b_rows.values()}
    assert not a_ids & b_ids
    b_ep = b_rows["https://api.example.com"]
    # Guessing the other tenant's record ids fails as "not found".
    assert c.patch(f"/api/v1/threats/matches/{b_ep['id']}", headers=analyst,
                   json={"remediation_status": "resolved"}).status_code == 404
    assert c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst,
                  json={"match_ids": [b_ep["id"]]}).status_code == 404
    # Counts, check runs and exports are per tenant.
    c.patch(f"/api/v1/threats/matches/{a_rows['https://api.example.com']['id']}", headers=analyst,
            json={"remediation_status": "resolved"})
    fake.set("nuclei", b"")
    c.post(f"/api/v1/threats/{adv_id}/checks", headers=analyst,
           json={"match_ids": [a_rows["https://api.example.com"]["id"]]})
    assert c.get(f"/api/v1/threats/{adv_id}", headers=analyst).json()["counts"]["remediated"] == 1
    b_detail = c.get(f"/api/v1/threats/{adv_id}", headers=bravo).json()
    assert b_detail["counts"]["remediated"] == 0 and b_detail["check_runs"] == []
    assert c.get(f"/api/v1/threats/{adv_id}/checks", headers=bravo).json() == []
    export = c.get(f"/api/v1/threats/{adv_id}/assets/export.csv", headers=bravo).text
    assert "resolved" not in export and export.count("\n") == len(b_rows) + 1
    assert system_db.scalar(select(func.count()).select_from(ThreatMatch)) == len(a_rows) + len(b_rows)
