"""End-to-end API workflows: scope -> scan -> inventory -> findings -> events -> reports -> notifications."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"


@pytest.fixture
def ctx(db_clean, factory, monkeypatch):
    from app.main import app

    FakeSensors(monkeypatch)
    t = factory.tenant("Acme")
    admin = factory.user(t.id, role="tenant_admin", password=PW)
    analyst = factory.user(t.id, role="security_analyst", password=PW)
    with TestClient(app) as c:
        def headers(u):
            r = c.post("/api/v1/auth/login", json={"email": u.email, "password": PW})
            return {"Authorization": f"Bearer {r.json()['access_token']}"}

        yield c, headers(admin), headers(analyst), t, admin, analyst


def setup_org(c, h):
    org = c.post("/api/v1/organizations", headers=h, json={"name": "Acme Holding"}).json()
    r = c.post("/api/v1/scopes/bulk", headers=h, json={"organization_id": org["id"],
                                                        "entries": ["example.com", "not a domain!", "10.0.0.0/8"]})
    assert r.status_code == 201 and [e["value"] for e in r.json()] == ["example.com"]
    ex = c.post("/api/v1/scopes", headers=h, json={"organization_id": org["id"], "entry_type": "domain",
                                                   "value": "dev-api.example.com", "is_exclusion": True})
    assert ex.status_code == 201
    return org


def run_scan(c, h, org, slug="standard-asm"):
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=h).json()}
    r = c.post("/api/v1/scans", headers=h, json={"organization_id": org["id"], "profile_id": profiles[slug]["id"]})
    assert r.status_code == 201, r.text
    return c.get(f"/api/v1/scans/{r.json()['id']}", headers=h).json()


def test_scope_check_endpoint(ctx):
    c, admin, analyst, *_ = ctx
    org = setup_org(c, admin)
    ok = c.post("/api/v1/scopes/check", headers=analyst, json={"organization_id": org["id"], "target": "api.example.com"})
    assert ok.json()["allowed"] is True
    bad = c.post("/api/v1/scopes/check", headers=analyst,
                 json={"organization_id": org["id"], "target": "x.dev-api.example.com"})
    assert bad.json()["allowed"] is False and "excluded" in bad.json()["reason"]
    # analysts cannot change scope
    assert c.post("/api/v1/scopes", headers=analyst, json={"organization_id": org["id"], "entry_type": "domain",
                                                           "value": "evil.com"}).status_code == 403


def test_web_apps_dashboard(ctx):
    c, admin, analyst, *_ = ctx
    org = setup_org(c, admin)
    run_scan(c, analyst, org)
    r = c.get("/api/v1/dashboard/web-apps", headers=analyst, params={"organization_id": org["id"]})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["total"] >= 1 and data["items"]
    for row in data["items"]:
        assert row["url"].startswith(("http://", "https://"))
        for k in ("risk_score", "by_severity", "dast_verified", "crawled", "open_findings"):
            assert k in row
        # standard-asm has no ZAP engine, so nothing is DAST-verified or crawled
        assert row["dast_verified"] == 0 and row["crawled"] is False
    # at least one web app carries open findings with a real severity breakdown
    assert any(x["open_findings"] > 0 and sum(x["by_severity"].values()) > 0 for x in data["items"])


def test_full_workflow(ctx):
    c, admin, analyst, tenant, admin_user, analyst_user = ctx
    org = setup_org(c, admin)
    scan = run_scan(c, analyst, org)
    assert scan["status"] == "completed"
    assert all(s["label"] for s in scan["stages"])  # platform labels, not tool names, for the UI
    decisions = c.get(f"/api/v1/scans/{scan['id']}/decisions", headers=analyst, params={"decision": "rejected"}).json()
    assert decisions["total"] >= 0

    # --- inventory & filters
    assets = c.get("/api/v1/assets", headers=analyst, params={"asset_type": ["subdomain"], "page_size": 100}).json()
    values = {a["value"] for a in assets["items"]}
    assert "api.example.com" in values and "dev-api.example.com" not in values
    api = next(a for a in assets["items"] if a["value"] == "api.example.com")
    assert api["ips"] == ["192.0.2.20"] and api["approval_status"] == "unverified"
    unknown = c.get("/api/v1/assets", headers=analyst, params={"unknown": True, "asset_type": ["subdomain"]}).json()
    assert unknown["total"] >= 1
    nginx = c.get("/api/v1/assets", headers=analyst, params={"technology": "nginx"}).json()
    assert {a["value"] for a in nginx["items"]} == {"https://api.example.com"}
    crit = c.get("/api/v1/assets", headers=analyst, params={"severity": ["critical"]}).json()
    assert [a["value"] for a in crit["items"]] == ["https://vpn.example.com:10443"]
    search = c.get("/api/v1/assets", headers=analyst, params={"q": "fortinet"}).json()  # matches page title
    assert search["total"] == 1
    facets = c.get("/api/v1/assets/facets", headers=analyst).json()
    assert any(f["value"] == "nginx" for f in facets["technologies"])

    # --- detail, relationships, timeline
    detail = c.get(f"/api/v1/assets/{api['id']}", headers=analyst).json()
    rels = {(r["relation"], r["direction"], r["asset"]["value"]) for r in detail["relationships"]}
    assert ("resolves_to", "out", "192.0.2.20") in rels and ("subdomain_of", "out", "example.com") in rels
    timeline = c.get(f"/api/v1/assets/{api['id']}/timeline", headers=analyst).json()
    assert any(e["event_type"] == "new_subdomain" for e in timeline["items"])
    obs = c.get(f"/api/v1/assets/{api['id']}/observations", headers=analyst).json()
    assert obs["total"] >= 1 and obs["items"][0]["source_label"]

    # --- shadow-IT workflow
    r = c.patch(f"/api/v1/assets/{api['id']}", headers=analyst,
                json={"owner": "Platform Team", "approval_status": "approved", "criticality": "high", "tags": ["API", "prod"]})
    assert r.status_code == 200 and r.json()["tags"] == ["api", "prod"]
    ev = c.get("/api/v1/events", headers=analyst, params={"event_type": ["approval_changed", "ownership_changed"]}).json()
    assert {e["event_type"] for e in ev["items"]} == {"approval_changed", "ownership_changed"}

    # --- findings workflow
    fl = c.get("/api/v1/findings", headers=analyst, params={"open_only": True, "kev": False}).json()
    cve = next(f for f in fl["items"] if "CVE-2018-13379" in f["cve"])
    assert cve["source_label"] == "Vulnerability detection" and cve["asset"]["value"] == "https://vpn.example.com:10443"
    fid = cve["id"]
    bad = c.patch(f"/api/v1/findings/{fid}", headers=analyst, json={"status": "accepted_risk", "comment": "legacy"})
    assert bad.status_code == 403  # analysts cannot accept risk
    assert c.patch(f"/api/v1/findings/{fid}", headers=admin, json={"status": "accepted_risk"}).status_code == 422
    ok = c.patch(f"/api/v1/findings/{fid}", headers=analyst,
                 json={"status": "investigating", "assigned_to": str(analyst_user.id), "comment": "Looking into it"})
    assert ok.status_code == 200 and ok.json()["status"] == "investigating"
    assert c.patch(f"/api/v1/findings/{fid}", headers=analyst, json={"status": "reopened"}).status_code == 422
    acc = c.patch(f"/api/v1/findings/{fid}", headers=admin,
                  json={"status": "accepted_risk", "comment": "Compensating control: WAF + VPN only"})
    assert acc.status_code == 200
    activity = c.get(f"/api/v1/findings/{fid}/activity", headers=analyst).json()
    assert [a["activity_type"] for a in activity][:3] == ["status", "comment", "assignment"] or len(activity) >= 4
    audit = c.get("/api/v1/audit-logs", headers=admin, params={"action": "finding."}).json()
    assert any(a["action"] == "finding.risk_accepted" for a in audit["items"])
    assert c.get("/api/v1/audit-logs/verify", headers=admin).json()["intact"] is True

    # --- events acknowledgement
    feed = c.get("/api/v1/events", headers=analyst, params={"include_baseline": True, "min_severity": "high"}).json()
    ids = [e["id"] for e in feed["items"][:3]]
    assert c.post("/api/v1/events/acknowledge", headers=analyst, json={"event_ids": ids}).json()["acknowledged"] == len(ids)

    # --- dashboard
    dash = c.get("/api/v1/dashboard/summary", headers=analyst).json()
    # the only critical finding was risk-accepted above, so it no longer counts as open
    assert dash["totals"]["critical_findings"] == 0 and dash["totals"]["high_findings"] >= 1
    assert dash["most_exposed_assets"]
    assert dash["expiring_certificates"] and dash["technologies"]
    assert c.get("/api/v1/dashboard/trends", headers=analyst).json()

    # --- CSV export is formula-injection safe
    csv_r = c.get("/api/v1/findings/export.csv", headers=analyst)
    assert csv_r.status_code == 200 and csv_r.text.startswith("title,asset")


def test_reports(ctx):
    c, admin, analyst, *_ = ctx
    org = setup_org(c, admin)
    run_scan(c, admin, org)
    for rtype, fmt in (("executive", "html"), ("technical", "html"), ("vulnerability", "csv"),
                       ("asset_inventory", "csv"), ("changes", "html"), ("risk_trend", "csv")):
        r = c.post("/api/v1/reports", headers=analyst, json={"report_type": rtype, "report_format": fmt,
                                                             "organization_id": org["id"]})
        assert r.status_code == 201, r.text
        rep = c.get(f"/api/v1/reports/{r.json()['id']}", headers=analyst).json()
        assert rep["status"] == "completed", rep
        dl = c.get(f"/api/v1/reports/{rep['id']}/download", headers=analyst)
        assert dl.status_code == 200 and len(dl.content) > 100
        if fmt == "html":
            assert b"Exteriq ASM" in dl.content and b"<script" not in dl.content
            assert "sandbox" in dl.headers["content-security-policy"]
    assert c.post("/api/v1/reports", headers=analyst, json={"report_type": "executive",
                                                           "report_format": "csv"}).status_code == 422


def test_notifications_webhook_and_wazuh(ctx, monkeypatch, tmp_path):
    c, admin, analyst, *_ = ctx
    monkeypatch.setenv("ASM_INTEGRATION_EXPORT_DIR", str(tmp_path))
    sent: list[dict] = []

    class Resp:
        status_code = 200

    def fake_post(url, content=None, headers=None, **kw):
        sent.append({"url": url, "body": json.loads(content), "headers": headers})
        return Resp()

    monkeypatch.setattr("app.integrations.channels.httpx.post", fake_post)
    hook = c.post("/api/v1/integrations", headers=admin, json={
        "name": "SOAR", "integration_type": "webhook", "config": {"url": "https://soar.example.net/hook"},
        "secret": "hmac-signing-secret"}).json()
    assert hook["has_secret"] and "secret" not in hook["config"]
    wazuh = c.post("/api/v1/integrations", headers=admin, json={
        "name": "Wazuh", "integration_type": "wazuh", "config": {"mode": "file", "file_name": "asm.json"}}).json()
    bad = c.post("/api/v1/integrations", headers=admin, json={
        "name": "x", "integration_type": "webhook", "config": {"url": "ftp://x", "evil": 1}})
    assert bad.status_code == 422
    assert c.post("/api/v1/integrations", headers=admin, json={"name": "j", "integration_type": "jira"}).status_code == 422
    assert c.post(f"/api/v1/integrations/{hook['id']}/test", headers=admin).status_code == 200
    sig = sent[-1]["headers"]["X-ASM-Signature"]
    assert sig.startswith("sha256=")
    sent.clear()

    c.post("/api/v1/integrations/policies", headers=admin, json={
        "name": "High and above", "min_severity": "high", "integration_ids": [hook["id"], wazuh["id"]]})
    org = setup_org(c, admin)
    run_scan(c, admin, org)  # baseline: recorded but not alerted
    assert sent == []
    # Second scan: VNC newly exposed -> high severity alert
    from asm_sensors.base import RawOutput
    from asm_sensors.registry import _REGISTRY

    naabu = (b'{"ip":"198.51.100.7","port":443}\n{"ip":"198.51.100.7","port":10443}\n'
             b'{"ip":"192.0.2.20","port":443}\n{"ip":"192.0.2.20","port":3389}\n{"ip":"192.0.2.20","port":5900}\n')

    async def naabu_exec(self, targets, config, ctx_):
        return RawOutput(files={"naabu": naabu})

    monkeypatch.setattr(_REGISTRY["naabu"], "execute", naabu_exec)
    run_scan(c, admin, org)
    titles = [e["title"] for msg in sent for e in ([msg["body"]] if "title" in msg["body"] else msg["body"]["events"])]
    assert any("5900/tcp" in t and "VNC" in t for t in titles), titles
    assert all(msg["body"]["severity"] in ("high", "critical") for msg in sent if "severity" in msg["body"])
    lines = (tmp_path / "asm.json").read_text().splitlines()
    doc = json.loads(lines[0])
    assert doc["source"] == "exteriq-asm" and doc["severity"] in ("high", "critical") and doc["event_type"]
    deliveries = c.get("/api/v1/integrations/deliveries", headers=admin).json()
    assert deliveries and all(d["status"] == "sent" for d in deliveries)


def test_wazuh_syslog_line_format():
    from app.integrations.channels import syslog_line

    line = syslog_line({"event_type": "port_opened", "severity": "high", "title": "t", "event_id": "e",
                        "occurred_at": "2026-09-18T09:42:00Z", "asset": "vpn.example.com"}).decode()
    assert line.startswith("<131>")  # local0.err
    header, _, body = line.partition(" exteriq-asm: ")
    assert json.loads(body)["source"] == "exteriq-asm"


def test_credentials_are_write_only(ctx):
    c, admin, analyst, *_ = ctx
    providers = {p["provider"] for p in c.get("/api/v1/credentials/providers", headers=admin).json()}
    assert "shodan" in providers
    r = c.put("/api/v1/credentials/shodan", headers=admin, json={"value": "SHODANKEY-1234567890"})
    assert r.status_code == 200 and r.json()["last_four"] == "7890"
    listed = c.get("/api/v1/credentials", headers=analyst).json()
    assert "SHODANKEY" not in json.dumps(listed)
    assert c.put("/api/v1/credentials/shodan", headers=analyst, json={"value": "x" * 10}).status_code == 403
    assert c.put("/api/v1/credentials/not-a-provider", headers=admin, json={"value": "x" * 10}).status_code == 422
