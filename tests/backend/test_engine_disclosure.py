"""The interface describes capabilities; it never discloses which engines implement them.

Anything a browser receives is inspectable, so engine names must not appear in API
responses or in the text shown to users — including error messages.
"""

from __future__ import annotations

import json

import pytest
from asm_sensors.registry import adapter_names
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import new_session
from app.models import Scan, ScanProfile
from app.scans import engines, messages, orchestrator

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"
# Names that must never reach the interface (engines and the projects behind them).
FORBIDDEN = sorted(set(adapter_names()) | {"nuclei", "subfinder", "amass", "dnsx", "httpx", "naabu", "zap",
                                           "zaproxy", "spiderfoot", "bbot", "shodan", "projectdiscovery", "owasp"})


def leaks(payload: object) -> list[str]:
    text = json.dumps(payload, default=str).lower()
    return [name for name in FORBIDDEN if name in text]


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def signed_in(client, factory, monkeypatch):
    FakeSensors(monkeypatch)
    tenant = factory.tenant()
    user = factory.user(tenant.id)
    org = factory.org(tenant.id, domains=("example.com",))
    r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
    return client, tenant, org, {"Authorization": f"Bearer {r.json()['access_token']}"}


def _run_scan(tenant_id, org_id, slug="standard-asm"):
    with new_session(tenant_id) as db:
        pid = db.scalar(select(ScanProfile.id).where(ScanProfile.slug == slug, ScanProfile.tenant_id.is_(None)))
        scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=pid)
        db.commit()
        return orchestrator.run_inline(db, scan.id).id


class TestApiResponses:
    def test_scan_detail_names_capabilities_not_engines(self, signed_in):
        client, tenant, org, h = signed_in
        scan_id = _run_scan(tenant.id, org.id)
        body = client.get(f"/api/v1/scans/{scan_id}", headers=h).json()
        assert leaks(body) == []
        stages = body["stages"]
        assert stages and all("engine" not in s for s in stages)
        assert all(s["label"] for s in stages)
        # Two engines doing the same kind of work must not look like one stage twice.
        enrichment = [s["label"] for s in stages if s["stage_type"] == "ip_enrichment"]
        assert len(enrichment) == len(set(enrichment)) > 1

    def test_profiles_and_capabilities_use_opaque_tokens(self, signed_in):
        client, tenant, org, h = signed_in
        profiles = client.get("/api/v1/scan-profiles", headers=h).json()
        assert leaks(profiles) == []
        tokens = {s["engine"] for p in profiles for s in p["stages"]}
        assert tokens and all(t.startswith("eng_") for t in tokens)
        capabilities = client.get("/api/v1/scan-profiles/engines", headers=h).json()
        # credential_providers names third-party services the customer buys keys for
        # (Shodan, and the web login slot) — those are theirs to see; the rest is not.
        assert leaks([{k: v for k, v in c.items() if k != "credential_providers"} for c in capabilities]) == []
        assert all(c["id"].startswith("eng_") and c["display_name"] for c in capabilities)
        assert all("Config" not in json.dumps(c["config_schema"]) for c in capabilities)

    def test_a_profile_can_be_saved_with_the_token_it_was_given(self, signed_in):
        client, tenant, org, h = signed_in
        profiles = client.get("/api/v1/scan-profiles", headers=h).json()
        source = next(p for p in profiles if p["slug"] == "standard-asm")
        created = client.post("/api/v1/scan-profiles", headers=h, json={
            "name": "Round trip", "stages": [{"stage": s["stage"], "engine": s["engine"], "config": s["config"],
                                              "enabled": s["enabled"], "optional": s["optional"]}
                                             for s in source["stages"]]})
        assert created.status_code == 201, created.text
        assert leaks(created.json()) == []
        assert [s["label"] for s in created.json()["stages"]] == [s["label"] for s in source["stages"]]

    def test_findings_and_assets_say_what_found_it_not_with_what(self, signed_in):
        client, tenant, org, h = signed_in
        _run_scan(tenant.id, org.id)
        findings = client.get("/api/v1/findings", headers=h, params={"page_size": 200}).json()
        assert leaks(findings) == []
        assert findings["items"] and all(f["source_label"] for f in findings["items"])
        detail = client.get(f"/api/v1/findings/{findings['items'][0]['id']}", headers=h).json()
        assert leaks(detail) == []
        assets = client.get("/api/v1/assets", headers=h, params={"page_size": 200}).json()
        assert leaks(assets) == []
        asset_id = assets["items"][0]["id"]
        assert leaks(client.get(f"/api/v1/assets/{asset_id}", headers=h).json()) == []
        assert leaks(client.get(f"/api/v1/assets/{asset_id}/observations", headers=h).json()) == []

    def test_a_failing_stage_explains_itself_without_naming_the_engine(self, signed_in, monkeypatch):
        client, tenant, org, h = signed_in

        async def broken(self, targets, config, ctx):
            from asm_sensors.base import RawOutput
            from asm_sensors.execution import ProcessResult
            return RawOutput(process=ProcessResult(argv=["nuclei"], returncode=1, stdout=b"",
                                                   stderr=b"[FTL] Could not run nuclei: no templates provided for scan",
                                                   duration=0.1))

        from asm_sensors.registry import get_adapter

        monkeypatch.setattr(type(get_adapter("nuclei")), "execute", broken)
        scan_id = _run_scan(tenant.id, org.id)
        body = client.get(f"/api/v1/scans/{scan_id}", headers=h).json()
        failed = [s for s in body["stages"] if s["error"]]
        assert failed, "expected the broken stage to report an error"
        assert leaks(body) == []
        assert any("Detection content is not installed" in s["error"] for s in failed)
        with new_session(tenant.id) as db:  # and the scan-level summary is clean too
            assert not leaks(db.get(Scan, scan_id).error or "")


class TestFriendlyMessages:
    @pytest.mark.parametrize(("raw", "expected"), [
        ("nuclei exit code 1: [FTL] Could not run nuclei: no templates provided for scan",
         "Detection content is not installed"),
        ("BinaryNotFound: dnsx is not installed in this sensor worker", "not installed in the scanner"),
        ("ConfigurationError: The web application scanner is not enabled in this deployment",
         "web application scanner is not enabled"),
        ("ConfigurationError: Open-source intelligence enrichment is not enabled in this deployment",
         "Open-source intelligence enrichment is not enabled"),
        ("ZAP integration is not enabled in this deployment (zap_url unset)", "web application scanner is not enabled"),
        ("crt.sh query for ifmi.sa failed: HTTPStatusError", "did not answer"),
        ("shodan: the API key was rejected (HTTP 401/403)", "was rejected"),
        ("zap_active: active scan of https://x did not finish before its deadline", "ran out of time"),
    ])
    def test_known_failures_become_advice(self, raw, expected):
        out = messages.friendly([raw], "Vulnerability detection")
        assert expected in out and not leaks(out)

    def test_an_unknown_failure_names_the_capability_only(self):
        out = messages.friendly(["Traceback: some.internal.Thing exploded in nuclei"], "Web service fingerprinting")
        assert "Web service fingerprinting" in out and not leaks(out)

    def test_repeated_failures_are_said_once(self):
        out = messages.friendly(["crt.sh query for a failed: HTTPStatusError",
                                 "crt.sh query for b failed: HTTPStatusError"])
        assert out.count("did not answer") == 1

    def test_nothing_to_say(self):
        assert messages.friendly([]) is None and messages.friendly(None) is None


class TestTokens:
    def test_tokens_are_stable_reversible_and_opaque(self):
        token = engines.token_for("nuclei")
        assert token.startswith("eng_") and "nuclei" not in token
        assert engines.token_for("nuclei") == token
        assert engines.engine_for(token) == "nuclei"
        assert engines.engine_for("nuclei") == "nuclei"  # plain names still accepted (CLI, scripts)
        assert engines.token_for("zap_active") != token

    def test_labels_describe_the_capability(self):
        assert engines.label_for("asnlookup") != engines.label_for("shodan")
        assert not leaks(engines.label_for("nuclei"))
        assert engines.accepts_login("zap_active") and not engines.accepts_login("dnsx")
