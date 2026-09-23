"""A sign-in cookie/token supplied when starting a scan (authenticated DAST)."""

from __future__ import annotations

import pytest
from asm_sensors.jobs import unseal_credentials
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core import crypto
from app.core.errors import ValidationFailed
from app.db.session import new_session
from app.models import Scan, ScanProfile
from app.models.enums import ScanStatus
from app.scans import orchestrator

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"
COOKIE = "PHPSESSID=abc123; security=low"


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


def _profile(db, slug):
    return db.scalar(select(ScanProfile.id).where(ScanProfile.slug == slug, ScanProfile.tenant_id.is_(None)))


def _start(db, tenant_id, org_id, slug="web-app-scan", **kw):
    return orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id,
                                    profile_id=_profile(db, slug), **kw)


def _record_jobs(monkeypatch) -> dict[str, dict]:
    """Run the real inline pipeline, capturing what each engine was handed."""
    import asm_sensors.runner as runner

    handed: dict[str, dict] = {}
    original = runner.execute_job

    async def capture(job, settings=None, transport_key=None, coordinator=None):
        handed[job.adapter] = {
            "config": job.config,
            "credentials": (unseal_credentials(job.sealed_credentials, job.job_id, transport_key)
                            if job.sealed_credentials else {}),
        }
        return await original(job, settings=settings, transport_key=transport_key, coordinator=coordinator)

    monkeypatch.setattr(runner, "execute_job", capture)
    return handed


def test_the_cookie_reaches_only_the_web_application_scanner(factory, monkeypatch):
    FakeSensors(monkeypatch)
    handed = _record_jobs(monkeypatch)
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    with new_session(tenant.id) as db:
        scan = _start(db, tenant.id, org.id, auth_secret=COOKIE, auth_header_name="Cookie")
        db.commit()
        assert scan.auth_secret_encrypted and COOKIE not in scan.auth_secret_encrypted  # encrypted at rest
        orchestrator.run_inline(db, scan.id)

    # The crawler and the active web scanner get it; nothing else does.
    assert handed["zap_spider"]["credentials"]["zap_auth"] == [COOKIE]
    assert handed["zap_active"]["credentials"]["zap_auth"] == [COOKIE]
    assert handed["zap_spider"]["config"]["auth_header_name"] == "Cookie"
    others = {e: h for e, h in handed.items() if not e.startswith("zap")}
    assert others and all("zap_auth" not in h["credentials"] for h in others.values())


def test_the_chosen_header_is_used(factory, monkeypatch):
    FakeSensors(monkeypatch)
    handed = _record_jobs(monkeypatch)
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    with new_session(tenant.id) as db:
        scan = _start(db, tenant.id, org.id, auth_secret="Bearer token-value", auth_header_name="Authorization")
        db.commit()
        orchestrator.run_inline(db, scan.id)
    assert handed["zap_active"]["config"]["auth_header_name"] == "Authorization"
    assert handed["zap_active"]["credentials"]["zap_auth"] == ["Bearer token-value"]


def test_it_is_erased_when_the_scan_ends(factory, monkeypatch):
    FakeSensors(monkeypatch)
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    with new_session(tenant.id) as db:
        scan = _start(db, tenant.id, org.id, auth_secret=COOKIE)
        db.commit()
        scan_id = scan.id
        orchestrator.run_inline(db, scan_id)
    with new_session(tenant.id) as db:
        done = db.get(Scan, scan_id)
        assert done.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED)
        assert done.auth_secret_encrypted is None  # not kept after the scan
        assert done.authenticated is True  # but we still know the scan was authenticated


def test_cancelling_also_erases_it(factory, monkeypatch):
    FakeSensors(monkeypatch)
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    with new_session(tenant.id) as db:
        scan = _start(db, tenant.id, org.id, auth_secret=COOKIE)
        db.commit()
        orchestrator.cancel_scan(db, scan.id)
        db.commit()
        assert db.get(Scan, scan.id).auth_secret_encrypted is None


def test_refused_when_the_profile_cannot_use_it(factory):
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    with new_session(tenant.id) as db:
        with pytest.raises(ValidationFailed, match="web application scanning stage"):
            _start(db, tenant.id, org.id, slug="passive-discovery", auth_secret=COOKIE)


class TestApi:
    def test_start_a_scan_with_a_cookie(self, client, factory, monkeypatch):
        FakeSensors(monkeypatch)
        tenant = factory.tenant()
        user = factory.user(tenant.id)
        org = factory.org(tenant.id, domains=("example.com",))
        r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        profiles = client.get("/api/v1/scan-profiles", headers=h).json()
        web = next(p for p in profiles if p["slug"] == "web-app-scan")

        created = client.post("/api/v1/scans", headers=h, json={
            "organization_id": str(org.id), "profile_id": web["id"], "auth_secret": COOKIE})
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["authenticated"] is True
        assert COOKIE not in created.text  # never echoed back
        detail = client.get(f"/api/v1/scans/{body['id']}", headers=h)
        assert COOKIE not in detail.text and detail.json()["authenticated"] is True

    def test_a_header_injection_attempt_is_rejected(self, client, factory):
        tenant = factory.tenant()
        user = factory.user(tenant.id)
        org = factory.org(tenant.id, domains=("example.com",))
        r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
        h = {"Authorization": f"Bearer {r.json()['access_token']}"}
        profiles = client.get("/api/v1/scan-profiles", headers=h).json()
        web = next(p for p in profiles if p["slug"] == "web-app-scan")
        bad = client.post("/api/v1/scans", headers=h, json={
            "organization_id": str(org.id), "profile_id": web["id"],
            "auth_secret": "a=b\r\nX-Injected: 1"})
        assert bad.status_code == 422
