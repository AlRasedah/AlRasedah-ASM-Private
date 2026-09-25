"""Diagnostics & Support on PostgreSQL with RLS: tenant isolation, platform-only data,
unavailable telemetry, and support bundles (ownership, limits, contents, cleanup).
"""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from .sensors_fake import FakeSensors
from .test_engine_disclosure import FORBIDDEN as _FORBIDDEN

# "screenshot" is a registered adapter name but also the public name of a feature.
FORBIDDEN = [n for n in _FORBIDDEN if n != "screenshot"]

PW = "Sup3r-Secret-Passw0rd!"


@pytest.fixture
def env(db_clean, factory, monkeypatch):
    from app.main import app

    FakeSensors(monkeypatch)
    ta, tb = factory.tenant("Alpha"), factory.tenant("Bravo")
    users = {"alpha": factory.user(ta.id, role="tenant_admin", password=PW),
             "alpha_viewer": factory.user(ta.id, role="viewer", password=PW),
             "bravo": factory.user(tb.id, role="tenant_admin", password=PW),
             "root": factory.user(ta.id, role="tenant_admin", password=PW, platform_admin=True)}
    with TestClient(app) as c:
        heads = {}
        for k, u in users.items():
            tok = c.post("/api/v1/auth/login", json={"email": u.email, "password": PW}).json()["access_token"]
            heads[k] = {"Authorization": f"Bearer {tok}"}
        yield {"c": c, "ta": ta, "tb": tb, **heads}


def _scan(c, h, name):
    org = c.post("/api/v1/organizations", headers=h, json={"name": name}).json()
    c.post("/api/v1/scopes/bulk", headers=h, json={"organization_id": org["id"], "entries": ["example.com"]})
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=h).json()}
    scan = c.post("/api/v1/scans", headers=h, json={"organization_id": org["id"],
                                                   "profile_id": profiles["standard-asm"]["id"]}).json()
    return org, scan


# ------------------------------------------------------------------ tenant views
def test_tenant_diagnostics_show_only_the_tenants_own_activity(env):
    c = env["c"]
    _, sa = _scan(c, env["alpha"], "Acme")
    _, sb = _scan(c, env["bravo"], "Beta")
    mine = c.get("/api/v1/diagnostics/tenant/scans", headers=env["alpha"]).json()
    assert [s["id"] for s in mine["items"]] == [sa["id"]]
    theirs = c.get("/api/v1/diagnostics/tenant/scans", headers=env["bravo"]).json()
    assert [s["id"] for s in theirs["items"]] == [sb["id"]]
    stage = mine["items"][0]["stages"][0]
    assert stage["timing"] and {"queue_wait_ms", "execution_ms", "ingestion_ms"} <= set(stage["timing"])
    blob = json.dumps(mine).lower()
    assert [n for n in FORBIDDEN if n in blob] == []  # capabilities, never engines
    overview = c.get("/api/v1/diagnostics/tenant/overview", headers=env["alpha"]).json()
    assert overview["scanner"]["status"] == "unavailable" and overview["scanner"]["reason"]  # never "healthy"
    assert "queues" not in overview and "host" not in overview
    assert c.get("/api/v1/diagnostics/tenant/events", headers=env["alpha"]).status_code == 200
    # A viewer has no diagnostics; a tenant admin has no platform diagnostics.
    assert c.get("/api/v1/diagnostics/tenant/scans", headers=env["alpha_viewer"]).status_code == 403
    for path in ("health", "events", "scans"):
        assert c.get(f"/api/v1/diagnostics/platform/{path}", headers=env["alpha"]).status_code == 403


def test_platform_diagnostics_report_missing_telemetry_as_unavailable(env):
    c = env["c"]
    h = c.get("/api/v1/diagnostics/platform/health", headers=env["root"]).json()
    assert h["broker"]["status"] == "unavailable"  # no broker in the test environment
    assert all(v["status"] == "unavailable" for v in h["services"].values())
    assert h["queues"]["status"] == "unavailable" and h["units"]["status"] == "unavailable"
    assert h["database"]["schema_version"] == h["database"]["expected_schema"]


def test_operational_events_are_platform_only_and_paginated(env, system_db):
    from app.models import OpsEvent

    c = env["c"]
    now = datetime.now(UTC)
    system_db.add_all([OpsEvent(event_id=uuid.uuid4().hex, ts=now - timedelta(minutes=i), level="ERROR",
                                service="worker", event="test.error", error_code="ASM-SCAN-001", message=f"boom {i}",
                                logger="t", tenant_id=env["ta"].id, data={}) for i in range(60)])
    system_db.commit()
    page1 = c.get("/api/v1/diagnostics/platform/events", headers=env["root"], params={"level": "ERROR"}).json()
    page2 = c.get("/api/v1/diagnostics/platform/events", headers=env["root"],
                  params={"level": "ERROR", "page": 2}).json()
    assert page1["total"] >= 60 and len(page1["items"]) == 50 and len(page2["items"]) >= 10
    assert c.get("/api/v1/diagnostics/platform/events", headers=env["alpha"]).status_code == 403
    only_b = c.get("/api/v1/diagnostics/platform/events", headers=env["root"],
                   params={"tenant_id": str(env["tb"].id), "event": "x"}).json()
    assert all(i["tenant_id"] == str(env["tb"].id) for i in only_b["items"])


# ---------------------------------------------------------------------- bundles
def _bundle(c, h, **body):
    r = c.post("/api/v1/diagnostics/bundles", headers=h, json=body)
    assert r.status_code == 202, r.text
    return r.json()


def test_a_tenant_bundle_contains_only_the_tenants_sanitized_data(env):
    c = env["c"]
    _, sa = _scan(c, env["alpha"], "Acme")
    _scan(c, env["bravo"], "Beta")
    pv = c.post("/api/v1/diagnostics/bundles/preview", headers=env["alpha"], json={"scan_ids": [sa["id"]]}).json()
    assert "database dumps" in pv["excluded"] and pv["counts"]["scans_selected"] == 1
    b = _bundle(c, env["alpha"], scan_ids=[sa["id"]])
    assert b["status"] == "ready" and b["contents"]["files"] and b["sha256"]
    r = c.get(f"/api/v1/diagnostics/bundles/{b['id']}/download", headers=env["alpha"])
    assert r.status_code == 200 and r.headers["content-disposition"].endswith(f'{b["filename"]}"')
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = set(z.namelist())
    assert {"manifest.json", "versions.json", "health.json", "config-summary.json", "scans.jsonl",
            "diagnostic-events.jsonl", "audit-actions.jsonl"} <= names
    assert any(n.startswith("stage-output/") for n in names)
    manifest = json.loads(z.read("manifest.json"))
    import hashlib

    for f in manifest["files"]:
        assert hashlib.sha256(z.read(f["name"])).hexdigest() == f["sha256"]
    everything = b"".join(z.read(n) for n in names).decode().lower()
    assert str(env["tb"].id) not in everything and "beta" not in everything  # no other tenant
    assert [n for n in FORBIDDEN if n in everything] == []  # no engine names for tenants
    assert "asm_secret_key" not in everything and "password" not in everything.replace("password_reset", "")
    for n in names:
        assert not n.startswith("/") and ".." not in n


def test_bundle_ownership_is_enforced_at_every_step(env, monkeypatch):
    from app.workers import dispatch

    c = env["c"]
    _, sa = _scan(c, env["alpha"], "Acme")
    _, sb = _scan(c, env["bravo"], "Beta")
    # Another tenant's scan id cannot be pulled into a bundle.
    r = c.post("/api/v1/diagnostics/bundles", headers=env["alpha"], json={"scan_ids": [sb["id"]]})
    assert r.status_code == 404
    b = _bundle(c, env["alpha"], scan_ids=[sa["id"]])
    for method, path in (("get", ""), ("get", "/download"), ("delete", "")):
        assert getattr(c, method)(f"/api/v1/diagnostics/bundles/{b['id']}{path}", headers=env["bravo"]).status_code == 404
    # Asking for it as a platform bundle does not work either (and needs platform permission).
    assert c.get(f"/api/v1/diagnostics/bundles/{b['id']}", headers=env["alpha"],
                 params={"scope": "platform"}).status_code == 403
    assert c.get(f"/api/v1/diagnostics/bundles/{b['id']}", headers=env["root"],
                 params={"scope": "platform"}).status_code == 404
    assert c.post("/api/v1/diagnostics/bundles", headers=env["alpha"], json={"scope": "platform"}).status_code == 403
    assert c.get("/api/v1/diagnostics/bundles", headers=env["bravo"]).json() == []
    # One active bundle per tenant.
    monkeypatch.setattr(dispatch, "generate_support_bundle", lambda *a: None)
    _bundle(c, env["alpha"])
    assert c.post("/api/v1/diagnostics/bundles", headers=env["alpha"], json={}).status_code == 409
    assert c.delete(f"/api/v1/diagnostics/bundles/{b['id']}", headers=env["alpha"]).status_code == 204
    assert c.get(f"/api/v1/diagnostics/bundles/{b['id']}", headers=env["alpha"]).status_code == 404


def test_a_platform_bundle_is_for_platform_administrators(env):
    c = env["c"]
    _scan(c, env["alpha"], "Acme")
    b = _bundle(c, env["root"], scope="platform")
    assert b["status"] == "ready"
    z = zipfile.ZipFile(io.BytesIO(c.get(f"/api/v1/diagnostics/bundles/{b['id']}/download", headers=env["root"],
                                         params={"scope": "platform"}).content))
    versions = json.loads(z.read("versions.json"))
    assert {"application", "schema", "python"} <= set(versions)
    config = json.loads(z.read("config-summary.json"))
    assert not {k for k in config if "key" in k or "secret" in k or "password" in k}
    assert c.get(f"/api/v1/diagnostics/bundles/{b['id']}", headers=env["alpha"]).status_code == 404
    assert c.get("/api/v1/diagnostics/bundles", headers=env["root"], params={"scope": "platform"}).json()[0]["id"] == b["id"]


def test_generation_failures_leave_nothing_behind_and_limits_hold(env, monkeypatch, system_db):
    from app.diagnostics import bundles
    from app.models import SupportBundle
    from app.services.storage import get_store

    c = env["c"]
    stored: list[str] = []
    real_put = type(get_store()).put

    def spy_put(self, key, data, ct):  # noqa: ANN001
        stored.append(key)
        return real_put(self, key, data, ct)

    monkeypatch.setattr(type(get_store()), "put", spy_put)
    monkeypatch.setattr(bundles, "MAX_BYTES", 10)  # nothing fits
    b = _bundle(c, env["alpha"])
    assert b["status"] == "failed" and stored == []
    monkeypatch.setattr(bundles, "MAX_BYTES", 50 * 1024 * 1024)
    with pytest.raises(ValueError):
        bundles._Archive(1e12).add("../etc/passwd", "x")
    with pytest.raises(ValueError):
        bundles._Archive(1e12).add("/abs", "x")
    with pytest.raises(ValueError):
        bundles._Archive(1e12).add("a/b/c/d", "x")
    r = c.post("/api/v1/diagnostics/bundles", headers=env["alpha"],
               json={"window_start": "2026-01-01T00:00:00Z", "window_end": "2026-06-01T00:00:00Z"})
    assert r.status_code == 422  # at most 30 days
    ok = _bundle(c, env["alpha"])
    system_db.execute(update(SupportBundle).where(SupportBundle.id == uuid.UUID(ok["id"])).values(
        expires_at=datetime.now(UTC) - timedelta(minutes=1)))
    system_db.commit()
    key = system_db.get(SupportBundle, uuid.UUID(ok["id"])).storage_key
    assert get_store().exists(key)
    assert bundles.purge_expired() >= 1
    assert not get_store().exists(key)


def test_deleting_an_organization_removes_bundles_that_hold_its_data(env, system_db):
    from app.models import StorageDeletion, SupportBundle
    from app.services import maintenance
    from app.services.storage import get_store

    c = env["c"]
    org, sa = _scan(c, env["alpha"], "Acme")
    b = _bundle(c, env["alpha"], scan_ids=[sa["id"]])
    key = system_db.get(SupportBundle, uuid.UUID(b["id"])).storage_key
    assert c.delete(f"/api/v1/organizations/{org['id']}", headers=env["alpha"]).status_code == 200
    system_db.expire_all()
    assert system_db.get(SupportBundle, uuid.UUID(b["id"])) is None
    maintenance.purge_retention()
    assert not get_store().exists(key)
    assert system_db.execute(select(StorageDeletion)).scalars().all() == []


# ------------------------------------------------------------------- local CLI
def test_the_cli_reports_what_it_could_not_reach_and_still_writes_a_report(tmp_path, monkeypatch):
    """Database and broker down, no systemd, no config file: every source is tried, the
    missing ones say why, and the archive is written with owner-only permissions."""
    import os
    import tarfile

    from app import diagcli

    monkeypatch.setattr(diagcli, "CONFIG", tmp_path / "missing.env")
    monkeypatch.setattr(diagcli, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setenv("ASM_DATABASE_URL", "postgresql+psycopg://x:y@127.0.0.1:1/none")
    monkeypatch.setenv("ASM_CELERY_BROKER_URL", "redis://:secretpw@127.0.0.1:1/0")
    rc = diagcli.main(["--out", str(tmp_path / "out"), "--since", "30m"])
    assert rc == 2
    archive = next((tmp_path / "out").glob("exteriq-diag-*.tar.gz"))
    if os.name == "posix":
        assert oct(archive.stat().st_mode & 0o777) == "0o600"
    with tarfile.open(archive) as tar:
        report = json.loads(tar.extractfile("exteriq-diag/report.json").read())
    assert report["database"]["status"] == "missing" and report["broker"]["status"] == "missing"
    assert report["config"]["status"] == "missing" and "versions" in report and report["versions"]["application"]
    assert "secretpw" not in json.dumps(report)
    assert set(report["missing"]) >= {"database", "broker", "config", "log_files"}


# ----------------------------------------------------------------- first-run setup
def test_setup_token_is_single_use_short_lived_and_closes_setup(db_clean, monkeypatch):
    from datetime import timedelta

    from app import setup
    from app.db.session import system_session
    from app.main import app
    from app.models import SetupToken

    with system_session() as db:
        assert setup.needed(db)
        old = setup.issue(db)
        token = setup.issue(db)  # a new token voids the old one
        db.commit()
        stored = [r.token_hash for r in db.execute(select(SetupToken)).scalars()]
    assert token not in stored and old not in stored  # only hashes are kept
    body = {"email": "admin@example.org", "password": "Corr3ct-Horse-Battery!", "full_name": "First Admin",
            "tenant_name": "Example"}
    with TestClient(app) as c:
        assert c.get("/api/v1/setup").json() == {"needed": True}
        assert c.post("/api/v1/setup", json={**body, "token": old}).status_code == 403
        assert c.post("/api/v1/setup", json={**body, "token": "x" * 43}).status_code == 403
        r = c.post("/api/v1/setup", json={**body, "token": token})
        assert r.status_code == 201, r.text
        assert c.post("/api/v1/setup", json={**body, "token": token}).status_code == 403  # used
        assert c.get("/api/v1/setup").json() == {"needed": False}
        login = c.post("/api/v1/auth/login", json={"email": body["email"], "password": body["password"]})
        assert login.status_code == 200
    with system_session() as db:
        with pytest.raises(Exception, match="already complete"):
            setup.issue(db)
    # Expiry: an expired token is refused even though it was never used.
    with system_session() as db:
        db.execute(SetupToken.__table__.delete())
        db.add(SetupToken(token_hash=setup._hash("e" * 43), expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        db.commit()
    with TestClient(app) as c:
        assert c.post("/api/v1/setup", json={**body, "token": "e" * 43, "email": "b@example.org"}).status_code == 403


def test_setup_token_cli(db_clean, capsys):
    """What the installer runs: prints a working token once, refuses after setup."""
    from app import cli, setup
    from app.db.session import system_session

    cli.main(["setup-token", "--ttl-minutes", "5"])
    token = capsys.readouterr().out.strip()
    assert len(token) >= 40
    with system_session() as db:
        setup.complete(db, token=token, email="first@example.org", password="Corr3ct-Horse-Battery!",
                       full_name="First", tenant_name="Example")
        db.commit()
    with pytest.raises(SystemExit) as exc:
        cli.main(["setup-token"])
    assert exc.value.code == 3
