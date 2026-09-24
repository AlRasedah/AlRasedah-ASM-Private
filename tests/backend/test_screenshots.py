"""Website screenshots, platform side, on PostgreSQL with RLS.

The browser run is replaced by a controllable result (the adapter itself is tested
in tests/sensors/test_screenshot.py); everything else — API, authorization,
dispatcher, sealed job, result binding, validation, storage, retention — is real.
"""

from __future__ import annotations

import base64
import hashlib
import threading
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from tests.sensors.fake_browser import png

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"


class Browser:
    """What the next capture returns: 'ok', 'fail', 'blocked', 'badsha', 'notpng' or a PNG size."""

    def __init__(self) -> None:
        self.mode = "ok"
        self.padding = 0
        self.calls: list[dict] = []

    async def run(self, adapter, targets, cfg, ctx):  # noqa: ANN001
        from asm_sensors.observations import ScreenshotImage, SensorResult

        self.calls.append({"targets": [t.value for t in targets], "config": cfg, "job": ctx.job_id})
        now = datetime.now(UTC)
        if self.mode in ("fail", "blocked"):
            return SensorResult(adapter="screenshot", status="failed", started_at=now, finished_at=now,
                                errors=["egress policy blocked 127.0.0.1:80: non-public address"]
                                if self.mode == "blocked" else ["the page did not finish loading within 20 seconds"],
                                stats={"outcome": self.mode if self.mode == "blocked" else "timeout"})
        data = png(64, 40, padding=self.padding) if self.mode != "notpng" else b"GIF89a" + b"\0" * 64
        sha = hashlib.sha256(data).hexdigest() if self.mode != "badsha" else "0" * 64
        img = ScreenshotImage(url=targets[0].value, final_url=targets[0].value, width=64, height=40, size=len(data),
                              sha256=sha, data=base64.b64encode(data).decode(), captured_at=now, title="Login")
        return SensorResult(adapter="screenshot", status="completed", started_at=now, finished_at=now,
                            screenshots=[img], stats={"outcome": "succeeded"})


@pytest.fixture
def env(db_clean, factory, monkeypatch):
    from asm_sensors.adapters.screenshot import ScreenshotAdapter

    from app.main import app

    FakeSensors(monkeypatch)
    browser = Browser()

    async def fake_run(self, targets, cfg, ctx):  # noqa: ANN001
        return await browser.run(self, targets, cfg, ctx)

    monkeypatch.setattr(ScreenshotAdapter, "run", fake_run)
    ta, tb = factory.tenant("Alpha"), factory.tenant("Bravo")
    root = factory.user(ta.id, role="tenant_admin", password=PW, platform_admin=True)
    analyst = factory.user(ta.id, role="security_analyst", password=PW)
    viewer = factory.user(ta.id, role="viewer", password=PW)
    badmin = factory.user(tb.id, role="tenant_admin", password=PW)
    with TestClient(app) as c:
        def login(u):
            token = c.post("/api/v1/auth/login", json={"email": u.email, "password": PW}).json()["access_token"]
            return {"Authorization": f"Bearer {token}"}

        yield {"c": c, "browser": browser, "ta": ta, "tb": tb, "root": login(root), "analyst": login(analyst),
               "viewer": login(viewer), "bravo": login(badmin)}


def _inventory(c, admin, name="Acme"):
    org = c.post("/api/v1/organizations", headers=admin, json={"name": name}).json()
    c.post("/api/v1/scopes/bulk", headers=admin, json={"organization_id": org["id"], "entries": ["example.com"]})
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=admin).json()}
    c.post("/api/v1/scans", headers=admin, json={"organization_id": org["id"], "profile_id": profiles["standard-asm"]["id"]})
    eps = c.get("/api/v1/assets", headers=admin, params={"asset_type": "http_endpoint", "page_size": 100}).json()["items"]
    return org, {a["value"]: a["id"] for a in eps}


def _enable(c, root, tenant_admin, **policy):
    assert c.put("/api/v1/settings/screenshots", headers=root, json={"available": True, **policy}).status_code == 200
    assert c.put("/api/v1/settings", headers=tenant_admin, json={"screenshots": {"enabled": True}}).status_code == 200


def _shots(c, h, asset_id):
    r = c.get(f"/api/v1/assets/{asset_id}/screenshots", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


# ------------------------------------------------------------------ availability
def test_disabled_until_the_platform_and_the_tenant_enable_it(env):
    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    st = _shots(c, analyst, ep)["status"]
    assert st["available"] is False and "not enabled in this deployment" in st["reason"]
    r = c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    assert r.status_code == 422 and r.json()["error"]["code"] == "feature_unavailable"
    assert c.put("/api/v1/settings/screenshots", headers=analyst, json={"available": True}).status_code == 403
    c.put("/api/v1/settings/screenshots", headers=root, json={"available": True})
    st = _shots(c, analyst, ep)["status"]
    assert st["available"] and "turned off for this tenant" in st["reason"]
    assert c.put("/api/v1/settings", headers=analyst, json={"screenshots": {"enabled": True}}).status_code == 403
    c.put("/api/v1/settings", headers=root, json={"screenshots": {"enabled": True, "cadence": "weekly"}})
    st = _shots(c, analyst, ep)["status"]
    assert st["reason"] is None and st["cadence"] == "weekly" and st["limits"]["retention_per_endpoint"] == 2


def test_policy_values_are_bounded(env):
    c, root = env["c"], env["root"]
    assert c.put("/api/v1/settings/screenshots", headers=root, json={"max_concurrent": 0}).status_code == 422
    assert c.put("/api/v1/settings/screenshots", headers=root, json={"max_image_kb": 99999}).status_code == 422
    assert c.put("/api/v1/settings/screenshots", headers=root, json={"surprise": 1}).status_code == 422
    r = c.put("/api/v1/settings/screenshots", headers=root, json={"max_concurrent": 3})
    assert r.json()["policy"]["max_concurrent"] == 3 and r.json()["policy"]["available"] is False


# -------------------------------------------------------------------- captures
def test_capture_end_to_end_through_the_sealed_job(env):
    c, root, analyst, viewer, browser = env["c"], env["root"], env["analyst"], env["viewer"], env["browser"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    _enable(c, root, root)
    assert c.post(f"/api/v1/assets/{ep}/screenshots", headers=viewer).status_code == 403
    r = c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    assert r.status_code == 202, r.text
    listing = _shots(c, viewer, ep)
    latest = listing["latest"]
    assert latest["status"] == "succeeded" and latest["page_title"] == "Login" and latest["has_image"]
    assert (latest["width"], latest["height"]) == (64, 40)
    # the job carried the policy and the scope's exclusions, and targeted exactly this endpoint
    call = browser.calls[0]
    assert call["targets"] == ["https://api.example.com"] and call["config"]["viewport_width"] == 1280
    img = c.get(f"/api/v1/assets/{ep}/screenshots/{latest['id']}/image", headers=viewer)
    assert img.status_code == 200 and img.content.startswith(b"\x89PNG")
    assert img.headers["content-type"] == "image/png" and img.headers["x-content-type-options"] == "nosniff"
    assert "no-store" in img.headers["cache-control"]
    # a capture never becomes a finding or a vulnerability verification
    assert c.get("/api/v1/findings", headers=viewer, params={"q": "screenshot"}).json()["total"] == 0


def test_only_web_endpoints_and_authorized_scope(env):
    c, root, analyst = env["c"], env["root"], env["analyst"]
    org, eps = _inventory(c, root)
    _enable(c, root, root)
    host = c.get("/api/v1/assets", headers=root, params={"asset_type": "subdomain", "page_size": 1}).json()["items"][0]
    assert c.post(f"/api/v1/assets/{host['id']}/screenshots", headers=analyst).status_code == 422
    c.post("/api/v1/scopes", headers=root, json={"organization_id": org["id"], "entry_type": "domain",
                                                 "value": "api.example.com", "is_exclusion": True})
    r = c.post(f"/api/v1/assets/{eps['https://api.example.com']}/screenshots", headers=analyst)
    assert r.status_code == 422 and "cannot be captured" in r.json()["error"]["message"]


def test_scope_is_checked_again_at_dispatch(env, monkeypatch):
    from app.screenshots import jobs
    from app.workers import dispatch

    c, root, analyst = env["c"], env["root"], env["analyst"]
    org, eps = _inventory(c, root)
    _enable(c, root, root)
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)  # leave it queued
    ep = eps["https://api.example.com"]
    assert c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).json()["status"] == "queued"
    c.post("/api/v1/scopes", headers=root, json={"organization_id": org["id"], "entry_type": "domain",
                                                 "value": "api.example.com", "is_exclusion": True})
    jobs.dispatch()
    cap = _shots(c, analyst, ep)["captures"][0]
    assert cap["status"] == "blocked" and "not authorized by scope" in cap["error"] and not env["browser"].calls


def test_a_failure_never_removes_the_previous_image(env):
    c, root, analyst, browser = env["c"], env["root"], env["analyst"], env["browser"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    _enable(c, root, root)
    c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    good = _shots(c, analyst, ep)["latest"]["id"]
    for mode, status in (("fail", "failed"), ("blocked", "blocked"), ("notpng", "failed"), ("badsha", "failed")):
        browser.mode = mode
        c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
        data = _shots(c, analyst, ep)
        assert data["captures"][0]["status"] == status, mode
        assert data["latest"]["id"] == good
        assert c.get(f"/api/v1/assets/{ep}/screenshots/{good}/image", headers=analyst).status_code == 200
    errors = [x["error"] for x in _shots(c, analyst, ep)["captures"][:4]]
    assert any("checksum" in e for e in errors) and any("not a PNG" in e for e in errors)


def test_retention_keeps_the_latest_two_and_deletes_objects(env, system_db):
    from app.models import ScreenshotCapture
    from app.services.storage import get_store

    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    _enable(c, root, root)
    ids = []
    for _ in range(3):
        c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
        ids.append(_shots(c, analyst, ep)["latest"]["id"])
    kept = system_db.execute(select(ScreenshotCapture.id).where(ScreenshotCapture.status == "succeeded")).scalars()
    assert {str(i) for i in kept} == set(ids[1:])
    tid = env["ta"].id
    assert not get_store().exists(f"tenants/{tid}/screenshots/{ids[0]}.png")
    assert get_store().exists(f"tenants/{tid}/screenshots/{ids[2]}.png")
    assert c.get(f"/api/v1/assets/{ep}/screenshots/{ids[0]}/image", headers=analyst).status_code == 404


def test_storage_quota_refuses_the_new_image_and_keeps_the_old(env):
    c, root, analyst, browser = env["c"], env["root"], env["analyst"], env["browser"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    _enable(c, root, root, storage_quota_mb=10, max_image_kb=5120, retention_per_endpoint=3)
    browser.padding = 4 * 1024 * 1024
    c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    data = _shots(c, analyst, ep)
    assert [x["status"] for x in data["captures"]] == ["failed", "succeeded", "succeeded"]
    assert "storage quota" in data["captures"][0]["error"]
    assert data["status"]["usage"]["stored_bytes"] <= 10 * 1024 * 1024


def test_daily_and_queue_limits(env, monkeypatch):
    from app.workers import dispatch

    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    _enable(c, root, root, per_tenant_daily=1)
    urls = sorted(u for u in eps if ".example.com" in u)
    assert len(urls) >= 2, eps
    assert c.post(f"/api/v1/assets/{eps[urls[0]]}/screenshots", headers=analyst).status_code == 202
    r = c.post(f"/api/v1/assets/{eps[urls[1]]}/screenshots", headers=analyst)
    assert r.status_code == 429 and "per day" in r.json()["error"]["message"]
    c.put("/api/v1/settings/screenshots", headers=root, json={"per_tenant_daily": 100, "per_tenant_queued": 1})
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)
    first = c.post(f"/api/v1/assets/{eps[urls[1]]}/screenshots", headers=analyst).json()
    again = c.post(f"/api/v1/assets/{eps[urls[1]]}/screenshots", headers=analyst).json()
    assert again["id"] == first["id"]  # one active capture per endpoint: a repeat click reuses it
    assert c.post(f"/api/v1/assets/{eps[urls[0]]}/screenshots", headers=analyst).status_code == 429


# ------------------------------------------------------------- concurrency limit
def _endpoint_like(system_db, asset_id, i):
    """Another web endpoint like this one: an endpoint has at most one active capture."""
    from sqlalchemy import inspect

    from app.models import Asset

    if i == 0:
        return asset_id
    src = system_db.get(Asset, asset_id)
    data = {a.key: getattr(src, a.key) for a in inspect(Asset).column_attrs if a.key not in ("id", "created_at",
                                                                                            "updated_at")}
    data["value"] = data["normalized_value"] = f"https://q{i}-{str(asset_id)[:8]}.example.com"
    copy = Asset(**data)
    system_db.add(copy)
    system_db.flush()
    return copy.id


def _queue(system_db, tenant, org_id, asset_id, n, minutes_ago=10):
    from app.models import ScreenshotCapture

    rows = []
    for i in range(n):
        cap = ScreenshotCapture(tenant_id=tenant, organization_id=org_id, asset_id=_endpoint_like(system_db, asset_id, i),
                                url="https://api.example.com", status="queued")
        system_db.add(cap)
        system_db.flush()
        system_db.execute(update(ScreenshotCapture).where(ScreenshotCapture.id == cap.id).values(
            created_at=datetime.now(UTC) - timedelta(minutes=minutes_ago - i)))
        rows.append(cap.id)
    system_db.commit()
    return rows


def _asset(system_db, tenant_id):
    from app.models import Asset

    a = system_db.execute(select(Asset).where(Asset.tenant_id == tenant_id,
                                              Asset.asset_type == "http_endpoint")).scalars().first()
    return a.organization_id, a.id


def test_one_active_capture_per_deployment_across_concurrent_dispatchers(env, system_db):
    """Eight dispatchers on eight connections at once reserve exactly the configured number."""
    from app.models import ScreenshotCapture
    from app.screenshots import service

    c, root, bravo = env["c"], env["root"], env["bravo"]
    _inventory(c, root)
    _inventory(c, bravo, "Bravo org")
    c.put("/api/v1/settings/screenshots", headers=root, json={"available": True})
    _queue(system_db, env["ta"].id, *_asset(system_db, env["ta"].id), 3)
    _queue(system_db, env["tb"].id, *_asset(system_db, env["tb"].id), 3)
    got: list = []
    barrier = threading.Barrier(8)

    def worker():
        barrier.wait()
        got.extend(service.reserve())

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(got) == 1
    system_db.expire_all()
    assert system_db.scalar(select(func.count()).select_from(ScreenshotCapture).where(
        ScreenshotCapture.status == "running")) == 1
    assert service.reserve() == []  # still full
    # Raise the limit: the next reservation goes to the other tenant first (fairness).
    c.put("/api/v1/settings/screenshots", headers=root, json={"max_concurrent": 3})
    more = service.reserve()
    assert len(more) == 2 and {t for t, _ in more} == {env["ta"].id, env["tb"].id}


def test_watchdog_frees_the_slot_of_a_lost_capture(env, system_db):
    from app.models import ScreenshotCapture
    from app.screenshots import service

    c, root = env["c"], env["root"]
    _inventory(c, root)
    c.put("/api/v1/settings/screenshots", headers=root, json={"available": True})
    org, asset = _asset(system_db, env["ta"].id)
    lost, waiting = _queue(system_db, env["ta"].id, org, asset, 2)
    system_db.execute(update(ScreenshotCapture).where(ScreenshotCapture.id == lost).values(
        status="running", task_id="x", dispatched_at=datetime.now(UTC) - timedelta(hours=1),
        started_at=datetime.now(UTC) - timedelta(hours=1)))
    system_db.commit()
    assert [cid for _, cid in service.reserve()] == [waiting]
    system_db.expire_all()
    dead = system_db.get(ScreenshotCapture, lost)
    assert dead.status == "failed" and "no result came back" in dead.error


# ---------------------------------------------------------------- result binding
def test_results_are_bound_to_their_capture(env, system_db, monkeypatch):
    from asm_sensors.jobs import seal_result

    from app.core import crypto
    from app.models import ScreenshotCapture
    from app.screenshots import service
    from app.workers import dispatch
    from app.workers.results import receive_result

    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    _enable(c, root, root)
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)
    cap = c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).json()
    (tid, cid), = service.reserve()
    job, pool = service.launch(tid, cid)
    good = __import__("asyncio").run(env["browser"].run(None, job.targets, job.config, type("X", (), {"job_id": "j"})))
    key = crypto.pool_transport_key(pool)

    forged_job = job.model_copy(update={"job_id": "other-job"})
    other_tenant = job.model_copy(update={"tenant_id": str(env["tb"].id)})
    for bad in (seal_result(forged_job, good, pool, key), seal_result(other_tenant, good, pool, key),
                seal_result(job, good, pool, crypto.pool_transport_key("other-pool")),
                seal_result(job, good.model_copy(update={"adapter": "nuclei"}), pool, key)):
        assert receive_result(bad) is None
    system_db.expire_all()
    assert system_db.get(ScreenshotCapture, uuid.UUID(cap["id"])).status == "running"
    assert receive_result(seal_result(job, good, pool, key)) is None  # accepted (screenshots never advance a scan)
    system_db.expire_all()
    assert system_db.get(ScreenshotCapture, uuid.UUID(cap["id"])).status == "succeeded"
    # a replay after completion changes nothing
    assert receive_result(seal_result(job, good, pool, key)) is None


# ------------------------------------------------------------------- isolation
def test_tenants_cannot_see_or_touch_each_others_screenshots(env):
    c, root, analyst, bravo = env["c"], env["root"], env["analyst"], env["bravo"]
    _, eps_a = _inventory(c, root)
    _, eps_b = _inventory(c, bravo, "Bravo org")  # the same URLs in another tenant
    _enable(c, root, root)
    c.put("/api/v1/settings", headers=bravo, json={"screenshots": {"enabled": True}})
    a_ep, b_ep = eps_a["https://api.example.com"], eps_b["https://api.example.com"]
    assert a_ep != b_ep
    c.post(f"/api/v1/assets/{a_ep}/screenshots", headers=analyst)
    a_cap = _shots(c, analyst, a_ep)["latest"]["id"]
    c.post(f"/api/v1/assets/{b_ep}/screenshots", headers=bravo)
    b_cap = _shots(c, bravo, b_ep)["latest"]["id"]
    for path in (f"/api/v1/assets/{a_ep}/screenshots/{a_cap}/image", f"/api/v1/assets/{b_ep}/screenshots/{a_cap}/image",
                 f"/api/v1/assets/{a_ep}/screenshots"):
        assert c.get(path, headers=bravo).status_code == 404, path
    # A's own asset with B's capture id: the id is a guess from A's point of view.
    assert c.get(f"/api/v1/assets/{a_ep}/screenshots/{b_cap}/image", headers=analyst).status_code == 404
    assert c.post(f"/api/v1/assets/{a_ep}/screenshots/{a_cap}/cancel", headers=bravo).status_code == 404
    assert c.delete(f"/api/v1/assets/{a_ep}/screenshots/{a_cap}", headers=bravo).status_code == 404
    assert c.post(f"/api/v1/assets/{a_ep}/screenshots", headers=bravo).status_code == 404
    assert c.get("/api/v1/screenshots/status", headers=bravo).json()["usage"]["captures_today"] == 1


def test_deleting_an_organization_deletes_its_images(env):
    from app.services.storage import get_store

    c, root, analyst = env["c"], env["root"], env["analyst"]
    org, eps = _inventory(c, root)
    _enable(c, root, root)
    ep = eps["https://api.example.com"]
    c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    cap = _shots(c, analyst, ep)["latest"]["id"]
    key = f"tenants/{env['ta'].id}/screenshots/{cap}.png"
    assert get_store().exists(key)
    assert c.delete(f"/api/v1/organizations/{org['id']}", headers=root).status_code == 200
    assert not get_store().exists(key)


def test_weekly_schedule_queues_each_endpoint_once_within_the_cap(env, system_db, tenant_db, monkeypatch):
    from app.models import ScreenshotCapture, Tenant
    from app.screenshots import service

    c, root = env["c"], env["root"]
    _, eps = _inventory(c, root)
    c.put("/api/v1/settings/screenshots", headers=root, json={"available": True, "per_tenant_queued": 2})
    c.put("/api/v1/settings", headers=root, json={"screenshots": {"enabled": True, "cadence": "weekly"}})
    with tenant_db(env["ta"].id) as db:
        assert service.schedule_weekly(db, db.get(Tenant, env["ta"].id)) == min(2, len(eps))
        db.commit()
        assert service.schedule_weekly(db, db.get(Tenant, env["ta"].id)) == 0  # queue is full
    assert system_db.scalar(select(func.count()).select_from(ScreenshotCapture).where(
        ScreenshotCapture.trigger == "scheduled")) == min(2, len(eps))


def test_screenshot_capability_is_not_a_scan_stage(env):
    c, root = env["c"], env["root"]
    engines = c.get("/api/v1/scan-profiles/engines", headers=root).json()
    assert all(e["display_name"] != "Website screenshot" for e in engines)
    r = c.post("/api/v1/scan-profiles", headers=root, json={"name": "Sneaky", "stages": [
        {"stage": "http_discovery", "engine": "screenshot", "config": {}}]})
    assert r.status_code == 422


def test_cancel_revokes_the_job_and_a_late_result_is_refused(env, system_db, monkeypatch):
    import asyncio

    from asm_sensors.jobs import seal_result

    from app.core import crypto
    from app.models import ScreenshotCapture
    from app.screenshots import service
    from app.workers import dispatch
    from app.workers.results import receive_result

    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    ep = eps["https://api.example.com"]
    _enable(c, root, root)
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)
    revoked: list = []
    monkeypatch.setattr(dispatch, "revoke", lambda tasks: revoked.extend(tasks))
    cap = c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).json()
    (tid, cid), = service.reserve()
    job, pool = service.launch(tid, cid)
    r = c.post(f"/api/v1/assets/{ep}/screenshots/{cap['id']}/cancel", headers=analyst)
    assert r.json()["status"] == "cancelled" and revoked == [(job.job_id, pool)]
    late = asyncio.run(env["browser"].run(None, job.targets, job.config, type("X", (), {"job_id": "j"})))
    receive_result(seal_result(job, late, pool, crypto.pool_transport_key(pool)))
    system_db.expire_all()
    row = system_db.get(ScreenshotCapture, uuid.UUID(cap["id"]))
    assert row.status == "cancelled" and row.storage_key is None
    assert service.reserve() == []  # nothing queued; the slot is free again


# ------------------------------------------------------- audit regressions (F3, F4, F6)
@pytest.mark.parametrize("same_endpoint", [True, False])
def test_concurrent_requests_cannot_pass_the_last_unit_of_quota(env, monkeypatch, same_endpoint):
    from app.db.session import new_session
    from app.models import ScreenshotCapture
    from app.screenshots import service
    from app.workers import dispatch

    c, root = env["c"], env["root"]
    _, eps = _inventory(c, root)
    _enable(c, root, root, per_tenant_daily=1, per_tenant_queued=1)
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)
    urls = sorted(u for u in eps if ".example.com" in u)
    targets = [eps[urls[0]]] * 2 if same_endpoint else [eps[urls[0]], eps[urls[1]]]
    tid = env["ta"].id
    barrier = threading.Barrier(2)
    outcomes: list = []

    def request(asset_id: str) -> None:
        with new_session(tid) as db:
            barrier.wait()
            try:
                _, created = service.request_capture(db, tenant_id=tid, asset_id=uuid.UUID(asset_id), user_id=None)
                db.commit()
                outcomes.append("created" if created else "reused")
            except Exception as exc:  # noqa: BLE001
                db.rollback()
                outcomes.append(type(exc).__name__)

    threads = [threading.Thread(target=request, args=(a,)) for a in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with new_session(tid) as db:
        assert db.scalar(select(func.count()).select_from(ScreenshotCapture)) == 1
    assert sorted(outcomes) == (["created", "reused"] if same_endpoint else ["QuotaExceeded", "created"])


def test_deleting_an_image_never_restores_the_daily_allowance(env):
    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    _enable(c, root, root, per_tenant_daily=1)
    ep = eps["https://api.example.com"]
    assert c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).status_code == 202
    cap = _shots(c, analyst, ep)["latest"]["id"]
    assert c.delete(f"/api/v1/assets/{ep}/screenshots/{cap}", headers=root).status_code in (200, 204)
    assert _shots(c, analyst, ep)["status"]["usage"]["captures_today"] == 1
    r = c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    assert r.status_code == 429, r.text


def test_retention_never_restores_the_daily_allowance(env):
    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    _enable(c, root, root, per_tenant_daily=3, retention_per_endpoint=1)
    ep = eps["https://api.example.com"]
    for _ in range(3):
        assert c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).status_code == 202
    shots = _shots(c, analyst, ep)
    assert len([x for x in shots["captures"] if x["status"] == "succeeded"]) == 1  # retention kept one
    assert shots["status"]["usage"]["captures_today"] == 3
    assert c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).status_code == 429


def test_cancelling_before_it_starts_gives_the_allowance_back(env, monkeypatch):
    from app.workers import dispatch

    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    _enable(c, root, root, per_tenant_daily=1)
    ep = eps["https://api.example.com"]
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)
    cap = c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).json()
    assert c.post(f"/api/v1/assets/{ep}/screenshots/{cap['id']}/cancel", headers=analyst).json()["status"] == "cancelled"
    assert c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst).status_code == 202


def test_a_capture_keeps_its_slot_until_its_job_can_no_longer_run(env, system_db):
    """The watchdog frees nothing a delayed job could still use; the job refuses to start late."""
    from asm_sensors.jobs import JOB_HARD_LIMIT_GRACE

    from app.models import ScreenshotCapture
    from app.screenshots import service

    c, root = env["c"], env["root"]
    org, eps = _inventory(c, root)
    _enable(c, root, root)
    first, second = _queue(system_db, env["ta"].id, uuid.UUID(org["id"]), uuid.UUID(eps["https://api.example.com"]), 2)
    start = datetime.now(UTC)
    assert [cid for _, cid in service.reserve(start)] == [first]
    job, _pool = service.launch(env["ta"].id, first)
    system_db.expire_all()
    row = system_db.get(ScreenshotCapture, first)
    # The job may start until not_after; the slot covers that plus its hard time limit.
    assert job.not_after is not None and job.not_after <= row.started_at + service.START_WINDOW
    assert row.slot_until >= job.not_after + timedelta(seconds=job.timeout_seconds + JOB_HARD_LIMIT_GRACE)
    # Eleven minutes on, with no result: the old watchdog freed the slot here.
    system_db.execute(update(ScreenshotCapture).where(ScreenshotCapture.id == first).values(dispatched_at=start))
    system_db.commit()
    assert service.reserve(start + timedelta(minutes=11)) == []
    # Once the job cannot be running any more, the capture fails and the slot is reused.
    assert [cid for _, cid in service.reserve(row.slot_until + timedelta(seconds=1))] == [second]
    system_db.expire_all()
    assert system_db.get(ScreenshotCapture, first).status == "failed"


def test_a_cancelled_running_capture_holds_its_slot_until_its_job_reports(env, monkeypatch):
    import asyncio

    from asm_sensors.jobs import seal_result

    from app.core import crypto
    from app.screenshots import service
    from app.workers import dispatch
    from app.workers.results import receive_result

    c, root, analyst = env["c"], env["root"], env["analyst"]
    _, eps = _inventory(c, root)
    _enable(c, root, root)
    urls = sorted(u for u in eps if ".example.com" in u)
    monkeypatch.setattr(dispatch, "dispatch_screenshots", lambda: None)
    monkeypatch.setattr(dispatch, "revoke", lambda tasks: None)
    cap = c.post(f"/api/v1/assets/{eps[urls[0]]}/screenshots", headers=analyst).json()
    (tid, cid), = service.reserve()
    job, pool = service.launch(tid, cid)
    c.post(f"/api/v1/assets/{eps[urls[0]]}/screenshots/{cap['id']}/cancel", headers=analyst)
    c.post(f"/api/v1/assets/{eps[urls[1]]}/screenshots", headers=analyst)
    assert service.reserve() == []  # the cancelled job may still be running
    late = asyncio.run(env["browser"].run(None, job.targets, job.config, type("X", (), {"job_id": "j"})))
    receive_result(seal_result(job, late, pool, crypto.pool_transport_key(pool)))
    assert len(service.reserve()) == 1  # its result arrived: the slot is free


def test_organization_images_that_fail_to_delete_are_retried_by_maintenance(env, system_db, monkeypatch):
    from app.models import StorageDeletion
    from app.services import maintenance
    from app.services.storage import get_store

    c, root, analyst = env["c"], env["root"], env["analyst"]
    org, eps = _inventory(c, root)
    _enable(c, root, root)
    ep = eps["https://api.example.com"]
    c.post(f"/api/v1/assets/{ep}/screenshots", headers=analyst)
    cap = _shots(c, analyst, ep)["latest"]
    key = f"tenants/{env['ta'].id}/screenshots/{cap['id']}.png"
    store = get_store()
    real_delete = type(store).delete

    def failing(self, k):  # noqa: ANN001
        raise OSError("storage unavailable")

    monkeypatch.setattr(type(store), "delete", failing)
    r = c.delete(f"/api/v1/organizations/{org['id']}", headers=root)
    assert r.status_code == 200 and "retried automatically" in r.json()["message"]
    assert store.exists(key)
    system_db.expire_all()
    pending = system_db.execute(select(StorageDeletion)).scalars().all()
    assert [p.storage_key for p in pending] == [key] and pending[0].attempts == 1
    # Still counted against the tenant's storage while it exists.
    st = c.get("/api/v1/screenshots/status", headers=analyst).json()
    assert st["usage"]["stored_bytes"] == cap["size"]
    monkeypatch.setattr(type(store), "delete", real_delete)
    maintenance.purge_retention()
    assert not store.exists(key)
    system_db.expire_all()
    assert system_db.execute(select(StorageDeletion)).scalars().all() == []
