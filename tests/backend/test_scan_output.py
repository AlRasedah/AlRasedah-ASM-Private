"""Verbose scan output, platform side, on PostgreSQL with RLS.

Scans run inline with recorded engine output (FakeSensors); each fake engine also
writes to the stage log the way a real one would, including its name, a version
banner and a secret, which must never reach the interface.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from asm_sensors import stagelog
from asm_sensors.jobs import SensorJob, seal_log
from asm_sensors.targets import Target, TargetKind
from fastapi.testclient import TestClient
from sqlalchemy import update

from .sensors_fake import DEFAULT_OUTPUTS, FakeSensors
from .test_engine_disclosure import FORBIDDEN

PW = "Sup3r-Secret-Passw0rd!"


def _noisy(engine: str):
    def out(targets):  # noqa: ANN001
        stagelog.note(f"[INF] Current {engine} version: v9.9.9 (latest)")
        stagelog.note(f"[INF] {engine} loaded from /opt/asm/bin/{engine} with nuclei-templates")
        stagelog.note(f"[VER] {engine} request to https://api.example.com/?api_key=TopSecret123 done")
        stagelog.note(f"[WRN] {engine}: {len(targets)} target(s) queued")
        return DEFAULT_OUTPUTS[engine]
    return out


@pytest.fixture
def env(db_clean, factory, monkeypatch):
    from app.main import app

    fake = FakeSensors(monkeypatch, {e: _noisy(e) for e in ("subfinder", "dnsx", "naabu", "httpx", "nuclei")})
    ta, tb = factory.tenant("Alpha"), factory.tenant("Bravo")
    a = factory.user(ta.id, role="tenant_admin", password=PW)
    b = factory.user(tb.id, role="tenant_admin", password=PW)
    with TestClient(app) as c:
        def login(u):
            r = c.post("/api/v1/auth/login", json={"email": u.email, "password": PW})
            return {"Authorization": f"Bearer {r.json()['access_token']}"}

        yield {"c": c, "fake": fake, "ta": ta, "tb": tb, "alpha": login(a), "bravo": login(b)}


def _scan(c, h):
    org = c.post("/api/v1/organizations", headers=h, json={"name": "Acme"}).json()
    c.post("/api/v1/scopes/bulk", headers=h, json={"organization_id": org["id"], "entries": ["example.com"]})
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=h).json()}
    r = c.post("/api/v1/scans", headers=h, json={"organization_id": org["id"],
                                               "profile_id": profiles["standard-asm"]["id"]})
    assert r.status_code == 201, r.text
    return c.get(f"/api/v1/scans/{r.json()['id']}", headers=h).json()


def test_every_stage_shows_its_verbose_output_without_engine_names_or_secrets(env):
    c, h = env["c"], env["alpha"]
    scan = _scan(c, h)
    ran = [s for s in scan["stages"] if s["status"] not in ("pending", "skipped")]
    assert ran
    for st in ran:
        r = c.get(f"/api/v1/scans/{scan['id']}/stages/{st['id']}/output", headers=h)
        assert r.status_code == 200, r.text
        out = r.json()
        text = [x[2] for x in out["head"] + out["tail"]]
        assert out["final"] and text[0].startswith("Stage started") and text[-1].startswith("Stage finished")
        blob = json.dumps(out).lower()
        assert [n for n in FORBIDDEN if n in blob] == [], (st["label"], blob[:400])
        assert "topsecret123" not in blob and "v9.9.9" not in blob and "/opt/asm" not in blob
    detection = next(s for s in ran if s["stage_type"] == "vulnerability_detection")
    out = c.get(f"/api/v1/scans/{scan['id']}/stages/{detection['id']}/output", headers=h).json()
    lines = [x for x in out["head"]]
    assert any(x[1] == "warning" and "target(s) queued" in x[2] for x in lines)
    assert any("api_key=[redacted]" in x[2] for x in lines)
    txt = c.get(f"/api/v1/scans/{scan['id']}/stages/{detection['id']}/output.txt", headers=h)
    assert txt.status_code == 200 and txt.text.startswith("# ") and "WARNING" in txt.text
    assert [n for n in FORBIDDEN if n in txt.text.lower()] == []


def test_another_tenant_cannot_read_the_output(env):
    c = env["c"]
    scan = _scan(c, env["alpha"])
    st = scan["stages"][0]
    assert c.get(f"/api/v1/scans/{scan['id']}/stages/{st['id']}/output", headers=env["bravo"]).status_code == 404
    assert c.get(f"/api/v1/scans/{scan['id']}/stages/{st['id']}/output.txt", headers=env["bravo"]).status_code == 404


def _stage(system_db, scan_id):
    from app.models import ScanStage

    return system_db.query(ScanStage).filter(ScanStage.scan_id == uuid.UUID(scan_id)).order_by(ScanStage.position).first()


def _job(stage, tenant_id, job_id=None):
    return SensorJob(job_id=job_id or stage.task_id, tenant_id=str(tenant_id), scan_id=str(stage.scan_id),
                     stage_id=str(stage.id), adapter=stage.engine,
                     targets=[Target(kind=TargetKind.HOSTNAME, value="example.com")])


def test_only_the_dispatched_job_from_its_pool_may_add_output_and_only_while_it_is_recent(env, system_db):
    from app.core import crypto
    from app.models import ScanStage, ScanStageOutput
    from app.scans import output

    c = env["c"]
    scan = _scan(c, env["alpha"])
    stage = _stage(system_db, scan["id"])
    key = crypto.pool_transport_key("default")
    chunk = {"seq": 99, "head": [[1.0, "info", "late but fine"]], "total": 1, "omitted": 0, "final": False}
    # Wrong key (another pool's), wrong job id, another tenant: all refused.
    assert not output.receive(seal_log(_job(stage, env["ta"].id), chunk, "default", b"x" * 32))
    assert not output.receive(seal_log(_job(stage, env["ta"].id, "someone-else"), chunk, "default", key))
    assert not output.receive(seal_log(_job(stage, env["tb"].id), chunk, "default", key))
    # The real job, just after its stage finished: accepted (chunks may trail the result).
    assert output.receive(seal_log(_job(stage, env["ta"].id), chunk, "default", key))
    system_db.expire_all()
    row = system_db.get(ScanStageOutput, stage.id)
    assert row.head[-1][2] == "late but fine" and row.last_seq == 99
    # A duplicate or older chunk changes nothing.
    assert output.receive(seal_log(_job(stage, env["ta"].id), {**chunk, "seq": 5, "head": [[2, "info", "old"]]},
                                   "default", key))
    system_db.expire_all()
    assert system_db.get(ScanStageOutput, stage.id).head[-1][2] == "late but fine"
    # Long after the stage ended: stale.
    system_db.execute(update(ScanStage).where(ScanStage.id == stage.id).values(
        finished_at=datetime.now(UTC) - timedelta(hours=1)))
    system_db.commit()
    assert not output.receive(seal_log(_job(stage, env["ta"].id), {**chunk, "seq": 100}, "default", key))


def test_the_platform_cleans_again_and_keeps_its_own_bounds(env, system_db):
    """A scanner is not trusted to have cleaned its output."""
    from app.core import crypto
    from app.models import ScanStageOutput
    from app.scans import output

    c = env["c"]
    scan = _scan(c, env["alpha"])
    stage = _stage(system_db, scan["id"])
    system_db.query(ScanStageOutput).filter(ScanStageOutput.stage_id == stage.id).delete()
    system_db.commit()
    key = crypto.pool_transport_key("default")
    dirty = [[0.5, "info", "nuclei says hi from /opt/asm/bin/nuclei"], [0.6, "bogus-level", "Authorization: Bearer abcdefgh12345"]]
    seq = 1
    output.receive(seal_log(_job(stage, env["ta"].id), {"seq": seq, "head": dirty, "total": 2, "omitted": 0}, "default", key))
    for _ in range(6):  # 6 × 400 lines: more than the platform keeps at the head
        seq += 1
        output.receive(seal_log(_job(stage, env["ta"].id), {"seq": seq, "head": [[1, "info", "x"]] * 400,
                                                             "total": 2 + 400 * (seq - 1), "omitted": 0}, "default", key))
    system_db.expire_all()
    row = system_db.get(ScanStageOutput, stage.id)
    assert row.head[0][2] == "engine says hi from [path]" and row.head[1] == [0.6, "info", "Authorization: [redacted]"]
    assert len(row.head) == stagelog.HEAD
