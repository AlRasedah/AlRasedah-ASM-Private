"""Structured logging: schema, redaction, non-blocking writes, correlation, exports.

Real PostgreSQL with RLS for the exports and scans; no network, no real engines.
"""

from __future__ import annotations

import contextlib
import io
import json
import logging
import threading
import time
import uuid

import pytest
from asm_sensors import eventlog
from fastapi.testclient import TestClient
from sqlalchemy import select

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"


class Capture(logging.Handler):
    """Collects formatted events (the exact JSON a native install writes)."""

    def __init__(self) -> None:
        super().__init__()
        self.fmt = eventlog.EventFormatter("test", "0")
        self.events: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.events.append(json.loads(self.fmt.format(record)))


@pytest.fixture
def captured():
    cap = Capture()
    root = logging.getLogger()
    root.addHandler(cap)
    old = root.level
    root.setLevel(logging.INFO)
    yield cap
    root.removeHandler(cap)
    root.setLevel(old)


# ------------------------------------------------------------------ schema, redaction
def test_events_follow_the_schema_and_keep_only_allowlisted_fields():
    rec = logging.LogRecord("exteriq.scans", logging.WARNING, "", 0, "stage %s", ("dns",), None)
    for k, v in {"event": "scan.stage.finished", "stream": "scans", "tenant_id": str(uuid.uuid4()), "severity": "high",
                 "duration_ms": 12, "something_unknown": "leak me", "error_code": "ASM-SCAN-002"}.items():
        setattr(rec, k, v)
    ev = json.loads(eventlog.EventFormatter("worker", "9.9").format(rec))
    assert ev["schema"] == "exteriq.event/1" and ev["event"] == "scan.stage.finished" and ev["stream"] == "scans"
    assert ev["level"] == "WARNING" and ev["severity"] == "high"  # operational level ≠ finding severity
    assert ev["service"] == "worker" and ev["version"] == "9.9" and len(ev["event_id"]) == 32
    assert ev["ts"].endswith("Z") and ev["msg"] == "stage dns" and ev["duration_ms"] == 12
    assert "something_unknown" not in ev and "leak me" not in json.dumps(ev) and ev["dropped_fields"] == 1


def test_secrets_are_removed_everywhere_in_the_event():
    secrets = ["hunter2", "S3cr3tT0ken", "abc.def.ghi-cookie", "AKIAsecretapikey", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345678"]
    msg = ("connect postgresql://asm:hunter2@db:5432/asm then GET https://api.example.com/x?token=S3cr3tT0ken&page=2 "
           "with Cookie: session=abc.def.ghi-cookie and Authorization: Bearer AKIAsecretapikey jwt "
           "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig12345678")
    try:
        raise RuntimeError("login failed for password=hunter2")
    except RuntimeError:
        import sys

        exc = sys.exc_info()
    rec = logging.LogRecord("app", logging.ERROR, "", 0, msg, (), exc)
    rec.data = {"cookie": "abc.def.ghi-cookie", "nested": {"api_key": "AKIAsecretapikey",
                                                          "url": "https://u:hunter2@h.example.com/?secret=S3cr3tT0ken"},
                "list": ["Bearer AKIAsecretapikey", {"password": "hunter2"}]}
    line = eventlog.EventFormatter("api", "1").format(rec)
    for s in secrets:
        assert s not in line, s
    ev = json.loads(line)
    assert ev["exc"]["type"] == "RuntimeError" and "password=[redacted]" in ev["exc"]["message"]
    assert ev["data"]["cookie"] == "[redacted]" and ev["data"]["nested"]["api_key"] == "[redacted]"
    assert "page=2" in ev["msg"] and "api.example.com" in ev["msg"]  # useful context survives


def test_an_oversized_event_is_truncated_not_dropped():
    rec = logging.LogRecord("app", logging.INFO, "", 0, "x" * 100_000, (), None)
    rec.data = {"blob": "y" * 50_000}
    line = eventlog.EventFormatter("api", "1").format(rec)
    assert len(line.encode()) <= eventlog.MAX_EVENT_BYTES and json.loads(line)["truncated"] is True


# ------------------------------------------------------------------ non-blocking writer
class Gate(io.StringIO):
    """A stdout that hangs until released (a stalled collector)."""

    def __init__(self) -> None:
        super().__init__()
        self.open = threading.Event()

    def write(self, s: str) -> int:
        self.open.wait(30)
        return super().write(s)


def test_a_stalled_stdout_never_blocks_the_caller_and_drops_are_counted(monkeypatch):
    monkeypatch.setattr(eventlog, "QUEUE_SIZE", 50)
    gate = Gate()
    writer = eventlog._Writer(gate)
    handler = eventlog._QueueHandler(writer.q)
    handler.setFormatter(eventlog.EventFormatter("worker", "1"))
    log = logging.getLogger("stall-test")
    log.addHandler(handler)
    log.propagate = False
    try:
        t0 = time.monotonic()
        for i in range(500):
            log.warning("event %d", i)
        assert time.monotonic() - t0 < 2.0  # returned although nothing could be written
        assert writer.q.full()  # nothing more fits; the rest were dropped (and counted)
        gate.open.set()
        time.sleep(0.2)
        log.warning("after the stall")
        deadline = time.monotonic() + 5
        while "after the stall" not in gate.getvalue() and time.monotonic() < deadline:
            time.sleep(0.05)
        out = [json.loads(x) for x in gate.getvalue().splitlines()]
        drops = [e for e in out if e["event"] == "logging.events_dropped"]
        assert sum(e["count"] for e in drops) >= 400 and {e["error_code"] for e in drops} == {"ASM-OPS-003"}
        assert out[-1]["msg"] == "after the stall"
    finally:
        log.removeHandler(handler)
        gate.open.set()
        with contextlib.suppress(Exception):
            writer.q.put_nowait(None)


class SlowStream(io.StringIO):
    """A stdout that writes in small pieces and yields between them, as a pipe may."""

    def write(self, s: str) -> int:
        for i in range(0, len(s), 7):
            super().write(s[i:i + 7])
            time.sleep(0)
        return len(s)


def test_concurrent_writers_never_interleave_lines(monkeypatch):
    stream = SlowStream()
    writer = eventlog._Writer(stream)
    monkeypatch.setattr(eventlog, "_writer", writer)
    handler = eventlog._QueueHandler(writer.q)
    handler.setFormatter(eventlog.EventFormatter("worker", "1"))
    log = logging.getLogger("concurrency-test")
    log.addHandler(handler)
    log.propagate = False

    def queued(n: int) -> None:
        for i in range(200):
            log.warning("queued %d-%d %s", n, i, "x" * (i % 50))

    def direct(n: int) -> None:
        for i in range(200):
            assert eventlog.write_sync("exteriq.alerts", logging.INFO, f"direct {n}-{i}", stream="alerts")

    try:
        threads = [threading.Thread(target=f, args=(n,)) for n in range(4) for f in (queued, direct)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        deadline = time.monotonic() + 10
        while stream.getvalue().count("\n") < 1600 and time.monotonic() < deadline:
            time.sleep(0.05)
        lines = stream.getvalue().splitlines()
        assert len(lines) == 1600
        assert all(json.loads(x)["schema"] == eventlog.SCHEMA for x in lines)  # every line whole
    finally:
        log.removeHandler(handler)
        writer.close()


# ------------------------------------------------------------------ correlation
def test_task_context_comes_from_headers_for_correlation_only_and_never_leaks():
    from app.observability import celery_hooks

    class Task:
        name = "asm.core.advance_scan"

        def __init__(self, header):  # noqa: ANN001
            self.request = type("R", (), {celery_hooks.HEADER: header})()

    token = eventlog.bind(request_id="req1", correlation_id="req1", tenant_id=str(uuid.uuid4()))
    headers: dict = {}
    celery_hooks._publish(headers=headers)
    eventlog.reset(token)
    assert headers[celery_hooks.HEADER]["correlation_id"] == "req1" and "tenant_id" not in headers[celery_hooks.HEADER]
    forged = {**headers[celery_hooks.HEADER], "tenant_id": str(uuid.uuid4())}  # a header can't carry identity
    celery_hooks._prerun(task_id="t1", task=Task(forged))
    ctx = eventlog.current()
    assert ctx["correlation_id"] == "req1" and ctx["task_id"] == "t1" and "tenant_id" not in ctx
    eventlog.annotate(tenant_id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()))  # loaded from the database
    celery_hooks._postrun()
    celery_hooks._prerun(task_id="t2", task=Task({}))
    ctx2 = eventlog.current()
    assert "tenant_id" not in ctx2 and "scan_id" not in ctx2 and ctx2["correlation_id"] == "t2"
    celery_hooks._postrun()


@pytest.fixture
def api(db_clean, factory, monkeypatch):
    from app.main import app

    FakeSensors(monkeypatch)
    ta, tb = factory.tenant("Alpha"), factory.tenant("Bravo")
    a = factory.user(ta.id, role="tenant_admin", password=PW)
    b = factory.user(tb.id, role="tenant_admin", password=PW)
    with TestClient(app) as c:
        def login(u):
            return {"Authorization": "Bearer " + c.post("/api/v1/auth/login", json={
                "email": u.email, "password": PW}).json()["access_token"]}

        yield {"c": c, "ta": ta, "tb": tb, "alpha": login(a), "bravo": login(b)}


def _scan(c, h, name):
    org = c.post("/api/v1/organizations", headers=h, json={"name": name}).json()
    c.post("/api/v1/scopes/bulk", headers=h, json={"organization_id": org["id"], "entries": ["example.com"]})
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=h).json()}
    return c.post("/api/v1/scans", headers=h, json={"organization_id": org["id"],
                                                   "profile_id": profiles["standard-asm"]["id"]}).json()


def test_scan_events_carry_the_right_tenant_ids_and_a_timeline(api, captured):
    c = api["c"]
    sa = _scan(c, api["alpha"], "Acme")
    sb = _scan(c, api["bravo"], "Beta")
    stages = [e for e in captured.events if e.get("event") == "scan.stage.finished"]
    finished = [e for e in captured.events if e.get("event") == "scan.finished"]
    assert stages and len(finished) == 2
    owner = {sa["id"]: str(api["ta"].id), sb["id"]: str(api["tb"].id)}
    for e in stages + finished:
        assert e["stream"] == "scans" and e["tenant_id"] == owner[e["scan_id"]]
    one = next(e for e in stages if e["status"] == "completed")
    assert {"queue_wait_ms", "execution_ms", "ingestion_ms", "coverage", "target_count"} <= set(one)
    assert one["coverage"] == "complete" and one["stage_id"] and one["job_id"]
    # Nothing a tenant sees is affected: the scan's own stage timing is also stored for Diagnostics.
    detail = c.get(f"/api/v1/scans/{sa['id']}", headers=api["alpha"]).json()
    assert "timing" in detail["stages"][0]["stats"]


def test_request_events_carry_request_and_authenticated_tenant_only(api, captured):
    c = api["c"]
    r = c.get("/api/v1/organizations", headers={**api["alpha"], "X-Request-ID": "abc123", "X-Tenant-ID":
                                                str(api["tb"].id)})
    assert r.status_code == 200 and r.headers["X-Request-ID"] == "abc123"
    logging.getLogger("app.test").warning("inside nothing")  # outside a request: no stale context
    last = captured.events[-1]
    assert "request_id" not in last and "tenant_id" not in last


# ------------------------------------------------------------------ exports
def test_finding_events_are_exported_once_retried_on_failure_and_never_for_rollbacks(api, system_db, monkeypatch):
    from app.models import Finding, FindingActivity
    from app.observability import export

    c = api["c"]
    _scan(c, api["alpha"], "Acme")  # the fake detections create findings (and activities)
    pending = system_db.scalar(select(FindingActivity.id).where(FindingActivity.exported_at.is_(None)).limit(1))
    assert pending is not None
    written: list[dict] = []
    monkeypatch.setattr(eventlog, "write_sync", lambda name, level, msg, **f: False)
    assert export.export_alerts(system_db)["exported"] == 0
    system_db.expire_all()
    assert system_db.get(FindingActivity, pending).exported_at is None  # nothing marked when the write failed

    def ok(name, level, msg, **f):  # noqa: ANN001
        written.append(f)
        return True

    monkeypatch.setattr(eventlog, "write_sync", ok)
    n = export.export_alerts(system_db)["exported"]
    assert n >= 1 and all(w["stream"] == "alerts" and w["event"].startswith("finding.") for w in written)
    ids = {w["event_id"] for w in written}
    assert pending.hex in ids and all(w["tenant_id"] == str(api["ta"].id) for w in written)
    assert export.export_alerts(system_db)["exported"] == 0  # exactly once per committed change
    # A change that is rolled back never becomes an event.
    f = system_db.scalar(select(Finding).limit(1))
    system_db.add(FindingActivity(tenant_id=f.tenant_id, finding_id=f.id, activity_type="status",
                                  previous={"status": "new"}, new={"status": "acknowledged"}))
    system_db.flush()
    system_db.rollback()
    written.clear()
    assert export.export_alerts(system_db)["exported"] == 0 and written == []


def test_audit_export_waits_for_late_commits_without_touching_the_chain(api, monkeypatch):
    from app.db.session import new_session, system_session
    from app.models import AuditLog
    from app.observability import export
    from app.services import audit

    written: list[dict] = []
    monkeypatch.setattr(eventlog, "write_sync", lambda name, level, msg, **f: written.append(f) or True)
    with system_session() as db:
        export.export_audit(db)  # catch up with the fixtures' own records
    written.clear()
    late = new_session(api["ta"].id)
    audit.record(late, "test.late", tenant_id=api["ta"].id, object_type="x", new={"n": 1})
    late.flush()  # has its id, not committed
    with new_session(api["tb"].id) as db:
        audit.record(db, "test.early", tenant_id=api["tb"].id, object_type="x", new={"n": 2})
        db.commit()
    with system_session() as db:
        export.export_audit(db)
    assert [w["action"] for w in written] == ["test.early"]
    late.commit()
    late.close()
    with system_session() as db:
        export.export_audit(db)
        rows = {r.action: r for r in db.execute(select(AuditLog).where(AuditLog.action.like("test.%"))).scalars()}
    assert [w["action"] for w in written] == ["test.early", "test.late"]
    assert written[1]["entry_hash"] == rows["test.late"].hash  # exported as recorded, chain untouched
