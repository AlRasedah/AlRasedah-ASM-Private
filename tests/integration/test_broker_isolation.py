"""Broker trust boundary against a real Valkey/Redis and real Celery workers (audit A01).

Applies the scanner ACL exactly as written in docker-compose.yml, then runs a
sensor worker as that user and the platform's result consumer, and checks that

* a job flows platform -> sensor worker -> results.<pool> without any ACL denial,
* the sensor worker's user cannot touch the platform's queue, other pools' queues,
  results or bookkeeping, or run administrative commands,
* the result consumer refuses anything but result submission (platform tasks and
  Celery built-ins such as ``celery.group`` sent to it are discarded),
* a redelivered job is not executed twice, and revocation reaches the pool.

Needs a *disposable* server (database 0 is flushed): set ASM_TEST_BROKER_ADMIN_URL,
e.g. ``redis://:secret@127.0.0.1:56379/0``. Skipped otherwise.
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

ADMIN_URL = os.environ.get("ASM_TEST_BROKER_ADMIN_URL")
pytestmark = pytest.mark.skipif(not ADMIN_URL, reason="set ASM_TEST_BROKER_ADMIN_URL to a disposable Valkey/Redis")

ROOT = Path(__file__).resolve().parents[2]
SCANNER_PASSWORD = "scanner-" + uuid.uuid4().hex
MASTER = os.urandom(32)


def _compose_acl() -> tuple[str, list[str]]:
    import yaml

    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    cmd = compose["services"]["redis"]["command"]
    i = cmd.index("--user")
    rest = cmd[i + 1:]
    end = next((j for j, tok in enumerate(rest) if tok.startswith("--")), len(rest))
    name, *rules = rest[:end]
    rules = [re.sub(r"\$\{ASM_SCANNER_REDIS_PASSWORD[^}]*\}", SCANNER_PASSWORD, r) for r in rules]
    assert not any("${" in r for r in rules), rules
    return name, rules


def _scanner_url() -> str:
    host = ADMIN_URL.split("@", 1)[-1] if "@" in ADMIN_URL else ADMIN_URL.split("//", 1)[1]
    return f"redis://scanner-default:{SCANNER_PASSWORD}@{host}"


@pytest.fixture(scope="module")
def broker():
    import redis

    admin = redis.Redis.from_url(ADMIN_URL)
    admin.flushdb()
    name, rules = _compose_acl()
    assert name == "scanner-default"
    admin.execute_command("ACL", "SETUSER", name, "reset", *rules)
    admin.execute_command("ACL", "LOG", "RESET")
    yield admin
    admin.execute_command("ACL", "DELUSER", name)


def _env(**extra: str) -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT / "workers"), str(ROOT / "backend"), env.get("PYTHONPATH", "")])
    env.update(extra)
    return env


def _start(args: list[str], env: dict[str, str], log: Path) -> subprocess.Popen:
    fh = log.open("wb")
    return subprocess.Popen([sys.executable, "-m", "celery", *args], env=env, stdout=fh,  # noqa: S603
                            stderr=subprocess.STDOUT, cwd=str(ROOT))


def _wait(predicate, timeout: float = 45.0, what: str = "condition") -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.25)
    raise AssertionError(f"timed out waiting for {what}")


def _core_app():
    from celery import Celery

    app = Celery("test-core", broker=ADMIN_URL, set_as_current=False)
    app.conf.update(broker_transport_options={"priority_steps": [0], "visibility_timeout": 21600},
                    task_serializer="json", accept_content=["json"])
    return app


def _job(job_id: str):
    from asm_sensors.jobs import SensorJob
    from asm_sensors.targets import Target, TargetKind

    # An engine the worker does not have: it fails fast, locally, with no network traffic.
    return SensorJob(job_id=job_id, tenant_id=str(uuid.uuid4()), scan_id=str(uuid.uuid4()),
                     stage_id=str(uuid.uuid4()), adapter="no-such-engine",
                     targets=[Target(kind=TargetKind.HOSTNAME, value="example.com")])


def _decode(raw: bytes) -> tuple[str, list]:
    msg = json.loads(raw)
    body = json.loads(base64.b64decode(msg["body"]))
    return msg["headers"]["task"], body[0]


def test_sensor_pool_is_confined(broker, tmp_path):
    import redis
    from asm_sensors.jobs import open_result, pool_key

    key = pool_key(MASTER, "default")
    scanner = _start(["-A", "asm_sensors.worker", "worker", "-Q", "scanners.default", "--pool", "solo",
                      "--without-gossip", "--without-mingle", "--without-heartbeat", "-l", "INFO",
                      "--hostname", "sensor-test@%h"],
                     _env(ASM_CELERY_BROKER_URL=_scanner_url(), ASM_SENSOR_POOL="default",
                          ASM_SCANNER_TRANSPORT_KEY=base64.urlsafe_b64encode(key).decode()),
                     tmp_path / "scanner.log")
    try:
        core = _core_app()
        job = _job(uuid.uuid4().hex)
        core.send_task("asm.sensors.run", args=[job.model_dump(mode="json")], task_id=job.job_id,
                       queue="scanners.default")
        _wait(lambda: broker.llen("results.default") >= 1, what="the sensor result")
        task, args = _decode(broker.rpop("results.default"))
        assert task == "asm.results.submit"
        env, result = open_result(args[0], lambda pool: pool_key(MASTER, pool))
        assert env.job_id == job.job_id and env.pool == "default" and result.status == "failed"

        # A redelivery of the same job is not executed again.
        core.send_task("asm.sensors.run", args=[job.model_dump(mode="json")], task_id=job.job_id,
                       queue="scanners.default")
        _wait(lambda: b"already claimed" in (tmp_path / "scanner.log").read_bytes(), what="the duplicate check")
        assert broker.llen("results.default") == 0

        # Revocation reaches the pool on its own control channel.
        from celery import Celery

        ctl = Celery("test-control", broker=ADMIN_URL, set_as_current=False)
        ctl.conf.update(control_exchange="asm-default", broker_transport_options={"priority_steps": [0]})
        ctl.control.revoke("some-task-id")
        _wait(lambda: b"some-task-id" in (tmp_path / "scanner.log").read_bytes(), what="the revocation")

        # Normal operation needed no permission the ACL does not grant.
        denials = broker.execute_command("ACL", "LOG")
        assert denials == [], denials
    finally:
        scanner.terminate()
        scanner.wait(20)
    log = (tmp_path / "scanner.log").read_text(errors="replace")
    assert "NOPERM" not in log and "NoPermissionError" not in log, log[-3000:]

    # What a compromised sensor worker of pool "default" can and cannot do.
    r = redis.Redis.from_url(_scanner_url())
    denied = [
        lambda: r.lpush("core", "x"),                       # inject platform tasks
        lambda: r.lrange("scanners.other", 0, -1),          # read another pool's jobs (and credentials)
        lambda: r.lpush("scanners.other", "x"),
        lambda: r.lpush("results.other", "x"),              # submit as another pool
        lambda: r.hgetall("unacked.core"),                  # read in-flight platform messages
        lambda: r.hgetall("unacked"),
        lambda: r.hgetall("unacked.scanners.other"),
        lambda: r.get("celery-task-meta-x"),                # platform result backend
        lambda: r.sadd("_kombu.binding.core", "x"),         # re-route platform publishing
        lambda: r.set("asm.pool.other.lease", "x"),         # another pool's coordination keys
        lambda: r.publish("/0.celery.pidbox", "x"),         # the default control channel
        lambda: r.publish("/0.asm-other.pidbox", "x"),      # another pool's control channel
        lambda: r.keys("*"),
        lambda: r.scan(0),
        lambda: r.config_get("*"),
        lambda: r.flushdb(),
        lambda: r.eval("return redis.call('lpush', KEYS[1], 'x')", 1, "core"),
        lambda: r.eval("return redis.call('lpush', 'core', 'x')", 0),
        lambda: r.execute_command("ACL", "LIST"),
    ]
    for i, attempt in enumerate(denied):
        # Denials inside a Lua script surface as a generic "ACL failure in script" error.
        with pytest.raises(redis.exceptions.ResponseError, match="(?i)no permissions"):
            attempt()
            pytest.fail(f"denied operation #{i} was allowed")
    assert r.set("asm.pool.default.probe", "1") and r.lpush("results.default", "x")
    assert broker.llen("core") == 0
    broker.delete("results.default")

    import asyncio

    from asm_sensors.coordination import RedisCoordinator

    async def lease():
        async with RedisCoordinator(_scanner_url(), "asm.pool.default.").lease("zap:test", ttl=5, wait=2):
            assert broker.get("asm.pool.default.zap:test")
        assert broker.get("asm.pool.default.zap:test") is None

    asyncio.run(lease())


def test_result_consumer_runs_nothing_but_result_submission(broker, tmp_path):
    from celery import Celery

    consumer = _start(["-A", "app.workers.results:results_app", "worker", "--pool", "solo", "--without-gossip",
                       "--without-mingle", "-l", "INFO", "--hostname", "ingest-test@%h"],
                      _env(ASM_REDIS_URL=ADMIN_URL, ASM_WORKER_POOLS="default",
                           ASM_SCANNER_TRANSPORT_KEY=base64.urlsafe_b64encode(MASTER).decode()),
                      tmp_path / "ingest.log")
    try:
        log = tmp_path / "ingest.log"
        _wait(lambda: b"ready" in log.read_bytes(), what="the result consumer")
        # A compromised sensor worker, using its own broker user, targets the consumer.
        rogue = Celery("rogue", broker=_scanner_url(), set_as_current=False)
        rogue.conf.update(broker_transport_options={"priority_steps": [0]})
        start = {"task": "asm.core.start_scan", "args": [str(uuid.uuid4())], "kwargs": {},
                 "options": {"queue": "core"}, "subtask_type": None, "immutable": False}
        rogue.send_task("asm.core.start_scan", args=[str(uuid.uuid4())], queue="results.default")
        rogue.send_task("celery.group", args=[[start], ["gid", None], "gid", []], queue="results.default")
        rogue.send_task("celery.map", args=[start, [[1]]], queue="results.default")
        rogue.send_task("asm.results.submit", args=[{"job_id": "forged"}], queue="results.default")
        _wait(lambda: log.read_bytes().count(b"unregistered task") >= 3, what="the rogue messages to be refused")
        _wait(lambda: b"rejected sensor result" in log.read_bytes(), what="the forged result to be rejected")
        time.sleep(1)
        assert broker.llen("core") == 0 and not broker.exists("core")
    finally:
        consumer.terminate()
        consumer.wait(20)
