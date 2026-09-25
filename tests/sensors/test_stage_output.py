"""Verbose stage output, scanner side: cleaning, bounds, streaming, and its signed envelope."""

from __future__ import annotations

import asyncio
import sys

import pytest
from asm_sensors import stagelog
from asm_sensors.execution import run_process
from asm_sensors.jobs import (
    ResultRejected,
    SensorJob,
    open_log,
    open_result,
    seal_log,
    seal_result,
)
from asm_sensors.observations import SensorResult
from asm_sensors.stagelog import ENGINE_NAMES, StageLog, clean
from asm_sensors.targets import Target, TargetKind

KEY = b"k" * 32


def _leaks(text: str) -> list[str]:
    return [n for n in ENGINE_NAMES if n in text.lower()]


@pytest.mark.parametrize("raw", [
    "[INF] Current nuclei version: v3.3.2 (latest)",
    "[INF] Your current subfinder version v2.6.6 is outdated. Latest is v2.7.0",
    "    __  __  __  _  __  ",
    "   / /_/ /_/ /_ ____ | |/ /",
    "\t\tprojectdiscovery.io",
])
def test_banners_and_version_lines_are_dropped(raw):
    assert clean(raw) is None


def test_engine_names_paths_and_secrets_never_survive():
    cases = {
        "[INF] Using nuclei-templates from /data/nuclei-templates/http/cves": "the detection set",
        "[WRN] Running /opt/asm/bin/httpx with 50 threads": "[path]",
        "[ERR] Could not run nuclei: no templates provided for scan": "no templates provided",
        "GET https://api.example.com/?api_key=S3cr3tValue123 200": "api_key=[redacted]",
        "Authorization: Bearer abcdefghijklmnop": "authorization: [redacted]",
        "see https://docs.projectdiscovery.io/tools/nuclei/running for help": "[link removed]",
        "\x1b[31m[FTL]\x1b[0m zaproxy daemon unreachable": "engine daemon unreachable",
    }
    for raw, expected in cases.items():
        level, text = clean(raw)
        assert expected.lower() in text.lower(), (raw, text)
        assert _leaks(text) == [] and "S3cr3tValue123" not in text and "abcdefghijklmnop" not in text
    assert clean("[FTL] boom")[0] == "error" and clean("[WRN] careful")[0] == "warning"
    assert clean("[VER] sent request to https://x.example.com")[0] == "debug"
    # A credential the job carried is removed wherever it appears.
    assert "hunter2-cookie" not in clean("header X-Token: hunter2-cookie sent", ["hunter2-cookie"])[1]


def test_the_log_keeps_the_first_and_last_lines_and_counts_the_rest():
    log = StageLog()
    for i in range(10_000):
        log.add(f"line {i}")
    assert len(log.head) == stagelog.HEAD and len(log.tail) == stagelog.TAIL and log.omitted == 6000
    assert log.head[0][2] == "line 0" and log.tail[-1][2] == "line 9999"
    chunks = log.chunks(final=True)
    assert all(len(c["head"]) <= stagelog.CHUNK_LINES for c in chunks)
    assert [c["seq"] for c in chunks] == list(range(1, len(chunks) + 1))
    assert chunks[-1]["final"] and sum(len(c["head"]) for c in chunks) == stagelog.HEAD
    assert chunks[-1]["tail"][-1][2] == "line 9999" and chunks[-1]["omitted"] == 6000
    assert log.chunks() == []  # nothing new


def test_process_stderr_streams_into_the_running_stage_log():
    script = ("import sys\n"
              "for i in range(3000): print(f'[INF] nuclei probe {i}', file=sys.stderr)\n"
              "print('RESULT', flush=True)\n")

    async def go():
        log = StageLog()
        token = stagelog.CURRENT.set(log)
        try:
            proc = await run_process([sys.executable, "-c", script], timeout=60)
        finally:
            stagelog.CURRENT.reset(token)
        return log, proc

    log, proc = asyncio.run(go())
    assert proc.stdout.strip() == b"RESULT"  # results are untouched and never logged
    assert log.total == 3000 and log.head[0][2] == "engine probe 0" and log.tail[-1][2] == "engine probe 2999"
    assert all("RESULT" not in e[2] for e in log.head)


def test_execute_job_hands_chunks_to_the_sink_and_ends_with_a_final_one(monkeypatch):
    from asm_sensors import runner

    class Dummy:
        name = "dummy"

        def is_active(self, cfg):  # noqa: ANN001
            return False

        def parse_config(self, cfg):  # noqa: ANN001
            return cfg

        async def run(self, targets, config, ctx):  # noqa: ANN001
            stagelog.note("[INF] asking amass for names")
            await run_process([sys.executable, "-c", "import sys; print('[WRN] dnsx slow resolver', file=sys.stderr)"],
                              timeout=30)
            from datetime import UTC, datetime
            now = datetime.now(UTC)
            return SensorResult(adapter="dummy", status="partial", started_at=now, finished_at=now,
                                errors=["subfinder source timed out"])

    monkeypatch.setattr(runner, "get_adapter", lambda name: Dummy())
    sent: list[dict] = []
    job = SensorJob(job_id="j1", tenant_id="t", scan_id="s", stage_id="st", adapter="dummy",
                    targets=[Target(kind=TargetKind.HOSTNAME, value="example.com")], timeout_seconds=60)
    result = asyncio.run(runner.execute_job(job, log_sink=sent.append))
    assert result.status == "partial" and sent and sent[-1]["final"]
    lines = [e[2] for c in sent for e in c["head"]]
    assert lines[0] == "Stage started with 1 target(s)" and lines[-1].startswith("Stage finished: partial")
    assert "asking engine for names" in lines and "engine slow resolver" in lines
    assert "engine source timed out" in lines  # the error, cleaned too
    assert not any(_leaks(x) for x in lines)


def test_log_envelopes_are_signed_and_never_pass_for_results():
    job = SensorJob(job_id="j1", tenant_id="t", scan_id="s", stage_id="st", adapter="dummy",
                    targets=[Target(kind=TargetKind.HOSTNAME, value="example.com")])
    chunk = {"seq": 1, "head": [[0.1, "info", "hello"]], "total": 1, "omitted": 0, "final": False}
    env = seal_log(job, chunk, "default", KEY)
    got_env, got = open_log(env, lambda pool: KEY)
    assert got.head[0][2] == "hello" and got_env.stage_id == "st"
    tampered = {**env, "chunk": {**env["chunk"], "head": [[0.1, "info", "rm -rf"]]}}
    with pytest.raises(ResultRejected):
        open_log(tampered, lambda pool: KEY)
    with pytest.raises(ResultRejected):
        open_log(env, lambda pool: b"x" * 32)  # another pool's key
    with pytest.raises(ResultRejected):
        open_result(env, lambda pool: KEY)  # a log is not a result
    from datetime import UTC, datetime

    res = seal_result(job, SensorResult(adapter="dummy", started_at=datetime.now(UTC), finished_at=datetime.now(UTC)),
                      "default", KEY)
    with pytest.raises(ResultRejected):
        open_log(res, lambda pool: KEY)  # nor a result a log
    with pytest.raises(ValueError):
        seal_log(job, {**chunk, "head": [[0, "info", "x"]] * 401}, "default", KEY)  # bounded


def test_engines_run_in_verbose_mode():
    from asm_sensors.adapters.nuclei import NucleiAdapter, NucleiConfig

    argv = NucleiAdapter().build_argv("nuclei", "t.txt", "o.jsonl", NucleiConfig(), None)
    assert "-v" in argv and "-silent" not in argv
