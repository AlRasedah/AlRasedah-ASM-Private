"""Tests for the sensor framework: targets, safe execution, run() semantics, sealing, registry."""

from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

import pytest

from asm_sensors.base import ExecutionContext, RawOutput, write_targets_file
from asm_sensors.execution import ExecutionError, ProcessResult, resolve_binary, run_process
from asm_sensors.jobs import SealingError, SensorJob, seal_credentials, unseal_credentials
from asm_sensors.ports import count_ports, normalize_spec, port_in_spec, validate_port_spec
from asm_sensors.registry import adapter_names, describe_adapters, get_adapter
from asm_sensors.runner import execute_job
from asm_sensors.targets import InvalidTarget, Target, TargetKind, validate_cidr

from .helpers import fixture_bytes


class TestTargets:
    @pytest.mark.parametrize("value", ["-oG.example.com", "a b.example.com", "example.com;id", "$(id).example.com",
                                       "*.example.com", "exa\nmple.com", "localhost", ""])
    def test_rejects_unsafe_hostnames(self, value):
        with pytest.raises((InvalidTarget, ValueError)):
            Target(kind=TargetKind.HOSTNAME, value=value)

    def test_normalizes(self):
        assert Target(kind="hostname", value="WWW.Example.COM.").value == "www.example.com"
        assert Target(kind="hostname", value="bücher.example").value == "xn--bcher-kva.example"
        assert Target(kind="ip", value="2001:0db8::0001").value == "2001:db8::1"
        assert Target(kind="host_port", value="[2001:db8::1]:443").value == "[2001:db8::1]:443"
        assert Target(kind="url", value="https://Example.com:8443/a").value == "https://example.com:8443/a"

    def test_url_rules(self):
        for bad in ["file:///etc/passwd", "https://user:pw@example.com", "gopher://example.com"]:
            with pytest.raises((InvalidTarget, ValueError)):
                Target(kind="url", value=bad)

    def test_cidr_size_limit(self):
        assert validate_cidr("192.0.2.0/24") == "192.0.2.0/24"
        with pytest.raises(InvalidTarget):
            validate_cidr("10.0.0.0/8")

    def test_targets_file(self, tmp_path):
        p = write_targets_file(tmp_path, [Target(kind="hostname", value="b.example.com"),
                                          Target(kind="hostname", value="a.example.com"),
                                          Target(kind="hostname", value="a.example.com")])
        assert p.read_text().splitlines() == ["a.example.com", "b.example.com"]


class TestPorts:
    def test_specs(self):
        assert normalize_spec("443,80,81-85,82") == "80-85,443"
        assert port_in_spec(83, "80-85,443") and not port_in_spec(8443, "80-85,443")
        assert count_ports("1-1024") == 1024
        for bad in ["80;id", "0-10", "1-70000", "a"]:
            with pytest.raises(ValueError):
                validate_port_spec(bad)


class TestExecution:
    async def test_runs_without_shell(self, tmp_path):
        # A shell metacharacter in an argument is passed literally, not interpreted.
        res = await run_process([sys.executable, "-c", "import sys; print(sys.argv[1])", "hello; echo pwned"],
                                timeout=30, cwd=str(tmp_path))
        assert res.ok and res.stdout.strip() == b"hello; echo pwned"

    async def test_timeout_kills(self, tmp_path):
        res = await run_process([sys.executable, "-c", "import time; time.sleep(30)"], timeout=1, cwd=str(tmp_path))
        assert res.timed_out and not res.ok

    async def test_output_cap(self, tmp_path):
        res = await run_process([sys.executable, "-c", "print('x' * 100000)"], timeout=30, cwd=str(tmp_path),
                                max_output_bytes=1000)
        assert len(res.stdout) == 1000 and res.stdout_truncated

    async def test_rejects_nul(self):
        with pytest.raises(ExecutionError):
            await run_process(["echo", "a\x00b"], timeout=5)

    def test_allowlist(self):
        with pytest.raises(ExecutionError):
            resolve_binary("bash", ("amass",))


class TestRunSemantics:
    async def test_failed_process_drops_coverage(self, tmp_path, monkeypatch):
        adapter = get_adapter("dnsx")

        async def fake_execute(targets, config, ctx):
            proc = ProcessResult(argv=["dnsx"], returncode=1, stdout=b"", stderr=b"boom", duration=0.1)
            return RawOutput(process=proc, files={"dnsx.jsonl": fixture_bytes("dnsx.jsonl")})

        async def ok(config, ctx):
            return None

        monkeypatch.setattr(adapter, "execute", fake_execute)
        monkeypatch.setattr(adapter, "validate_configuration", ok)
        res = await adapter.run([Target(kind="hostname", value="api.example.com")], {}, ExecutionContext(workdir=tmp_path))
        assert res.status == "partial"
        assert res.observations and res.coverage == []  # partial runs never vouch for absence
        assert any("exit code 1" in e for e in res.errors)

    async def test_successful_run_keeps_coverage_and_artifact(self, tmp_path, monkeypatch):
        adapter = get_adapter("dnsx")

        async def fake_execute(targets, config, ctx):
            proc = ProcessResult(argv=["dnsx"], returncode=0, stdout=b"", stderr=b"", duration=0.1)
            return RawOutput(process=proc, files={"dnsx.jsonl": fixture_bytes("dnsx.jsonl")})

        async def ok(config, ctx):
            return None

        monkeypatch.setattr(adapter, "execute", fake_execute)
        monkeypatch.setattr(adapter, "validate_configuration", ok)
        ctx = ExecutionContext(workdir=tmp_path, retain_raw_output=True)
        res = await adapter.run([Target(kind="hostname", value="api.example.com")], {}, ctx)
        assert res.status == "completed" and res.coverage
        assert res.artifacts and res.artifacts[0].size == len(fixture_bytes("dnsx.jsonl"))

    async def test_rate_limits_are_clamped(self, tmp_path):
        adapter = get_adapter("httpx")
        cfg = adapter.apply_limits(adapter.parse_config({"rate_limit": 5000}), ExecutionContext(workdir=tmp_path, max_rate=100))
        assert cfg.rate_limit == 100

    async def test_missing_binary_is_a_clean_failure(self, monkeypatch):
        monkeypatch.setenv("PATH", "")
        job = SensorJob(job_id="j", tenant_id="t", scan_id="s", stage_id="st", adapter="naabu",
                        targets=[Target(kind="ip", value="192.0.2.1")])
        res = await execute_job(job)
        assert res.status == "failed" and "not installed" in res.errors[0]

    async def test_unknown_adapter(self):
        job = SensorJob(job_id="j", tenant_id="t", scan_id="s", stage_id="st", adapter="nope", targets=[])
        assert (await execute_job(job)).status == "failed"

    async def test_wrong_target_kind(self):
        job = SensorJob(job_id="j", tenant_id="t", scan_id="s", stage_id="st", adapter="naabu",
                        targets=[Target(kind="hostname", value="example.com")])
        res = await execute_job(job)
        assert res.status == "failed" and "does not accept" in res.errors[0]


class TestSealing:
    def test_roundtrip_and_binding(self):
        key = os.urandom(32)
        token = seal_credentials({"shodan": ["k1"]}, "job-1", key)
        assert "k1" not in base64.urlsafe_b64decode(token).decode("latin-1")
        assert unseal_credentials(token, "job-1", key) == {"shodan": ["k1"]}
        with pytest.raises(SealingError):
            unseal_credentials(token, "job-2", key)  # bound to the job id


class TestRegistry:
    def test_builtins_registered(self):
        names = adapter_names()
        for n in ("amass", "subfinder", "crtsh", "dnsx", "asnlookup", "naabu", "httpx", "nuclei", "spiderfoot",
                  "bbot", "zap_spider", "zap_active"):
            assert n in names
        described = {d["name"]: d for d in describe_adapters()}
        assert described["naabu"]["active"] is True
        assert "properties" in described["nuclei"]["config_schema"]
        # ZAP DAST engines are active and cover the crawl / vulnerability stages.
        assert described["zap_spider"]["active"] is True
        assert "web_crawl" in described["zap_spider"]["stage_types"]
        assert "vulnerability_detection" in described["zap_active"]["stage_types"]


def test_path_helper(tmp_path: Path):
    assert tmp_path.exists()
