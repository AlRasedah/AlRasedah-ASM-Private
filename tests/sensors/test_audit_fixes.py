"""Regression tests for the 2026-09-19 platform audit (sensor side).

Each test asserts the *desired* behaviour for a finding the audit reproduced
(A01 broker trust boundary, A02 destination checks, A03 ZAP origin regex,
A04 completeness/coverage, A10 ZAP daemon isolation, A11 redelivery).
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import re
from datetime import UTC, datetime
from unittest.mock import patch

import httpx
import pytest
from asm_sensors.adapters.dnsx import DnsxAdapter
from asm_sensors.adapters.zap import ZapActiveAdapter, ZapSpiderAdapter, _include_regex, _ZapClient
from asm_sensors.base import ExecutionContext, RawOutput, read_output_file, tool_output
from asm_sensors.coordination import LeaseLost, LeaseUnavailable, LocalCoordinator
from asm_sensors.execution import ProcessResult
from asm_sensors.jobs import (
    ResultRejected,
    SealingError,
    SensorJob,
    open_result,
    pool_key,
    seal_credentials,
    seal_result,
    unseal_credentials,
)
from asm_sensors.observations import SensorResult
from asm_sensors.runner import egress_filter
from asm_sensors.targets import Target, TargetKind


# ------------------------------------------------------------------ A03
class TestZapOriginRegex:
    def test_matches_only_the_exact_origin(self):
        rx = re.compile(_include_regex("https://example.com"))
        for ok in ("https://example.com", "https://example.com/", "https://example.com/a/b?x=1",
                   "https://example.com:443/login", "https://example.com?q", "https://example.com#frag"):
            assert rx.fullmatch(ok), ok
            assert rx.search(ok), ok  # anchored: search and fullmatch agree
        for bad in ("https://example.com.attacker.invalid/path", "https://example.com:8443/path",
                    "http://example.com/", "https://example.com@attacker.invalid/", "https://user@example.com/",
                    "https://attacker.invalid/https://example.com/", "https://sub.example.com/",
                    "https://example.company/"):
            assert not rx.search(bad), bad

    def test_non_default_ports_and_ipv6(self):
        rx = re.compile(_include_regex("https://example.com:8443/app"))
        assert rx.search("https://example.com:8443/app/x")
        assert not rx.search("https://example.com/app") and not rx.search("https://example.com:84430/")
        rx6 = re.compile(_include_regex("http://[2001:db8::1]:8080"))
        assert rx6.search("http://[2001:db8::1]:8080/x")
        assert not rx6.search("http://[2001:db8::1]/x") and not rx6.search("http://[2001:db8::10]:8080/")

    def test_rejects_non_http(self):
        with pytest.raises(ValueError):
            _include_regex("ftp://example.com")


# ------------------------------------------------------------------ A04
class TestCompleteness:
    async def test_unavailable_zap_fails_without_coverage(self, tmp_path):
        async def unavailable(*args, **kwargs):
            raise httpx.ConnectError("simulated offline daemon")

        ctx = ExecutionContext(workdir=tmp_path, settings={"zap_url": "http://unused.invalid"},
                               coordinator=LocalCoordinator())
        with patch.object(_ZapClient, "call", unavailable):
            result = await ZapActiveAdapter().run([Target(kind=TargetKind.URL, value="https://example.com")], {}, ctx)
        assert result.errors
        assert result.status == "failed"
        assert result.coverage == []

    async def test_truncated_output_is_partial_without_coverage(self, tmp_path):
        adapter = DnsxAdapter()

        async def execute(*args, **kwargs):
            return RawOutput(process=ProcessResult(argv=[], returncode=0, stdout=b"", stderr=b"", duration=1,
                                                   stdout_truncated=True))

        async def validate(*args, **kwargs):
            pass

        with patch.object(adapter, "execute", execute), patch.object(adapter, "validate_configuration", validate):
            result = await adapter.run([Target(kind=TargetKind.HOSTNAME, value="example.com")], {},
                                       ExecutionContext(workdir=tmp_path))
        assert result.status != "completed" and result.coverage == []

    async def test_truncated_output_file_is_flagged(self, tmp_path):
        out = tmp_path / "tool.jsonl"
        out.write_bytes(b'{"host":"a.example.com"}\n' * 100)
        data, truncated = read_output_file(out, 50)
        assert len(data) == 50 and truncated
        assert read_output_file(out, 10_000) == (out.read_bytes(), False)
        proc = ProcessResult(argv=[], returncode=0, stdout=b"", stderr=b"", duration=0)
        assert tool_output(out, proc, 50)[1] is True

    async def test_adapter_reporting_truncation_loses_coverage(self, tmp_path):
        adapter = DnsxAdapter()
        good = b'{"host":"a.example.com","a":["93.184.216.34"],"status_code":"NOERROR"}\n'

        async def execute(*args, **kwargs):
            proc = ProcessResult(argv=[], returncode=0, stdout=b"", stderr=b"", duration=1)
            return RawOutput(process=proc, files={"dnsx.jsonl": good}, truncated=True)

        async def validate(*args, **kwargs):
            pass

        with patch.object(adapter, "execute", execute), patch.object(adapter, "validate_configuration", validate):
            result = await adapter.run([Target(kind=TargetKind.HOSTNAME, value="a.example.com"),
                                        Target(kind=TargetKind.HOSTNAME, value="b.example.com")], {},
                                       ExecutionContext(workdir=tmp_path))
        # b.example.com may have been cut off: it must not be reported as gone.
        assert result.status == "partial" and result.observations and result.coverage == []

    async def test_zap_alert_limit_and_deadline_are_incomplete(self, tmp_path):
        zap = _ScriptedZap(alerts=[{"url": "https://app.example.com/x", "name": "A", "risk": "Low"}] * 3,
                           status="40")
        raw = RawOutput()
        cfg = ZapActiveAdapter().parse_config({"max_alerts": 3, "max_duration_minutes": 1, "poll_interval_seconds": 2})
        with patch("asm_sensors.adapters.zap.time.monotonic", _clock()), \
                patch("asm_sensors.adapters.zap.asyncio.sleep", _no_sleep):
            await ZapActiveAdapter()._scan_origin(zap, "https://app.example.com", ["https://app.example.com"],
                                                  cfg, raw, "ctx-1")
        assert any("did not finish" in e for e in raw.errors)
        assert any("alert limit" in e for e in raw.errors)
        assert ("ascan", "action", "stop") in zap.actions  # the remote scan is stopped, not left running

    async def test_zap_drops_alerts_from_other_origins(self, tmp_path):
        zap = _ScriptedZap(alerts=[{"url": "https://app.example.com/x", "name": "A", "risk": "Low"},
                                   {"url": "https://app.example.com.evil.test/x", "name": "B", "risk": "Low"},
                                   {"url": "https://app.example.com:8443/x", "name": "C", "risk": "Low"}])
        raw = RawOutput()
        await ZapActiveAdapter()._scan_origin(zap, "https://app.example.com", ["https://app.example.com"],
                                              ZapActiveAdapter().parse_config({}), raw, "ctx-1")
        assert [r["name"] for r in raw.records] == ["A"]


# ------------------------------------------------------------------ A10
class TestZapIsolation:
    async def test_jobs_on_one_daemon_are_serialized_in_fresh_sessions(self, tmp_path):
        """Two tenants' jobs against the same origin, with different credentials, never overlap."""
        log: list[tuple[str, str, str]] = []
        contexts: list[str] = []
        active: set[str] = set()
        overlap: list[bool] = []

        def make_call(job: str):
            async def call(self, component, kind, action, params=None, *, secret=False):
                params = params or {}
                log.append((job, component, action))
                if action == "newContext":
                    contexts.append(params["contextName"])
                if action == "newSession":
                    if job in active:
                        active.discard(job)
                    else:
                        overlap.append(bool(active))
                        active.add(job)
                if action == "addRule":
                    assert params["url"] == _include_regex("https://shared.example.com")
                if action == "newContext":
                    return {"contextId": "1"}
                if action == "scan":
                    await asyncio.sleep(0.05)  # give the other job a chance to interleave
                    return {"scan": "3"}
                if action == "status":
                    return {"status": "100"}
                if action == "alerts":
                    return {"alerts": []}
                return {}
            return call

        coordinator = LocalCoordinator(poll_interval=0.01)

        async def run(job: str, secret: str):
            ctx = ExecutionContext(workdir=tmp_path / job, settings={"zap_url": "http://zap:8090"},
                                   credentials={"zap_auth": [secret]}, coordinator=coordinator, job_id=job)
            adapter = ZapActiveAdapter()
            client_call = make_call(job)

            class Client(_ZapClient):
                call = client_call

            with patch("asm_sensors.adapters.zap._ZapClient", Client):
                return await adapter.execute([Target(kind=TargetKind.URL, value="https://shared.example.com")],
                                             adapter.parse_config({}), ctx)

        a, b = await asyncio.gather(run("tenant-a", "session=A"), run("tenant-b", "session=B"))
        assert not a.errors and not b.errors
        assert overlap == [False, False]  # the second job only started after the first had wiped the daemon
        for job in ("tenant-a", "tenant-b"):
            actions = [a for (j, _c, a) in log if j == job]
            assert actions[0] == "newSession" and actions[-1] == "newSession"  # fresh session in, wiped out
            assert "removeRule" in actions and "removeContext" in actions
        # Context / rule names are unique per job, not a reused "asm-ascan-0".
        assert sorted(contexts) == ["asm-tenant-a-0", "asm-tenant-b-0"]

    async def test_lease_times_out_instead_of_sharing(self):
        coordinator = LocalCoordinator(poll_interval=0.01)
        async with coordinator.lease("zap:x", ttl=60, wait=1):
            with pytest.raises(LeaseUnavailable):
                async with coordinator.lease("zap:x", ttl=60, wait=0.05):
                    pass
        async with coordinator.lease("zap:x", ttl=60, wait=0.05):  # released afterwards
            pass

    async def test_busy_daemon_fails_the_run_without_touching_zap(self, tmp_path):
        class Busy(LocalCoordinator):
            @contextlib.asynccontextmanager
            async def lease(self, name, *, ttl=120, wait=3600):
                raise LeaseUnavailable(name)
                yield  # pragma: no cover

        calls = []

        async def call(self, *args, **kwargs):
            calls.append(args)
            return {}

        ctx = ExecutionContext(workdir=tmp_path, settings={"zap_url": "http://zap:8090"}, coordinator=Busy())
        with patch.object(_ZapClient, "call", call):
            result = await ZapActiveAdapter().run([Target(kind=TargetKind.URL, value="https://a.example.com")], {}, ctx)
        assert calls == []
        assert result.status == "failed" and result.coverage == [] and "busy" in result.errors[0]

    async def test_spider_seeds_without_redirects(self, tmp_path):
        zap = _ScriptedZap()
        raw = RawOutput()
        await ZapSpiderAdapter()._crawl_one(zap, "https://app.example.com", ZapSpiderAdapter().parse_config({}), raw,
                                            "ctx-1")
        assert zap.params("accessUrl") == [{"url": "https://app.example.com", "followRedirects": "false"}]


# ------------------------------------------------------------------ A02
class TestEgressFilter:
    async def test_private_and_metadata_destinations_are_dropped(self):
        targets = [Target(kind=TargetKind.IP, value=v) for v in ("127.0.0.1", "10.0.0.1", "169.254.169.254",
                                                                  "100.64.0.1", "8.8.8.8")]
        targets.append(Target(kind=TargetKind.URL, value="http://192.168.1.10:8080/admin"))
        targets.append(Target(kind=TargetKind.CIDR, value="10.1.0.0/24"))
        kept, dropped = await egress_filter(targets, allow_non_public=False)
        assert [t.value for t in kept] == ["8.8.8.8"]
        assert len(dropped) == 6

    async def test_hostnames_are_checked_by_resolved_address(self, monkeypatch):
        answers = {"internal.example.com": {"10.0.0.5"}, "mixed.example.com": {"93.184.216.34", "127.0.0.1"},
                   "public.example.com": {"93.184.216.34"}, "excluded.example.com": {"203.0.113.9"}}

        async def fake_resolve(host, timeout=5.0):
            return {ipaddress.ip_address(a) for a in answers.get(host, set())}

        monkeypatch.setattr("asm_sensors.runner._resolve", fake_resolve)
        targets = [Target(kind=TargetKind.HOSTNAME, value=h) for h in answers]
        kept, dropped = await egress_filter(targets, allow_non_public=False,
                                            excluded=[ipaddress.ip_network("203.0.113.0/24")])
        assert [t.value for t in kept] == ["public.example.com"]
        assert any("excluded" in d for d in dropped)

    async def test_lab_deployments_can_allow_non_public(self):
        kept, dropped = await egress_filter([Target(kind=TargetKind.IP, value="10.0.0.1")], allow_non_public=True)
        assert kept and not dropped


# ------------------------------------------------------------------ A01
class TestPoolKeysAndResults:
    def _job(self) -> SensorJob:
        return SensorJob(job_id="j" * 32, tenant_id="t-1", scan_id="s-1", stage_id="st-1", adapter="dnsx",
                         targets=[Target(kind=TargetKind.HOSTNAME, value="example.com")])

    def _result(self) -> SensorResult:
        now = datetime.now(UTC)
        return SensorResult(adapter="dnsx", status="completed", started_at=now, finished_at=now, target_count=1,
                            stats={"ratio": 0.1, "n": 3}, errors=["ünïcode ✓"])

    def test_pool_keys_are_independent(self):
        master = os.urandom(32)
        a, b = pool_key(master, "default"), pool_key(master, "tenant-b")
        assert a != b and len(a) == 32 and pool_key(master, "default") == a
        token = seal_credentials({"zap_auth": ["secret"]}, "job-1", a)
        assert unseal_credentials(token, "job-1", a) == {"zap_auth": ["secret"]}
        with pytest.raises(SealingError):
            unseal_credentials(token, "job-1", b)  # another pool cannot open this pool's credentials
        with pytest.raises(ValueError):
            pool_key(master, "../core")

    def test_result_envelope_roundtrip(self):
        import json

        master = os.urandom(32)
        keys = lambda pool: pool_key(master, pool)  # noqa: E731
        env = seal_result(self._job(), self._result(), "default", keys("default"))
        wire = json.loads(json.dumps(env))  # what the broker delivers
        opened, result = open_result(wire, keys)
        assert opened.job_id == "j" * 32 and result.adapter == "dnsx" and result.errors == ["ünïcode ✓"]

    def test_forged_or_tampered_results_are_rejected(self):
        master = os.urandom(32)
        keys = lambda pool: pool_key(master, pool)  # noqa: E731
        # A worker of pool "rogue" signs with its own key but claims to be pool "default".
        forged = seal_result(self._job(), self._result(), "rogue", keys("rogue"))
        forged["pool"] = "default"
        with pytest.raises(ResultRejected):
            open_result(forged, keys)
        # Any change to the signed content (here: the stage it answers) breaks the MAC.
        env = seal_result(self._job(), self._result(), "default", keys("default"))
        env["stage_id"] = "another-stage"
        with pytest.raises(ResultRejected):
            open_result(env, keys)
        env = seal_result(self._job(), self._result(), "default", keys("default"))
        env["result"]["coverage"] = [{"kind": "liveness", "asset_type": "hostname", "values": ["x.example.com"]}]
        with pytest.raises(ResultRejected):
            open_result(env, keys)
        with pytest.raises(ResultRejected):
            open_result({"job_id": "x"}, keys)


# ------------------------------------------------------------------ A11
class TestClaims:
    def test_redelivered_job_is_claimed_once(self):
        c = LocalCoordinator()
        assert c.claim("job.1", ttl=60) and not c.claim("job.1", ttl=60) and c.claim("job.2", ttl=60)


# ------------------------------------------------------------------ helpers
class _ScriptedZap(_ZapClient):
    def __init__(self, alerts=None, status="100"):
        self.calls = []
        self._alerts = alerts or []
        self._status = status

    @property
    def actions(self):
        return [(c, k, a) for (c, k, a, _p) in self.calls]

    def params(self, action):
        return [p for (_c, _k, a, p) in self.calls if a == action]

    async def call(self, component, kind, action, params=None, *, secret=False):
        self.calls.append((component, kind, action, params or {}))
        if action == "newContext":
            return {"contextId": "5"}
        if action == "scan":
            return {"scan": "9"}
        if action == "status":
            return {"status": self._status}
        if action == "results":
            return {"results": []}
        if action == "recordsToScan":
            return {"recordsToScan": "0"}
        if action == "alerts":
            return {"alerts": list(self._alerts)}
        return {}


def _clock(step: float = 45.0):
    t = [0.0]

    def monotonic():
        t[0] += step
        return t[0]

    return monotonic


async def _no_sleep(_seconds):
    return None


class TestLostLeaseStopsTheHolder:
    """Review finding F3: losing the lease must stop the job that held it.

    The renewal loop ignored a false return and swallowed exceptions, so once a
    broker hiccup outlasted the TTL a second worker could take the lease while the
    first job was still driving the same ZAP daemon — resetting each other's
    sessions and mixing two tenants' traffic. Worse, the stale holder's cleanup
    would then wipe the new owner's session.
    """

    class _FlakyCoordinator(LocalCoordinator):
        """Acquires normally; renewal fails the way a broker outage would."""

        def __init__(self, *, raises: bool) -> None:
            super().__init__(poll_interval=0.01)
            self.raises = raises
            self.renewed = 0

        async def _renew(self, name: str, token: str, ttl: int) -> bool:
            self.renewed += 1
            if self.raises:
                raise ConnectionError("broker gone")
            return False

    @pytest.mark.parametrize("raises", [False, True], ids=["renewal_returns_false", "renewal_raises"])
    async def test_the_body_is_stopped_and_the_lease_is_not_handed_back(self, raises):
        coordinator = self._FlakyCoordinator(raises=raises)
        cleaned: list[str] = []

        with pytest.raises(LeaseLost):
            async with coordinator.lease("zap:x", ttl=1, wait=1) as lost:
                try:
                    await asyncio.sleep(5)  # the long-running scan
                finally:
                    # The adapter's cleanup: it must not reset a daemon it no longer owns.
                    if not lost.is_set():
                        cleaned.append("reset")
        assert coordinator.renewed >= 1
        assert cleaned == [], "a stale holder must not touch the resource on the way out"

    async def test_a_healthy_lease_still_releases_normally(self):
        coordinator = LocalCoordinator(poll_interval=0.01)
        async with coordinator.lease("zap:y", ttl=60, wait=1) as lost:
            assert not lost.is_set()
        # released, so the next job gets it immediately
        async with coordinator.lease("zap:y", ttl=60, wait=1):
            pass
