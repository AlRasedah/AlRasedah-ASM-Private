"""Shodan host-intelligence engine (the Nmap ``shodan-api`` data, as inventory)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx
from asm_sensors.adapters.shodan import PROVIDER, ShodanAdapter, ShodanConfig
from asm_sensors.base import ConfigurationError, ExecutionContext
from asm_sensors.observations import AssetObservation, FindingCoverage, FindingObservation, Severity
from asm_sensors.targets import Target, TargetKind

from .helpers import fixture_bytes

KEY = "sh0dan-secret-key"
HOST = json.loads(fixture_bytes("shodan_host.json"))


def ctx(tmp_path, **kw):
    return ExecutionContext(workdir=tmp_path, credentials={PROVIDER: [KEY]}, **kw)


def ip(value: str) -> Target:
    return Target(kind=TargetKind.IP, value=value)


def _account(route_key_holder: list | None = None):
    def responder(request: httpx.Request) -> httpx.Response:
        if route_key_holder is not None:
            route_key_holder.append(request.url.params.get("key"))
        return httpx.Response(200, json={"plan": "corp", "query_credits": 100, "scan_credits": 10})
    return responder


async def run(tmp_path, targets, config=None):
    adapter = ShodanAdapter()
    return await adapter.run(targets, config or {}, ctx(tmp_path))


@respx.mock
async def test_host_lookup_becomes_inventory(tmp_path):
    keys: list = []
    respx.get("https://api.shodan.io/api-info").mock(side_effect=_account(keys))
    respx.get("https://api.shodan.io/shodan/host/198.51.100.7").mock(return_value=httpx.Response(200, json=HOST))
    respx.get("https://api.shodan.io/shodan/host/203.0.113.9").mock(return_value=httpx.Response(404, json={}))

    result = await run(tmp_path, [ip("198.51.100.7"), ip("203.0.113.9")])

    assert result.status == "completed" and not result.errors
    assert result.historical is True  # Shodan reports what it last saw
    assert keys == [KEY]
    assets = {(o.type.value, o.value): o for o in result.observations if isinstance(o, AssetObservation)}
    address = assets[("ip_address", "198.51.100.7")]
    assert address.attributes["asn"] == "AS64500" and address.attributes["as_name"] == "Example Hosting"
    assert ("hostname", "vpn.example.com") in assets
    https = assets[("service", "198.51.100.7:443/tcp")]
    assert https.attributes["product"] == "Fortinet FortiGate" and https.attributes["version"] == "6.0.4"
    assert https.attributes["title"] == "Fortinet SSL VPN Login"
    assert https.attributes["shodan_last_seen"].startswith("2026-09-14")
    assert ("port", "198.51.100.7:22/tcp") in assets
    assert ("certificate", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789") in assets
    # A record Shodan last saw in 2024 is too old to present as current exposure.
    assert ("port", "198.51.100.7:8080/tcp") not in assets
    # 404 is "Shodan has no data", not an error.
    assert ("ip_address", "203.0.113.9") not in assets


@respx.mock
async def test_reported_cves_are_unverified_findings(tmp_path):
    respx.get("https://api.shodan.io/api-info").mock(side_effect=_account())
    respx.get("https://api.shodan.io/shodan/host/198.51.100.7").mock(return_value=httpx.Response(200, json=HOST))

    result = await run(tmp_path, [ip("198.51.100.7")])

    findings = [o for o in result.observations if isinstance(o, FindingObservation)]
    fortinet = next(f for f in findings if f.rule_id == "shodan:CVE-2018-13379" and f.asset.type.value == "port")
    assert fortinet.severity == Severity.CRITICAL and fortinet.cve == ["CVE-2018-13379"]
    assert "unverified" in fortinet.tags and fortinet.confidence <= 50
    assert fortinet.evidence["verified"] is False
    # Shodan may close only its own reports, never another sensor's findings.
    coverage = [c for c in result.coverage if isinstance(c, FindingCoverage)]
    assert len(coverage) == 1 and coverage[0].include_tags == ["exposure-intelligence"]
    assert {a.value for a in coverage[0].assets} >= {"198.51.100.7", "198.51.100.7:443/tcp"}
    # Nothing that could close ports or hosts.
    assert all(isinstance(c, FindingCoverage) for c in result.coverage)


@respx.mock
async def test_rejected_key_fails_once_without_lookups(tmp_path):
    respx.get("https://api.shodan.io/api-info").mock(return_value=httpx.Response(401, json={"error": "Invalid API key"}))
    lookup = respx.get("https://api.shodan.io/shodan/host/198.51.100.7").mock(
        return_value=httpx.Response(200, json=HOST))

    result = await run(tmp_path, [ip("198.51.100.7")])

    assert not lookup.called  # the key is checked before any credit is spent
    assert result.status == "failed" and result.coverage == []
    assert "rejected" in result.errors[0]
    assert KEY not in " ".join(result.errors)  # the key never reaches an error message


@respx.mock
async def test_rate_limit_is_partial_not_silent(tmp_path):
    respx.get("https://api.shodan.io/api-info").mock(side_effect=_account())
    respx.get("https://api.shodan.io/shodan/host/198.51.100.7").mock(return_value=httpx.Response(200, json=HOST))
    respx.get("https://api.shodan.io/shodan/host/203.0.113.9").mock(return_value=httpx.Response(429, json={}))

    result = await run(tmp_path, [ip("198.51.100.7"), ip("203.0.113.9")],
                       {"retries": 0})

    assert result.status == "partial" and any("rate limit" in e for e in result.errors)
    assert result.coverage == []  # an incomplete run vouches for nothing


@respx.mock
async def test_lookup_cap_is_reported(tmp_path):
    respx.get("https://api.shodan.io/api-info").mock(side_effect=_account())
    respx.get("https://api.shodan.io/shodan/host/198.51.100.7").mock(return_value=httpx.Response(200, json=HOST))

    result = await run(tmp_path, [ip("198.51.100.7"), ip("203.0.113.9")], {"max_lookups": 1})

    assert result.status == "partial" and any("max_lookups" in e for e in result.errors)


async def test_without_a_key_the_stage_says_so(tmp_path):
    with pytest.raises(ConfigurationError, match="Shodan API key"):
        await ShodanAdapter().validate_configuration(ShodanConfig(), ExecutionContext(workdir=tmp_path))


def test_engine_is_passive_and_ip_scoped():
    adapter = ShodanAdapter()
    assert adapter.active is False and adapter.historical is True
    assert adapter.credential_providers == ("shodan",)
    assert adapter.target_kinds == frozenset({TargetKind.IP})
