"""What scans look like on the wire: no product branding unless a deployment asks for it."""

from __future__ import annotations

import httpx
import pytest
import respx
from asm_sensors.adapters.httpx import HttpxAdapter, HttpxConfig
from asm_sensors.adapters.nuclei import NucleiAdapter, NucleiConfig
from asm_sensors.adapters.shodan import ShodanAdapter
from asm_sensors.base import ExecutionContext
from asm_sensors.identity import DEFAULT_USER_AGENT, identity_header, user_agent
from asm_sensors.runner import deployment_settings
from asm_sensors.targets import Target, TargetKind


class TestIdentityHeader:
    def test_nothing_identifies_the_product_by_default(self):
        assert identity_header({}) is None
        assert identity_header({"scanner_identity": ""}) is None

    def test_a_deployment_can_announce_its_scans(self):
        assert identity_header({"scanner_identity": "acme-pentest"}) == "X-Scanner: acme-pentest"
        assert identity_header({"scanner_identity": "X-Audit: ticket-4711"}) == "X-Audit: ticket-4711"

    def test_header_injection_is_refused(self):
        assert identity_header({"scanner_identity": "a: b\r\nX-Other: c"}) is None
        assert identity_header({"scanner_identity": ":"}) is None

    def test_the_scanners_only_send_it_when_configured(self):
        argv = HttpxAdapter().build_argv("httpx", "t.txt", "o.json", HttpxConfig(), False, None)
        assert "-H" not in argv
        argv = HttpxAdapter().build_argv("httpx", "t.txt", "o.json", HttpxConfig(), False, "X-Scanner: acme")
        assert argv[argv.index("-H") + 1] == "X-Scanner: acme"
        argv = NucleiAdapter().build_argv("nuclei", "t.txt", "o.json", NucleiConfig(), None, "X-Scanner: acme")
        assert argv[argv.index("-H") + 1] == "X-Scanner: acme"

    def test_a_profile_can_still_turn_it_off(self):
        argv = HttpxAdapter().build_argv("httpx", "t.txt", "o.json", HttpxConfig(identify_scanner=False), False,
                                         "X-Scanner: acme")
        assert "-H" not in argv


class TestUserAgent:
    def test_the_default_does_not_name_the_product(self):
        assert user_agent({}) == DEFAULT_USER_AGENT
        assert "exteriq" not in DEFAULT_USER_AGENT.lower() and "asm" not in DEFAULT_USER_AGENT.lower()

    def test_a_deployment_can_choose_its_own(self):
        assert user_agent({"scanner_user_agent": "acme-scanner/2"}) == "acme-scanner/2"

    @respx.mock
    async def test_api_clients_use_it(self, tmp_path):
        seen: list[str] = []

        def record(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("user-agent", ""))
            return httpx.Response(200, json={"plan": "corp"})

        respx.get("https://api.shodan.io/api-info").mock(side_effect=record)
        respx.get("https://api.shodan.io/shodan/host/8.8.8.8").mock(return_value=httpx.Response(404, json={}))
        ctx = ExecutionContext(workdir=tmp_path, credentials={"shodan": ["k"]},
                               settings={"scanner_user_agent": "acme-scanner/2"})
        await ShodanAdapter().run([Target(kind=TargetKind.IP, value="8.8.8.8")], {}, ctx)
        assert seen == ["acme-scanner/2"]


def test_the_deployment_settings_carry_it(monkeypatch):
    monkeypatch.setenv("ASM_SCANNER_IDENTITY", "acme-pentest")
    monkeypatch.setenv("ASM_SCANNER_USER_AGENT", "acme-scanner/2")
    settings = deployment_settings()
    assert identity_header(settings) == "X-Scanner: acme-pentest" and user_agent(settings) == "acme-scanner/2"


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_settings_mean_off(value):
    assert identity_header({"scanner_identity": value}) is None
    assert user_agent({"scanner_user_agent": value}) == DEFAULT_USER_AGENT
