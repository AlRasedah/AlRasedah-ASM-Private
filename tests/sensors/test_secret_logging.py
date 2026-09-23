"""Credentials must not reach the worker's logs (review finding F2).

Shodan takes its key as a query parameter — it accepts no other form — and the
ZAP Replacer rule carried the target application's session cookie the same way.
HTTP clients log the request line at INFO, so both were written to stdout in
clear: outside the database encryption, the sealed job envelope and the error
sanitizer, and into whatever aggregates the scanner's logs.
"""

from __future__ import annotations

import logging
from urllib.parse import parse_qs

import httpx
import pytest
from asm_sensors import logs
from asm_sensors.adapters.shodan import _ShodanClient
from asm_sensors.adapters.zap import _ZapClient

KEY = "sh0dan-key-NEVER-IN-LOGS"
COOKIE = "PHPSESSID=s3ssion-NEVER-IN-LOGS; security=low"


@pytest.fixture
def captured(caplog):
    """Everything the process logs at INFO, with the worker's configuration applied."""
    logs.configure()
    caplog.set_level(logging.DEBUG)
    return caplog


async def test_the_shodan_key_never_reaches_the_logs(captured):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"ip_str": "192.0.2.1"}))
    client = _ShodanClient(KEY, timeout=5, retries=0)
    client._client = httpx.AsyncClient(base_url="https://api.shodan.io", transport=transport)
    async with client:
        await client.get("/shodan/host/192.0.2.1")
    assert KEY not in captured.text


async def test_the_scan_login_secret_never_reaches_the_logs(captured):
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"Result": "OK"})

    zap = _ZapClient("http://zap:8090", "zap-api-key", timeout=5)
    zap._c = httpx.AsyncClient(base_url="http://zap:8090", transport=httpx.MockTransport(handler))
    async with zap:
        await zap.add_auth_header("asm-auth-1", "Cookie", COOKIE, "^http://app\\.example\\.com/.*")

    assert COOKIE not in captured.text
    assert COOKIE not in str(seen["url"]), "the secret must not be in the URL, which is what gets logged"
    sent = parse_qs(str(seen["body"]))
    assert sent["replacement"] == [COOKIE], "it still has to reach ZAP — in the body"


def test_a_secret_that_slips_through_is_redacted(captured):
    logging.getLogger("some.adapter").error("GET https://api.example.com/host?key=%s failed", KEY)
    assert KEY not in captured.text
    assert "[redacted]" in captured.text


def test_request_logging_is_silenced_rather_than_relied_on(captured):
    # The redactor is a backstop; routine request logging is off, so a URL shape the
    # pattern does not know about is not printed in the first place.
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING


@pytest.mark.parametrize("line", [
    "https://api.shodan.io/shodan/host/1.2.3.4?key=abc123",
    "/JSON/replacer/action/addRule/?replacement=PHPSESSID%3Dabc&url=x",
    "POST /login apikey=deadbeef",
    "Authorization token=abc.def.ghi",
])
def test_known_secret_shapes_are_removed(line):
    out = logs.redact(line)
    assert "[redacted]" in out
    for secret in ("abc123", "PHPSESSID%3Dabc", "deadbeef", "abc.def.ghi"):
        assert secret not in out
