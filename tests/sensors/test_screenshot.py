"""Website screenshots, sensor side: destination enforcement, limits, isolation, cleanup.

Everything runs against a local HTTP server and a stand-in browser
(``fake_browser.py``); nothing leaves the machine. The real Chromium flags are
checked separately (``test_browser_flags_keep_isolation``).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from asm_sensors.adapters import screenshot as shot
from asm_sensors.adapters.screenshot import (
    FORBIDDEN_FLAGS,
    ScreenshotAdapter,
    ScreenshotConfig,
    find_stale_browsers,
    kill_pids,
    png_dimensions,
    strip_url,
)
from asm_sensors.base import ExecutionContext
from asm_sensors.coordination import LocalCoordinator
from asm_sensors.egress_proxy import EgressPolicy, EgressProxy, address_verdict
from asm_sensors.jobs import SensorJob
from asm_sensors.runner import execute_job
from asm_sensors.targets import Target, TargetKind

FAKE = str(Path(__file__).with_name("fake_browser.py"))


# ------------------------------------------------------------------ origin server
class Origin:
    """A local web server whose pages describe the scenario."""

    def __init__(self) -> None:
        self.routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
        self.hits: list[str] = []
        self.active = 0
        self.max_active = 0
        self.delay = 0.0
        lock = threading.Lock()
        origin = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # noqa: ANN002
                pass

            def do_GET(self):  # noqa: N802
                with lock:
                    origin.active += 1
                    origin.max_active = max(origin.max_active, origin.active)
                origin.hits.append(self.path)
                try:
                    if origin.delay:
                        time.sleep(origin.delay)
                    status, headers, body = origin.routes.get(self.path, (404, {}, b"not found"))
                    self.send_response(status)
                    for k, v in {"Content-Type": "text/html", **headers}.items():
                        self.send_header(k, v)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    with lock:
                        origin.active -= 1

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def page(self, path: str, html: str, status: int = 200, **headers: str) -> str:
        self.routes[path] = (status, headers, html.encode())
        return f"http://127.0.0.1:{self.port}{path}"

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def origin():
    o = Origin()
    yield o
    o.close()


@pytest.fixture
def fake_browser(monkeypatch):
    """Run the stand-in instead of Chromium, with the adapter's real argument list."""
    real = ScreenshotAdapter.browser_argv
    monkeypatch.setattr(shot, "resolve_binary", lambda name, allowed: "chromium")

    def argv(self, binary, *a, **kw):  # noqa: ANN001
        full = real(self, binary, *a, **kw)
        i = full.index("chromium")
        return full[:i] + [sys.executable, FAKE] + full[i + 1:]

    monkeypatch.setattr(ScreenshotAdapter, "browser_argv", argv)


def _ctx(tmp_path: Path, coordinator=None, job="job1") -> ExecutionContext:
    wd = tmp_path / job
    wd.mkdir(parents=True, exist_ok=True)
    # Lab mode: the local origin is 127.0.0.1. Exclusions and metadata still apply.
    return ExecutionContext(workdir=wd, settings={"allow_non_public_targets": True},
                            coordinator=coordinator or LocalCoordinator(poll_interval=0.02), job_id=job)


def _cfg(**kw):
    base = {"timeout_seconds": 5, "excluded_networks": ["127.0.0.2/32"], "excluded_domains": ["secret.example.com"]}
    base.update(kw)
    return base


def run(url: str, ctx: ExecutionContext, **cfg):
    return asyncio.run(ScreenshotAdapter().run([Target(kind=TargetKind.URL, value=url)], _cfg(**cfg), ctx))


def fetched(ctx: ExecutionContext) -> dict:
    return json.loads((ctx.workdir / "fake-browser.fetched").read_text())


# --------------------------------------------------------------- destination rules
@pytest.mark.parametrize(("addr", "lab", "blocked"), [
    ("93.184.216.34", False, False),
    ("127.0.0.1", False, True), ("10.1.2.3", False, True), ("192.168.1.1", False, True),
    ("100.64.0.1", False, True), ("::1", False, True), ("fc00::1", False, True),
    ("::ffff:127.0.0.1", False, True),  # IPv4-mapped loopback
    ("::ffff:10.0.0.1", True, False),
    ("64:ff9b::7f00:1", False, True),  # NAT64 wrapping 127.0.0.1
    ("2002:7f00:1::1", False, True),  # 6to4 wrapping 127.0.0.1
    ("0.0.0.0", True, True), ("224.0.0.1", True, True),
    # Metadata / link-local is refused even in lab mode.
    ("169.254.169.254", True, True), ("fe80::1", True, True), ("fd00:ec2::254", True, True),
    ("100.100.100.200", True, True),
])
def test_address_rules(addr, lab, blocked):
    assert (address_verdict(ipaddress.ip_address(addr), allow_non_public=lab, excluded=[]) is not None) is blocked


def test_excluded_networks_apply_in_lab_mode_too():
    net = [ipaddress.ip_network("198.51.100.0/24")]
    assert address_verdict(ipaddress.ip_address("198.51.100.9"), allow_non_public=True, excluded=net)


def _raw(proxy: EgressProxy, request: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", proxy.port), timeout=5) as s:
        s.sendall(request)
        chunks = []
        while True:
            try:
                d = s.recv(65536)
            except OSError:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)


def test_proxy_pins_each_connection_and_survives_dns_rebinding(origin):
    """The second lookup of the same name returns an excluded address: that connection is refused,
    and the allowed one went to the exact address that was checked."""
    origin.page("/", "<title>ok</title>hello")
    answers = [[ipaddress.ip_address("127.0.0.1")], [ipaddress.ip_address("127.0.0.2")]]

    async def resolver(host):  # noqa: ANN001
        return answers.pop(0)

    async def scenario():
        proxy = EgressProxy(EgressPolicy(allow_non_public=True, excluded_networks=[ipaddress.ip_network("127.0.0.2/32")],
                                         allowed_ports=frozenset({origin.port})), resolver=resolver)
        await proxy.start()
        try:
            req = f"GET http://rebind.test:{origin.port}/ HTTP/1.1\r\nHost: rebind.test\r\n\r\n".encode()
            first = await asyncio.to_thread(_raw, proxy, req)
            second = await asyncio.to_thread(_raw, proxy, req)
        finally:
            await proxy.stop()
        return first, second, proxy.stats

    first, second, stats = asyncio.run(scenario())
    assert b"200" in first.split(b"\r\n")[0] and b"hello" in first
    assert b"403" in second.split(b"\r\n")[0] and b"X-Egress-Blocked" in second
    assert origin.hits == ["/"] and stats.blocked == [f"rebind.test:{origin.port}: excluded address 127.0.0.2"]


def test_proxy_refuses_ports_schemes_exclusions_and_limits(origin):
    origin.page("/big", "x" * 300_000)

    async def resolver(host):  # noqa: ANN001
        return [ipaddress.ip_address("127.0.0.1")]

    async def scenario():
        proxy = EgressProxy(EgressPolicy(allow_non_public=True, excluded_domains=["secret.example.com"],
                                         allowed_ports=frozenset({origin.port}), max_response_bytes=100_000,
                                         max_connections=5), resolver=resolver)
        await proxy.start()
        try:
            out = {
                "port": await asyncio.to_thread(_raw, proxy, b"CONNECT 127.0.0.1:22 HTTP/1.1\r\n\r\n"),
                "scheme": await asyncio.to_thread(_raw, proxy, b"GET ftp://127.0.0.1/x HTTP/1.1\r\n\r\n"),
                "excluded": await asyncio.to_thread(_raw, proxy, f"CONNECT a.secret.example.com:{origin.port} "
                                                                  f"HTTP/1.1\r\n\r\n".encode()),
                "big": await asyncio.to_thread(_raw, proxy, f"GET http://127.0.0.1:{origin.port}/big HTTP/1.1\r\n"
                                                             f"Host: x\r\n\r\n".encode()),
                "tunnel": await asyncio.to_thread(_raw, proxy, f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\n\r\n"
                                                                f"GET /big HTTP/1.1\r\nHost: x\r\n\r\n".encode()),
            }
            for _ in range(3):
                out["cap"] = await asyncio.to_thread(_raw, proxy, b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
        finally:
            await proxy.stop()
        return out, proxy.stats

    out, stats = asyncio.run(scenario())
    for k in ("port", "scheme", "excluded"):
        assert out[k].startswith(b"HTTP/1.1 403"), k
    assert b"200 OK" in out["big"] and len(out["big"]) < 200_000  # cut at the response limit
    assert b"200 Connection Established" in out["tunnel"] and len(out["tunnel"]) < 200_000
    assert stats.limit_hit == "response size"
    assert any("connection limit" in b for b in stats.blocked)
    assert not any("secret.example.com" in h for h in origin.hits)


# --------------------------------------------------------------------- the adapter
def test_capture_blocks_internal_subresources_and_returns_a_bounded_png(origin, fake_browser, tmp_path):
    url = origin.page("/", f"""<html><head><title>  Acme   VPN portal </title>
        <script src="http://169.254.169.254/latest/meta-data/iam"></script></head>
        <body><img src="http://127.0.0.1:{origin.port}/logo.png">
        <iframe src="http://127.0.0.2:{origin.port}/admin"></iframe>
        <img src="http://secret.example.com:{origin.port}/x.png">
        <img src="http://unresolvable.invalid/x.png"></body></html>""")
    origin.page("/logo.png", "PNG", **{"Content-Type": "image/png"})
    ctx = _ctx(tmp_path)
    result = run(url, ctx, viewport_width=640, viewport_height=400)
    assert result.status == "completed", result.errors
    img = result.screenshots[0]
    assert (img.width, img.height) == (640, 400) and img.title == "Acme VPN portal"
    assert img.final_url == url and img.status_code == 200
    got = {u: s for u, s in fetched(ctx)["resources"]}
    assert got[f"http://127.0.0.1:{origin.port}/logo.png"] == 200
    for blocked in ("http://169.254.169.254/latest/meta-data/iam", f"http://127.0.0.2:{origin.port}/admin",
                    f"http://secret.example.com:{origin.port}/x.png", "http://unresolvable.invalid/x.png"):
        assert got[blocked] == 403, blocked
    assert result.stats["blocked"] >= 4 and result.stats["outcome"] == "succeeded"
    assert sorted(origin.hits) == ["/", "/", "/logo.png"]  # preflight + browser; nothing blocked reached it


def test_browser_flags_keep_isolation(tmp_path):
    cfg = ScreenshotConfig()
    argv = ScreenshotAdapter().browser_argv("chromium", "https://example.com", cfg, "http://127.0.0.1:9",
                                            tmp_path / "asm-shot-profile-j1", tmp_path / "o.png", "UA")
    flags = {a.split("=", 1)[0] for a in argv}
    assert not flags & set(FORBIDDEN_FLAGS)
    assert "--proxy-server=http://127.0.0.1:9" in argv and "--proxy-bypass-list=<-loopback>" in argv
    assert "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" in argv  # no DNS of its own
    assert "--disable-quic" in argv and "--force-webrtc-ip-handling-policy=disable_non_proxied_udp" in argv
    assert f"--user-data-dir={tmp_path / 'asm-shot-profile-j1'}" in argv
    assert "--window-size=1280,800" in argv and argv[-1] == "https://example.com"


def test_redirects_are_bounded_and_checked_hop_by_hop(origin, fake_browser, tmp_path):
    for i in range(4):
        origin.page(f"/r{i}", "", status=302, Location=f"/r{i + 1}")
    origin.page("/r4", "<title>end</title>")
    ok = run(f"http://127.0.0.1:{origin.port}/r0", _ctx(tmp_path, job="a"), max_redirects=4)
    assert ok.status == "completed" and ok.screenshots[0].final_url.endswith("/r4")
    assert len(ok.screenshots[0].redirects) == 4
    too_many = run(f"http://127.0.0.1:{origin.port}/r0", _ctx(tmp_path, job="b"), max_redirects=2)
    assert too_many.status == "failed" and "more than 2 redirects" in too_many.errors[0]
    origin.page("/away", "", status=302, Location=f"http://127.0.0.2:{origin.port}/internal?token=s3cret")
    blocked = run(f"http://127.0.0.1:{origin.port}/away", _ctx(tmp_path, job="c"))
    assert blocked.stats["outcome"] == "blocked" and "s3cret" not in json.dumps(blocked.model_dump(mode="json"))


@pytest.mark.parametrize(("marker", "outcome", "text"), [
    ("fake:sandbox", "unavailable", "sandbox is not available"),
    ("fake:noimage", "failed", "no image"),
    ("fake:notpng", "failed", "not a PNG"),
    ("fake:big", "failed", "larger than the 64 KB limit"),
    ("fake:giant", "failed", "larger than the configured viewport"),
])
def test_failures_are_reported_not_raised(origin, fake_browser, tmp_path, marker, outcome, text):
    url = origin.page("/", f"<title>t</title>{marker}")
    r = run(url, _ctx(tmp_path), max_image_bytes=64 * 1024, viewport_width=320, viewport_height=240)
    assert r.status == "failed" and r.stats["outcome"] == outcome and text in r.errors[0]
    assert not r.screenshots


def test_non_pages_are_not_rendered(origin, fake_browser, tmp_path):
    url = origin.page("/file.zip", "PK", **{"Content-Type": "application/zip"})
    r = run(url, _ctx(tmp_path))
    assert r.status == "failed" and "not a web page" in r.errors[0]
    assert not (tmp_path / "job1" / "fake-browser.pid").exists()  # the browser never started


def _alive(pid: int) -> bool:
    if sys.platform == "win32":
        import ctypes

        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        code = ctypes.c_ulong()
        ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
        ctypes.windll.kernel32.CloseHandle(h)
        return code.value == 259  # STILL_ACTIVE
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:  # a zombie is dead too
        return "Z" not in Path(f"/proc/{pid}/stat").read_text().split(")")[1].split()[0]
    except OSError:
        return True


def test_a_hung_page_is_killed_at_the_time_limit(origin, fake_browser, tmp_path, monkeypatch):
    url = origin.page("/", "<title>t</title>fake:hang")
    monkeypatch.setattr(shot, "run_process", _short(shot.run_process, 2))
    ctx = _ctx(tmp_path)
    r = run(url, ctx)
    assert r.stats["outcome"] == "timeout" and "did not finish loading" in r.errors[0]
    assert not _alive(int((ctx.workdir / "fake-browser.pid").read_text()))


def _short(real, seconds):  # noqa: ANN001
    async def run_process(argv, *, timeout, **kw):  # noqa: ANN001
        return await real(argv, timeout=seconds, **kw)
    return run_process


def test_cancelling_the_job_kills_the_browser_and_closes_the_proxy(origin, fake_browser, tmp_path):
    url = origin.page("/", "<title>t</title>fake:hang")
    ctx = _ctx(tmp_path)

    async def scenario():
        task = asyncio.create_task(ScreenshotAdapter().run([Target(kind=TargetKind.URL, value=url)], _cfg(), ctx))
        pidfile = ctx.workdir / "fake-browser.pid"
        for _ in range(200):
            if pidfile.exists() and (ctx.workdir / "fake-browser.fetched").exists():
                break
            await asyncio.sleep(0.05)
        argv = json.loads((ctx.workdir / "fake-browser.argv").read_text())
        proxy_port = int(next(a for a in argv if a.startswith("--proxy-server=")).rsplit(":", 1)[1])
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        return int(pidfile.read_text()), proxy_port

    pid, port = asyncio.run(scenario())
    time.sleep(0.3)
    assert not _alive(pid)
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_one_browser_per_pool_at_a_time(origin, fake_browser, tmp_path):
    origin.page("/", "<title>slow</title>")
    origin.delay = 0.4
    coord = LocalCoordinator(poll_interval=0.02)
    url = f"http://127.0.0.1:{origin.port}/"

    async def both():
        a = ScreenshotAdapter().run([Target(kind=TargetKind.URL, value=url)], _cfg(), _ctx(tmp_path, coord, "a"))
        b = ScreenshotAdapter().run([Target(kind=TargetKind.URL, value=url)], _cfg(), _ctx(tmp_path, coord, "b"))
        return await asyncio.gather(a, b)

    ra, rb = asyncio.run(both())
    assert ra.status == rb.status == "completed"
    assert origin.max_active == 1  # the two captures never overlapped

    async def impatient():
        async with coord.lease(shot.LEASE_NAME, ttl=30):
            return await ScreenshotAdapter().run([Target(kind=TargetKind.URL, value=url)],
                                                 _cfg(lease_wait_seconds=1), _ctx(tmp_path, coord, "c"))

    busy = asyncio.run(impatient())
    assert busy.status == "failed" and "another capture is still running" in busy.errors[0]


def test_every_capture_gets_a_fresh_profile_that_is_deleted(origin, fake_browser, monkeypatch, tmp_path):
    origin.page("/", "<title>t</title>")
    seen: list[list[str]] = []
    real = shot.run_process

    async def spy(argv, **kw):  # noqa: ANN001
        seen.append(list(argv))
        return await real(argv, **kw)

    monkeypatch.setattr(shot, "run_process", spy)
    for n in ("1", "2"):
        job = SensorJob(job_id=f"job{n}", tenant_id="t", scan_id="c", stage_id="c", adapter="screenshot",
                        targets=[Target(kind=TargetKind.URL, value=f"http://127.0.0.1:{origin.port}/")],
                        config=_cfg(), timeout_seconds=60)
        r = asyncio.run(execute_job(job, settings={"allow_non_public_targets": True},
                                    coordinator=LocalCoordinator(poll_interval=0.02)))
        assert r.status == "completed", r.errors
    profiles = [next(a.split("=", 1)[1] for a in argv if a.startswith("--user-data-dir=")) for argv in seen]
    assert len(set(profiles)) == 2 and all(shot.PROFILE_MARKER in p for p in profiles)
    assert not any(Path(p).exists() for p in profiles)  # removed with the job's temp directory


def test_runner_refuses_a_target_that_resolves_to_a_private_address():
    job = SensorJob(job_id="j", tenant_id="t", scan_id="c", stage_id="c", adapter="screenshot",
                    targets=[Target(kind=TargetKind.URL, value="http://10.0.0.8/")], config={}, timeout_seconds=60)
    r = asyncio.run(execute_job(job, settings={}))
    assert not r.screenshots and "egress policy" in r.errors[0]


def test_stale_browsers_are_found_by_marker_only(tmp_path):
    proc = tmp_path / "proc"
    for pid, cmd in ((101, f"chromium\x00--user-data-dir=/tmp/x/{shot.PROFILE_MARKER}j1\x00"),
                     (102, "chromium\x00--user-data-dir=/home/user/.config/chromium\x00"),
                     (103, f"python\x00{shot.PROFILE_MARKER}\x00")):
        (proc / str(pid)).mkdir(parents=True)
        (proc / str(pid) / "cmdline").write_bytes(cmd.encode())
    (proc / "self").mkdir()
    assert find_stale_browsers(proc_root=proc, own_pid=103) == [101]


def test_kill_pids_stops_a_real_process():
    import subprocess

    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        assert kill_pids([p.pid]) == 1
        p.wait(timeout=10)
        assert p.returncode is not None
    finally:
        if p.poll() is None:
            p.kill()


def test_png_and_url_helpers():
    from tests.sensors.fake_browser import png

    assert png_dimensions(png(3, 2)) == (3, 2)
    with pytest.raises(ValueError):
        png_dimensions(b"GIF89a" + b"\x00" * 40)
    assert strip_url("https://user:pw@Example.com:8443/a/b?token=x#frag") == "https://example.com:8443/a/b"


def test_browser_background_services_are_refused_and_features_are_one_list(tmp_path):
    argv = ScreenshotAdapter().browser_argv("chromium", "https://example.com", ScreenshotConfig(),
                                            "http://127.0.0.1:9", tmp_path / "p", tmp_path / "o.png", "UA")
    assert sum(a.startswith("--disable-features=") for a in argv) == 1  # a second one would replace the first
    assert "CertificateTransparencyComponentUpdater" in next(a for a in argv if a.startswith("--disable-features="))
    policy = ScreenshotAdapter().policy_for("https://example.com", ScreenshotConfig(), _ctx(tmp_path))

    async def resolver(host):  # noqa: ANN001
        return [ipaddress.ip_address("93.184.216.34")]

    async def check():
        proxy = EgressProxy(policy, resolver=resolver)
        return [await proxy.authorize(h, 443) for h in ("update.googleapis.com", "accounts.google.com",
                                                        "x.gvt1.com", "cdn.example.com")]

    decisions = asyncio.run(check())
    assert [d[1] for d in decisions[:3]] == ["browser background service"] * 3
    assert decisions[3][0] is not None  # an ordinary public CDN is still allowed
