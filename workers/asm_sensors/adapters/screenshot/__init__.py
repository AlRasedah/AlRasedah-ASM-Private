"""Website screenshot: one viewport-sized image of one public web endpoint.

Why not the HTTP fingerprinter's own headless mode: it would couple capture to
discovery (a capture failure must never fail discovery), it launches its browser
through a library that downloads a browser at run time unless told otherwise, it
disables the browser sandbox when it runs as root, and it offers no hook to decide
each connection the browser makes. This adapter drives a *pinned, packaged*
Chromium directly, in its own job, with:

* a fresh profile directory per capture (no cookies, credentials or history are
  ever reused; the directory is deleted with the job's temp dir);
* no network of its own: Chromium's resolver maps every name to NOTFOUND and
  every request — top-level, redirects, frames, scripts, images, WebSockets —
  goes through :class:`~asm_sensors.egress_proxy.EgressProxy`, which resolves,
  checks and pins each connection; UDP (WebRTC, QUIC) is disabled;
* the sandbox left on (``--no-sandbox`` and friends are refused, see
  ``FORBIDDEN_FLAGS``); a container without the sandbox's prerequisites fails
  with a message that says so instead of silently running unsandboxed;
* bounded time, redirects, bytes, connections, image dimensions and image size;
* one browser per pool at a time (a pool lease), stale browsers from a crashed
  or killed worker reaped before the next one starts, and — on Linux — the
  browser tied to its parent's lifetime (``setpriv --pdeathsig KILL``).

A capture is a picture of a page. It is never evidence of a vulnerability.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx
from pydantic import Field, field_validator

from ...base import AdapterConfig, ConfigurationError, ExecutionContext, RawOutput, ScannerAdapter
from ...coordination import LeaseUnavailable
from ...egress_proxy import BLOCK_HEADER, EgressPolicy, EgressProxy
from ...execution import BinaryNotFound, minimal_env, run_process
from ...identity import user_agent
from ...observations import SCREENSHOT_MAX_BYTES, NormalizedOutput, ScreenshotImage, SensorResult
from ...registry import register
from ...targets import Target, TargetKind

log = logging.getLogger(__name__)

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PROFILE_MARKER = "asm-shot-profile-"
LEASE_NAME = "screenshot-browser"
# Flags that would switch off isolation. The adapter never builds them; the check
# is a tripwire for future edits.
FORBIDDEN_FLAGS = ("--no-sandbox", "--disable-setuid-sandbox", "--no-zygote", "--single-process",
                   "--disable-gpu-sandbox", "--disable-seccomp-filter-sandbox", "--disable-namespace-sandbox",
                   "--disable-web-security", "--remote-debugging-port", "--remote-debugging-pipe",
                   "--allow-running-insecure-content")
_SANDBOX_ERRORS = re.compile(r"no usable sandbox|sandbox.*(not|could not|failed)|setuid sandbox|"
                             r"namespace.*(denied|not permitted)|clone.*(denied|not permitted)", re.I)
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
# Browser features that phone home or fetch in the background. Measured with a real
# browser: without the component/CT updaters and optimization-guide features, the
# remaining background hosts are the ones in BROWSER_SERVICE_DOMAINS (docs/SCREENSHOTS.md).
DISABLED_FEATURES = ("Translate", "OptimizationHints", "OptimizationGuideModelDownloading", "OptimizationHintsFetching",
                     "MediaRouter", "DialMediaRouteProvider", "AutofillServerCommunication",
                     "InterestFeedContentSuggestions", "PrivacySandboxSettings4",
                     "CertificateTransparencyComponentUpdater", "NetworkTimeServiceQuerying",
                     "SafeBrowsingRealTimeUrlLookup")
# Browser-vendor service hosts that no page needs and a browser contacts on its own
# (updates, account sign-in, safe browsing, field trials). Refused by the egress proxy
# so a capture never talks to them, whichever browser build is installed.
BROWSER_SERVICE_DOMAINS = ("update.googleapis.com", "clients1.google.com", "clients2.google.com",
                           "clients3.google.com", "clients4.google.com", "clients5.google.com",
                           "clients6.google.com", "clientservices.googleapis.com", "accounts.google.com",
                           "safebrowsing.googleapis.com", "optimizationguide-pa.googleapis.com",
                           "content-autofill.googleapis.com", "redirector.gvt1.com", "gvt1.com", "gvt2.com",
                           "dl.google.com", "edge.microsoft.com", "msedge.api.cdp.microsoft.com")


class ScreenshotConfig(AdapterConfig):
    """Set by the platform from the administrator's policy — never from a scan profile."""

    viewport_width: int = Field(default=1280, ge=320, le=1920)
    viewport_height: int = Field(default=800, ge=240, le=1200)
    timeout_seconds: int = Field(default=20, ge=5, le=90)
    max_redirects: int = Field(default=5, ge=0, le=10)
    max_image_bytes: int = Field(default=2 * 1024 * 1024, ge=64 * 1024, le=SCREENSHOT_MAX_BYTES)
    max_response_bytes: int = Field(default=5 * 1024 * 1024, ge=64 * 1024, le=50 * 1024 * 1024)
    max_total_bytes: int = Field(default=20 * 1024 * 1024, ge=1024 * 1024, le=200 * 1024 * 1024)
    max_connections: int = Field(default=300, ge=10, le=2000)
    extra_ports: list[int] = Field(default_factory=lambda: [8080, 8443], max_length=10)
    excluded_domains: list[str] = Field(default_factory=list, max_length=10_000)
    excluded_networks: list[str] = Field(default_factory=list, max_length=10_000)
    lease_wait_seconds: int = Field(default=120, ge=1, le=3600)

    @field_validator("excluded_networks")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(n, strict=False)) for n in v]

    @field_validator("extra_ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if any(not 1 <= p <= 65535 for p in v):
            raise ValueError("invalid port")
        return sorted(set(v))

    @field_validator("excluded_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        return sorted({d.strip().lower().rstrip(".") for d in v if d.strip()})


BROWSER_NAMES = ("chromium", "chromium-browser")


def browser_binary() -> str:
    """The installed browser. Distributions have shipped it under both names (Alpine among
    them), so look for either; ``ASM_BIN_CHROMIUM`` wins only when it names a real file."""
    override = os.environ.get("ASM_BIN_CHROMIUM")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    for name in BROWSER_NAMES:
        found = shutil.which(name)
        if found:
            return found
    note = f" (ASM_BIN_CHROMIUM={override} does not exist)" if override else ""
    raise BinaryNotFound(f"the screenshot browser is not installed in this scanner{note}")


@functools.cache
def _supports_pdeathsig(path: str) -> bool:
    try:
        proc = subprocess.run([path, "--help"], capture_output=True, timeout=5, check=False)  # noqa: S603
    except (OSError, subprocess.SubprocessError):
        return False
    return b"--pdeathsig" in proc.stdout + proc.stderr


def parent_death_wrapper() -> str | None:
    """util-linux ``setpriv``, when installed. BusyBox also has a ``setpriv`` applet (Alpine
    links it at /bin/setpriv), but without ``--pdeathsig``; that one is not used."""
    if not sys.platform.startswith("linux"):
        return None
    path = shutil.which("setpriv")
    return path if path and _supports_pdeathsig(path) else None


def png_dimensions(data: bytes) -> tuple[int, int]:
    """Width and height from the IHDR chunk; raises ValueError for anything that is not a PNG."""
    if len(data) < 33 or not data.startswith(PNG_SIGNATURE) or data[12:16] != b"IHDR":
        raise ValueError("not a PNG image")
    width, height = struct.unpack(">II", data[16:24])
    if not (0 < width <= 4096 and 0 < height <= 4096):
        raise ValueError("implausible image dimensions")
    return width, height


def strip_url(url: str) -> str:
    """A URL without query string, fragment or credentials — safe to store and show."""
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    netloc = host + (f":{p.port}" if p.port else "")
    return urlunsplit((p.scheme, netloc, p.path or "/", "", ""))[:2048]


# ----------------------------------------------------------------- process hygiene
def find_stale_browsers(marker: str = PROFILE_MARKER, proc_root: Path = Path("/proc"),
                        own_pid: int | None = None) -> list[int]:
    """PIDs (of this user) whose command line carries our profile marker. Linux /proc layout."""
    own_pid = own_pid if own_pid is not None else os.getpid()
    uid = os.getuid() if hasattr(os, "getuid") else None
    out = []
    if not proc_root.is_dir():
        return out
    for d in proc_root.iterdir():
        if not d.name.isdigit() or int(d.name) == own_pid:
            continue
        try:
            if uid is not None and (d / "status").exists():
                owner = next((ln.split()[1] for ln in (d / "status").read_text().splitlines()
                              if ln.startswith("Uid:")), None)
                if owner is not None and int(owner) != uid:
                    continue
            cmd = (d / "cmdline").read_bytes().replace(b"\x00", b" ")
        except (OSError, ValueError):
            continue
        if marker.encode() in cmd:
            out.append(int(d.name))
    return sorted(out)


def kill_pids(pids: list[int]) -> int:
    """Kill each process and, when it leads a group of its own, that whole group.

    Never signals this process's own group: a stray process that shares it would
    otherwise take the worker down with it."""
    killed = 0
    own_group = os.getpgrp() if sys.platform != "win32" else None
    for pid in pids:
        try:
            if sys.platform != "win32":
                try:
                    group = os.getpgid(pid)
                    if group != own_group:
                        os.killpg(group, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            os.kill(pid, signal.SIGKILL if sys.platform != "win32" else signal.SIGTERM)
            killed += 1
        except (ProcessLookupError, PermissionError, OSError):
            continue
    return killed


def reap_stale_browsers() -> int:
    """Kill browsers left behind by a worker that was killed mid-capture.

    Called while holding the pool's browser lease, so no live capture of this pool
    can own them."""
    if not sys.platform.startswith("linux"):
        return 0
    stale = find_stale_browsers()
    if stale:
        log.warning("reaping %d stale screenshot browser process(es)", len(stale))
    return kill_pids(stale)


class _Outcome(Exception):
    def __init__(self, outcome: str, message: str) -> None:
        super().__init__(message)
        self.outcome = outcome


@register
class ScreenshotAdapter(ScannerAdapter):
    name = "screenshot"
    display_name = "Website screenshot"
    stage_types = frozenset()  # not a scan stage: dispatched by the screenshot service only
    target_kinds = frozenset({TargetKind.URL})
    active = True
    binaries = ("chromium",)
    config_model = ScreenshotConfig

    # The whole job is driven by run(); the pipeline hooks below are unused.
    async def execute(self, targets, config, ctx) -> RawOutput:  # type: ignore[override]  # pragma: no cover
        raise NotImplementedError

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:  # pragma: no cover
        return []

    async def normalize(self, parsed, targets, config) -> NormalizedOutput:  # type: ignore[override]  # pragma: no cover
        return NormalizedOutput()

    # ----------------------------------------------------------------- driver
    async def run(self, targets: list[Target], raw_config: dict[str, Any] | None,
                  ctx: ExecutionContext) -> SensorResult:
        started = datetime.now(UTC)
        targets = self.check_targets(targets)
        cfg = self.parse_config(raw_config)
        assert isinstance(cfg, ScreenshotConfig)
        stats: dict[str, Any] = {}
        if len(targets) != 1:
            return self._result(started, "failed", ["exactly one web endpoint per capture"], stats, None)
        url = targets[0].value
        try:
            binary = browser_binary()
        except Exception as exc:  # noqa: BLE001 - reported as configuration, never as a crash
            stats["outcome"] = "unavailable"
            return self._result(started, "failed", [f"ConfigurationError: {exc}"], stats, None)
        try:
            async with ctx.coordinator.lease(LEASE_NAME, ttl=max(60, cfg.timeout_seconds * 3),
                                             wait=cfg.lease_wait_seconds):
                reap_stale_browsers()
                image = await self._capture(binary, url, cfg, ctx, stats)
        except LeaseUnavailable:
            stats["outcome"] = "failed"
            return self._result(started, "failed", ["another capture is still running in this scanner pool"],
                                stats, None)
        except _Outcome as o:
            stats["outcome"] = o.outcome
            return self._result(started, "failed", [str(o)], stats, None)
        stats["outcome"] = "succeeded"
        return self._result(started, "completed", [], stats, image)

    def _result(self, started: datetime, status: str, errors: list[str], stats: dict[str, Any],
                image: ScreenshotImage | None) -> SensorResult:
        return SensorResult(adapter=self.name, adapter_version=self.adapter_version, status=status,  # type: ignore[arg-type]
                            started_at=started, finished_at=datetime.now(UTC), target_count=1,
                            errors=errors, stats=stats, screenshots=[image] if image else [])

    def policy_for(self, url: str, cfg: ScreenshotConfig, ctx: ExecutionContext) -> EgressPolicy:
        p = urlsplit(url)
        port = p.port or (443 if p.scheme == "https" else 80)

        return EgressPolicy(
            allow_non_public=bool(ctx.settings.get("allow_non_public_targets")),
            excluded_networks=[ipaddress.ip_network(n) for n in cfg.excluded_networks],
            excluded_domains=cfg.excluded_domains, denied_domains=list(BROWSER_SERVICE_DOMAINS),
            allowed_ports=frozenset({80, 443, port, *cfg.extra_ports}),
            max_connections=cfg.max_connections, max_response_bytes=cfg.max_response_bytes,
            max_total_bytes=cfg.max_total_bytes, idle_timeout=float(min(cfg.timeout_seconds, 30)))

    def browser_argv(self, binary: str, url: str, cfg: ScreenshotConfig, proxy_url: str, profile: Path,
                     out: Path, ua: str) -> list[str]:
        argv = [
            binary, "--headless=new", "--disable-gpu",
            # Alpine's Chromium 152 writes this cache with pwritev2, which its own GPU-process
            # seccomp policy forbids: the GPU process dies three times and the browser exits.
            # A one-shot capture has no use for the cache anyway.
            "--disable-gpu-shader-disk-cache",
            "--hide-scrollbars", "--mute-audio",
            "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-default-apps",
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--disable-domain-reliability", "--disable-client-side-phishing-detection", "--disable-breakpad",
            "--metrics-recording-only", "--no-pings", "--disable-dev-shm-usage", "--deny-permission-prompts",
            # One list: a second --disable-features would replace this one, not add to it.
            "--disable-features=" + ",".join(DISABLED_FEATURES),
            "--disable-quic",
            # No network of its own: every request goes through the egress proxy, and the
            # browser's resolver answers NOTFOUND for everything (the proxy is an IP literal).
            f"--proxy-server={proxy_url}", "--proxy-bypass-list=<-loopback>",
            "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
            "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
            # Visual recognition only; nothing secret is sent, so self-signed certificates may render.
            "--ignore-certificate-errors",
            "--js-flags=--max-old-space-size=256", "--renderer-process-limit=2",
            f"--user-agent={ua}",
            f"--user-data-dir={profile}",
            f"--window-size={cfg.viewport_width},{cfg.viewport_height}",
            f"--timeout={cfg.timeout_seconds * 1000}",
            f"--screenshot={out}",
            url,
        ]
        bad = [a for a in argv if a.split("=", 1)[0] in FORBIDDEN_FLAGS]
        if bad:
            raise ConfigurationError(f"refusing to start the browser with {bad}")
        pdeath = parent_death_wrapper()
        # Tie the browser to this worker process: if the worker dies, the kernel kills it.
        # Without setpriv, the stale-browser reaper is what cleans up after a dead worker.
        return [pdeath, "--pdeathsig", "KILL", "--", *argv] if pdeath else argv

    async def preflight(self, url: str, cfg: ScreenshotConfig, proxy: EgressProxy, ua: str,
                        stats: dict[str, Any]) -> tuple[str, int | None, str | None, list[str]]:
        """Follow redirects ourselves, through the proxy, with a hard limit. Returns the page to load."""
        redirects: list[str] = []
        current = url
        timeout = httpx.Timeout(min(cfg.timeout_seconds, 15))
        async with httpx.AsyncClient(proxy=proxy.url, verify=False, follow_redirects=False, timeout=timeout,  # noqa: S501
                                     headers={"User-Agent": ua}, trust_env=False) as client:
            for _ in range(cfg.max_redirects + 1):
                try:
                    async with client.stream("GET", current) as r:
                        if r.headers.get(BLOCK_HEADER):
                            raise _Outcome("blocked", f"egress policy blocked {strip_url(current)}")
                        head = b""
                        async for chunk in r.aiter_bytes():
                            head += chunk
                            if len(head) >= 65536:
                                break
                        status, ctype, location = r.status_code, r.headers.get("content-type", ""), \
                            r.headers.get("location")
                except httpx.ProxyError as exc:
                    reason = proxy.stats.blocked[-1] if proxy.stats.blocked else "the proxy refused the connection"
                    raise _Outcome("blocked", f"egress policy blocked: {reason}") from exc
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    raise _Outcome("failed", f"the endpoint could not be reached ({type(exc).__name__})") from exc
                if status in (301, 302, 303, 307, 308) and location:
                    nxt = urljoin(current, location)
                    if urlsplit(nxt).scheme not in ("http", "https"):
                        raise _Outcome("failed", "the page redirects to a non-web location")
                    redirects.append(strip_url(nxt))
                    current = nxt
                    continue
                m = _TITLE.search(head)
                stats["title"] = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip()[:300] if m else None
                if ctype and not any(t in ctype.lower() for t in ("html", "xml", "text/plain", "image/")):
                    raise _Outcome("failed", f"not a web page ({ctype.split(';')[0][:60]})")
                return current, status, ctype, redirects
        raise _Outcome("failed", f"more than {cfg.max_redirects} redirects")

    async def _capture(self, binary: str, url: str, cfg: ScreenshotConfig, ctx: ExecutionContext,
                       stats: dict[str, Any]) -> ScreenshotImage:
        ua = user_agent(ctx.settings)
        proxy = EgressProxy(self.policy_for(url, cfg, ctx))
        await proxy.start()
        try:
            final, status, _ctype, redirects = await self.preflight(url, cfg, proxy, ua, stats)
            profile = ctx.workdir / f"{PROFILE_MARKER}{ctx.job_id}"
            profile.mkdir(parents=True, exist_ok=True)
            out = ctx.workdir / "capture.png"
            argv = self.browser_argv(binary, final, cfg, proxy.url, profile, out, ua)
            proc = await run_process(argv, timeout=cfg.timeout_seconds + 15, cwd=str(ctx.workdir),
                                     env=minimal_env(home=str(ctx.workdir)), max_output_bytes=256 * 1024)
            stats.update({"browser_seconds": round(proc.duration, 2), "browser_exit": proc.returncode,
                          "timed_out": proc.timed_out})
            err = proc.stderr.decode("utf-8", "replace")
            if _SANDBOX_ERRORS.search(err):
                raise _Outcome("unavailable", "the browser sandbox is not available in this scanner container; "
                                              "see the deployment guide (website screenshots)")
            if proc.timed_out:
                raise _Outcome("timeout", f"the page did not finish loading within {cfg.timeout_seconds} seconds")
            if not out.exists():
                raise _Outcome("failed", "the browser produced no image")
            size = out.stat().st_size
            if size > cfg.max_image_bytes:
                raise _Outcome("failed", f"the image is larger than the {cfg.max_image_bytes // 1024} KB limit")
            data = out.read_bytes()
            try:
                width, height = png_dimensions(data)
            except ValueError as exc:
                raise _Outcome("failed", str(exc)) from exc
            if width > cfg.viewport_width * 2 or height > cfg.viewport_height * 2:
                raise _Outcome("failed", "the image is larger than the configured viewport")
            return ScreenshotImage(url=url, final_url=strip_url(final), redirects=redirects[:10], status_code=status,
                                   width=width, height=height, size=size, sha256=hashlib.sha256(data).hexdigest(),
                                   data=base64.b64encode(data).decode("ascii"), captured_at=datetime.now(UTC),
                                   title=stats.pop("title", None))
        finally:
            await proxy.stop()
            s = proxy.stats
            stats.update({"connections": s.connections, "blocked": s.blocked_count, "bytes": s.bytes_down,
                          "limit": s.limit_hit, "blocked_destinations": s.blocked[:5],
                          "destinations": s.allowed_hosts[:20]})
            await asyncio.sleep(0)


_BROWSER_ERROR_LINE = re.compile(r"FATAL|CRASHING|ERROR|sandbox", re.I)


def browser_errors(stderr: str, limit: int = 1200) -> str:
    """The browser's own error lines. A crash ends with crash-reporter noise that would
    otherwise push the one line naming the cause out of the self-test's output."""
    lines = [ln for ln in stderr.splitlines() if _BROWSER_ERROR_LINE.search(ln) and "crashpad" not in ln]
    return "\n".join(dict.fromkeys(lines))[-limit:] if lines else stderr[-limit:]


async def selftest(timeout: int = 60) -> dict[str, Any]:
    """Operator check, no network needed: can this container start the pinned browser
    *with its sandbox* and write a PNG? Chromium refuses to run unsandboxed unless told
    to, and this adapter never tells it to, so a PNG here means the sandbox works.

    ``docker compose run --rm asm-scanner browser-selftest``"""
    import tempfile

    out: dict[str, Any] = {"ok": False}
    try:
        binary = browser_binary()
    except Exception as exc:  # noqa: BLE001
        return {**out, "error": f"browser not installed: {exc}"}
    out["binary"] = binary
    try:
        version = await run_process([binary, "--version"], timeout=30, env=minimal_env(), max_output_bytes=4096)
    except OSError as exc:
        return {**out, "error": f"the browser could not be started: {exc}"}
    out["version"] = version.stdout.decode("utf-8", "replace").strip()[:200]
    out["dies_with_worker"] = parent_death_wrapper() is not None
    with tempfile.TemporaryDirectory(prefix="asm-selftest-") as wd:
        cfg = ScreenshotConfig(viewport_width=320, viewport_height=240, timeout_seconds=15)
        png_path = Path(wd) / "selftest.png"
        # A dead proxy address: the page is inline, so nothing should try the network.
        argv = ScreenshotAdapter().browser_argv(binary, "data:text/html,<h1>self-test</h1>", cfg,
                                                "http://127.0.0.1:9", Path(wd) / f"{PROFILE_MARKER}selftest",
                                                png_path, "selftest")
        try:
            proc = await run_process(argv, timeout=timeout, cwd=wd, env=minimal_env(home=wd), max_output_bytes=65536)
        except OSError as exc:
            return {**out, "error": f"the browser could not be started: {exc}"}
        err = proc.stderr.decode("utf-8", "replace")
        if _SANDBOX_ERRORS.search(err):
            return {**out, "error": "the browser sandbox is unavailable in this container", "detail": browser_errors(err)}
        if not png_path.exists():
            return {**out, "error": "no image was produced", "exit": proc.returncode, "detail": browser_errors(err)}
        out.update(ok=True, image_bytes=png_path.stat().st_size, dimensions=png_dimensions(png_path.read_bytes()),
                   seconds=round(proc.duration, 2))
    return out
