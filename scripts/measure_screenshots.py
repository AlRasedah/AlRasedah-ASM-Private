#!/usr/bin/env python3
"""Measure what one website capture costs, reproducibly, without touching the internet.

Runs the real screenshot adapter (real browser, real egress proxy) against a local
fixture site, N times in a row, and reports per capture: wall time, the browser
process tree's peak resident memory and CPU time, image size — plus the time a
capture waits for the deployment-wide slot when M are requested at once
(queue delay = captures ahead × capture time, with the default limit of 1).

    # inside the scanner image (the deployment's pinned browser):
    docker compose run --rm asm-scanner python /opt/asm/measure_screenshots.py --runs 10
    # on a workstation with Chrome/Chromium (lab numbers, not deployment numbers):
    ASM_BIN_CHROMIUM=/path/to/chrome python scripts/measure_screenshots.py --runs 10

Memory and CPU come from psutil when installed (``pip install psutil``), otherwise
from /proc on Linux; elsewhere they are reported as not measured. Storage growth is
reported from the image sizes: retained bytes = endpoints × retention × mean size.

The fixture binds 127.0.0.1, so the run uses lab mode (non-public destinations
allowed); link-local/metadata addresses and the fixture's "excluded" host are still
refused, and the report counts those refusals.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "workers"))

from asm_sensors.adapters.screenshot import PROFILE_MARKER, ScreenshotAdapter  # noqa: E402
from asm_sensors.base import ExecutionContext  # noqa: E402
from asm_sensors.coordination import LocalCoordinator  # noqa: E402
from asm_sensors.targets import Target, TargetKind  # noqa: E402

PAGE = """<!doctype html><html><head><title>Fixture login portal</title>
<style>body{font:16px sans-serif;background:linear-gradient(#123,#345);color:#eee;margin:0}
.card{width:420px;margin:80px auto;padding:32px;background:#234;border-radius:8px}
input{display:block;width:100%%;margin:8px 0;padding:8px}</style>
<script src="http://169.254.169.254/latest/meta-data/"></script></head>
<body><div class="card"><h1>Example portal</h1><p>%s</p>
<img src="/logo.svg" width="120"><form><input placeholder="user"><input type="password" placeholder="password">
<button>Sign in</button></form></div>
<iframe src="http://127.0.0.2:%d/admin" width="1" height="1"></iframe>
%s</body></html>"""
LOGO = b'<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40"><rect width="120" height="40" fill="#c73"/></svg>'


def fixture(extra_kb: int) -> tuple[ThreadingHTTPServer, int]:
    filler = "".join(f"<p>Paragraph {i} " + "lorem ipsum " * 20 + "</p>" for i in range(max(1, extra_kb * 4)))

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # noqa: ANN002
            pass

        def do_GET(self):  # noqa: N802
            body, ctype = (LOGO, "image/svg+xml") if self.path == "/logo.svg" else (
                (PAGE % ("Measured page", port, filler)).encode(), "text/html")
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


class Sampler:
    """Peak RSS and CPU of every process whose command line carries the profile marker."""

    def __init__(self) -> None:
        try:
            import psutil  # type: ignore[import-not-found]

            self.psutil = psutil
        except ImportError:
            self.psutil = None
        self.peak_rss = 0
        self.cpu: dict[int, float] = {}
        self._stop = threading.Event()

    @property
    def available(self) -> bool:
        return self.psutil is not None or sys.platform.startswith("linux")

    def _sample(self) -> None:
        total = 0
        if self.psutil is not None:
            for p in self.psutil.process_iter(["pid", "cmdline"]):
                try:
                    if any(PROFILE_MARKER in (a or "") for a in (p.info["cmdline"] or [])):
                        total += p.memory_info().rss
                        t = p.cpu_times()
                        self.cpu[p.pid] = t.user + t.system
                except (self.psutil.NoSuchProcess, self.psutil.AccessDenied):
                    continue
        else:
            tick = os.sysconf("SC_CLK_TCK")
            for d in Path("/proc").iterdir():
                if not d.name.isdigit():
                    continue
                try:
                    if PROFILE_MARKER.encode() not in (d / "cmdline").read_bytes():
                        continue
                    rss = next(int(ln.split()[1]) for ln in (d / "status").read_text().splitlines()
                               if ln.startswith("VmRSS:"))
                    total += rss * 1024
                    fields = (d / "stat").read_text().rsplit(")", 1)[1].split()
                    self.cpu[int(d.name)] = (int(fields[11]) + int(fields[12])) / tick
                except (OSError, StopIteration, ValueError, IndexError):
                    continue
        self.peak_rss = max(self.peak_rss, total)

    def __enter__(self) -> Sampler:
        if self.available:
            def loop() -> None:
                while not self._stop.is_set():
                    self._sample()
                    time.sleep(0.05)
            self._t = threading.Thread(target=loop, daemon=True)
            self._t.start()
        return self

    def __exit__(self, *a: object) -> None:
        self._stop.set()
        if self.available:
            self._t.join()


async def capture(url: str, workdir: Path, job: str, width: int, height: int) -> tuple[dict, Sampler]:
    ctx = ExecutionContext(workdir=workdir / job, settings={"allow_non_public_targets": True},
                           coordinator=LocalCoordinator(), job_id=job)
    ctx.workdir.mkdir(parents=True)
    cfg = {"viewport_width": width, "viewport_height": height, "timeout_seconds": 30,
           "excluded_networks": ["127.0.0.2/32"]}
    with Sampler() as s:
        started = time.perf_counter()
        r = await ScreenshotAdapter().run([Target(kind=TargetKind.URL, value=url)], cfg, ctx)
        wall = time.perf_counter() - started
    img = r.screenshots[0] if r.screenshots else None
    return {"status": r.status, "outcome": r.stats.get("outcome"), "wall_s": round(wall, 2),
            "browser_s": r.stats.get("browser_seconds"), "image_bytes": img.size if img else None,
            "blocked": r.stats.get("blocked"), "connections": r.stats.get("connections"),
            "external_destinations": [d for d in r.stats.get("destinations") or [] if not d.startswith("127.0.0.1:")],
            "refused": r.stats.get("blocked_destinations"),
            "errors": r.errors[:1]}, s


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--page-kb", type=int, default=40, help="approximate HTML size of the fixture page")
    ap.add_argument("--width", type=int, default=1280)
    ap.add_argument("--height", type=int, default=800)
    ap.add_argument("--burst", type=int, default=10, help="captures requested at once, for the queue-delay estimate")
    ap.add_argument("--endpoints", type=int, default=500, help="endpoints, for the storage estimate")
    ap.add_argument("--retention", type=int, default=2)
    args = ap.parse_args()

    srv, port = fixture(args.page_kb)
    url = f"http://127.0.0.1:{port}/"
    rows = []
    with tempfile.TemporaryDirectory(prefix="asm-measure-") as wd:
        for i in range(args.runs):
            row, s = asyncio.run(capture(url, Path(wd), f"m{i}", args.width, args.height))
            row["peak_rss_mb"] = round(s.peak_rss / 2**20, 1) if s.available else None
            row["cpu_s"] = round(sum(s.cpu.values()), 2) if s.available and s.cpu else None
            rows.append(row)
            print(json.dumps(row))
    srv.shutdown()
    ok = [r for r in rows if r["status"] == "completed"]
    if not ok:
        print("no successful capture; see errors above", file=sys.stderr)
        return 1

    def stat(key: str) -> dict | None:
        vals = [r[key] for r in ok if r.get(key) is not None]
        if not vals:
            return None
        return {"min": min(vals), "median": round(statistics.median(vals), 2), "max": max(vals)}

    mean_img = statistics.mean(r["image_bytes"] for r in ok)
    per_capture = statistics.median(r["wall_s"] for r in ok)
    summary = {
        "measured": {"runs": len(rows), "succeeded": len(ok), "wall_s": stat("wall_s"),
                     "peak_rss_mb": stat("peak_rss_mb"), "cpu_s": stat("cpu_s"), "image_bytes": stat("image_bytes"),
                     "blocked_per_capture": stat("blocked"), "viewport": f"{args.width}x{args.height}",
                     "external_destinations": sorted({d for r in ok for d in r["external_destinations"]}),
                     "platform": sys.platform, "memory_source": "psutil" if Sampler().psutil else (
                         "/proc" if sys.platform.startswith("linux") else "not measured")},
        "derived_estimates": {
            "queue_delay_s_for_last_of_burst_at_limit_1": round(per_capture * (args.burst - 1), 1),
            "retained_storage_mb": round(args.endpoints * args.retention * mean_img / 2**20, 1),
            "assumptions": f"{args.endpoints} endpoints x retention {args.retention} x mean image "
                           f"{round(mean_img / 1024)} KB; queue delay excludes broker latency",
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
