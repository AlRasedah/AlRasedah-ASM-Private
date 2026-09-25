"""The scanner's health report, published for the platform's Diagnostics page.

A scanner has no database access; it writes one short-lived key on the broker, inside
the keyspace its pool's broker user may already write (``asm.pool.<pool>.*``):

    asm.pool.<pool>.health.<host>-<pid>   (JSON, expires after 120 s, refreshed every 30 s)

The report carries versions (application, engines), the detection content on disk
(template count and newest file), whether the screenshot browser is installed, the last
job, and the last warnings/errors this process logged (already redacted). Engine names
are in it: the platform shows this report to platform administrators only.
"""

from __future__ import annotations

import collections
import contextlib
import json
import logging
import os
import socket
import subprocess
import threading
import time
from datetime import UTC, datetime
from typing import Any

from . import __version__
from .eventlog import EventFormatter

INTERVAL = 30
TTL = 120
RULES_REFRESH = 600
ENGINES = ("subfinder", "dnsx", "httpx", "naabu", "nuclei", "amass")
_recent: collections.deque[dict[str, Any]] = collections.deque(maxlen=20)
_last_job: dict[str, Any] = {}
_rules: dict[str, Any] = {}
_engines: dict[str, str] = {}


class RecentErrors(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.fmt = EventFormatter("scanner", __version__)

    def emit(self, record: logging.LogRecord) -> None:
        with contextlib.suppress(Exception):
            ev = self.fmt.event(record)
            _recent.append({k: ev.get(k) for k in ("ts", "level", "event", "error_code", "msg", "job_id")})


def job_finished(status: str) -> None:
    _last_job.update(ts=datetime.now(UTC).isoformat(), status=status)


def _engine_versions() -> dict[str, str]:
    out = {}
    for name in ENGINES:
        try:
            p = subprocess.run([name, "-version"], capture_output=True, timeout=10, check=False)  # noqa: S603
            text = (p.stdout + p.stderr).decode("utf-8", "replace").strip().splitlines()
            out[name] = (text[-1] if text else "unknown")[:120]
        except (OSError, subprocess.SubprocessError):
            out[name] = "not installed"
    return out


def _count_rules() -> dict[str, Any]:
    root = os.environ.get("ASM_NUCLEI_TEMPLATES_DIR", "")
    if not root or not os.path.isdir(root):
        return {"available": False, "count": 0, "newest": None, "reason": "detection content directory is missing"}
    count, newest = 0, 0.0
    for base, _dirs, files in os.walk(root):
        for f in files:
            if f.endswith((".yaml", ".yml")):
                count += 1
                with contextlib.suppress(OSError):
                    newest = max(newest, os.path.getmtime(os.path.join(base, f)))
    return {"available": count > 0, "count": count,
            "newest": datetime.fromtimestamp(newest, UTC).isoformat() if newest else None,
            "reason": None if count else "detection content is not installed"}


def _browser() -> dict[str, Any]:
    try:
        from .adapters.screenshot import browser_binary

        return {"installed": True, "binary": os.path.basename(browser_binary())}
    except Exception:  # noqa: BLE001
        return {"installed": False}


def report(pool: str) -> dict[str, Any]:
    return {"schema": "exteriq.scanner-health/1", "ts": datetime.now(UTC).isoformat(), "pool": pool,
            "host": socket.gethostname(), "pid": os.getpid(), "version": __version__, "engines": dict(_engines),
            "detection_rules": dict(_rules), "browser": _browser(), "last_job": dict(_last_job),
            "recent_errors": list(_recent)}


def start(pool: str, broker_url: str) -> threading.Thread:
    """Start the heartbeat thread (idempotent per process)."""
    def run() -> None:
        import redis

        client = redis.Redis.from_url(broker_url, socket_timeout=5, socket_connect_timeout=5)
        key = f"asm.pool.{pool}.health.{socket.gethostname()}-{os.getpid()}"
        _engines.update(_engine_versions())
        last_rules = 0.0
        while True:
            if time.monotonic() - last_rules > RULES_REFRESH or not _rules:
                _rules.clear()
                _rules.update(_count_rules())
                last_rules = time.monotonic()
            with contextlib.suppress(Exception):  # the broker is down: try again next round
                client.set(key, json.dumps(report(pool)), ex=TTL)
            time.sleep(INTERVAL)

    t = threading.Thread(target=run, name="exteriq-scanner-health", daemon=True)
    t.start()
    return t
