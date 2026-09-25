"""Configure logging for one platform process (API, core worker, ingest, scheduler, CLI)."""

from __future__ import annotations

import logging
import os
import sys

from asm_sensors import eventlog

from app import __version__

SERVICES = ("api", "worker", "ingest", "scheduler", "cli", "migrate")


def service_name(default: str = "worker") -> str:
    """ASM_SERVICE when set (compose and systemd units set it), else inferred from argv."""
    env = os.environ.get("ASM_SERVICE", "").strip().lower()
    if env in SERVICES:
        return env
    argv = " ".join(sys.argv).lower()
    if " beat" in argv or argv.endswith("beat"):
        return "scheduler"
    if "results" in argv:
        return "ingest"
    return default


def configure(service: str | None = None) -> None:
    from app.core.config import get_settings

    s = get_settings()
    name = service or service_name()
    handlers: list[logging.Handler] = []
    if name in ("api", "worker", "ingest", "scheduler") and os.environ.get("ASM_OPS_EVENTS", "true") != "false":
        from app.observability.opsdb import OpsEventHandler

        handlers.append(OpsEventHandler(name, __version__))
    eventlog.configure(name, __version__, s.log_level, s.log_json, extra_handlers=handlers)
