"""Correlation across Celery: every task starts with a fresh context and ends with none.

Publishing a task (platform tasks and scanner jobs alike) copies the *correlation* ids —
request, correlation — into a message header, plus the publish time (queue age). Tenant,
scan and stage ids are never taken from a header: a task binds them after loading the
records it acts on (``eventlog.annotate``), so identity always comes from the database or
from a validated job binding.
"""

from __future__ import annotations

import time
from typing import Any

from asm_sensors import eventlog
from celery import signals

HEADER = "exteriq_ctx"
_connected = False


def _publish(headers: dict[str, Any] | None = None, **_: Any) -> None:
    if headers is None:
        return
    ctx = eventlog.current()
    headers[HEADER] = {k: ctx[k] for k in ("request_id", "correlation_id") if ctx.get(k)}
    headers[HEADER]["published"] = round(time.time(), 3)


def _task_ctx(task: Any) -> dict[str, Any]:
    req = getattr(task, "request", None)
    raw = getattr(req, HEADER, None) or (getattr(req, "headers", None) or {}).get(HEADER) or {}
    return raw if isinstance(raw, dict) else {}


def _prerun(task_id: str | None = None, task: Any = None, **_: Any) -> None:
    header = _task_ctx(task)
    eventlog.bind(task_id=task_id, task=getattr(task, "name", None),
                  request_id=header.get("request_id"),
                  correlation_id=header.get("correlation_id") or header.get("request_id") or task_id)


def _postrun(**_: Any) -> None:
    eventlog.clear()


def _setup_logging(**_: Any) -> None:
    from app.observability.setup import configure

    configure()


def _heartbeat(**_: Any) -> None:
    import os

    if os.environ.get("ASM_HEARTBEAT", "true").lower() == "false":
        return
    from app.observability.health import start_heartbeat
    from app.observability.setup import service_name

    start_heartbeat(service_name())


def connect() -> None:
    """Idempotent; called by every platform Celery app module."""
    global _connected
    if _connected:
        return
    signals.before_task_publish.connect(_publish, weak=False)
    signals.task_prerun.connect(_prerun, weak=False)
    signals.task_postrun.connect(_postrun, weak=False)
    # Our handler replaces Celery's own logging setup (the app sets worker_hijack_root_logger=False).
    signals.setup_logging.connect(_setup_logging, weak=False)
    # Heartbeats for the Diagnostics page: the main process, every forked child, and beat.
    signals.worker_ready.connect(_heartbeat, weak=False)
    signals.worker_process_init.connect(_heartbeat, weak=False)
    signals.beat_init.connect(_heartbeat, weak=False)
    _connected = True
