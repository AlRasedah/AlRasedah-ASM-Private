"""Recent operational warnings and errors, kept in the database for the Diagnostics page.

The web process has no access to the host's logs (and must not have). Instead each
platform process copies its own WARNING-and-above events — already redacted, same
schema as the log line — into ``ops_events`` (platform-only table, RLS: system sessions
only), from a background thread with a bounded buffer. When the database is unavailable
the buffer drops its oldest events and counts them; the log line on stdout is still the
authoritative copy. Retention: 14 days and 50 000 rows (maintenance).
"""

from __future__ import annotations

import atexit
import collections
import logging
import os
import threading
from datetime import UTC, datetime
from typing import Any

from asm_sensors.eventlog import CONTEXT_FIELDS, EventFormatter

BUFFER = 500
FLUSH_SECONDS = 3.0
RETENTION_DAYS = 14
MAX_ROWS = 50_000
_IGNORED = ("sqlalchemy", "app.observability.opsdb", "psycopg")
_guard = threading.local()


class OpsEventHandler(logging.Handler):
    def __init__(self, service: str, version: str) -> None:
        super().__init__(level=logging.WARNING)
        self.fmt = EventFormatter(service, version)
        self.buffer: collections.deque[dict[str, Any]] = collections.deque(maxlen=BUFFER)
        self.dropped = 0
        self._buf_lock = threading.Lock()
        self.wake = threading.Event()
        self._start()
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._after_fork)
        atexit.register(self.flush_now)

    def _start(self) -> None:
        threading.Thread(target=self._run, name="exteriq-ops-events", daemon=True).start()

    def _after_fork(self) -> None:
        self.buffer.clear()
        self._buf_lock = threading.Lock()
        self.wake = threading.Event()
        self._start()

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(_guard, "active", False) or record.name.startswith(_IGNORED):
            return
        try:
            ev = self.fmt.event(record)
        except Exception:  # noqa: BLE001
            return
        with self._buf_lock:
            if len(self.buffer) == self.buffer.maxlen:
                self.dropped += 1
            self.buffer.append(ev)

    def _run(self) -> None:
        while True:
            self.wake.wait(FLUSH_SECONDS)
            self.wake.clear()
            self.flush_now()

    def flush_now(self) -> None:
        with self._buf_lock:
            batch, self.buffer = list(self.buffer), collections.deque(maxlen=BUFFER)
            dropped, self.dropped = self.dropped, 0
        if dropped:
            batch.append({"event_id": os.urandom(16).hex(), "ts": datetime.now(UTC).isoformat(), "level": "WARNING",
                          "service": self.fmt.service, "event": "ops_events.dropped", "error_code": "ASM-OPS-002",
                          "msg": f"{dropped} operational event(s) could not be kept for the Diagnostics page",
                          "count": dropped})
        if not batch:
            return
        _guard.active = True
        try:
            store(batch)
        except Exception:  # noqa: BLE001 - the database is down: keep a bounded backlog
            with self._buf_lock:
                for ev in batch[-BUFFER:]:
                    if len(self.buffer) == self.buffer.maxlen:
                        self.dropped += 1
                    self.buffer.appendleft(ev)
        finally:
            _guard.active = False


def _row(ev: dict[str, Any]) -> dict[str, Any]:
    ts = ev.get("ts")
    try:
        when = datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if ts else datetime.now(UTC)
    except ValueError:
        when = datetime.now(UTC)
    data = {k: v for k, v in ev.items() if k not in (
        "schema", "ts", "event_id", "level", "service", "event", "error_code", "msg", "logger", *CONTEXT_FIELDS)}
    return {
        "event_id": str(ev.get("event_id") or os.urandom(16).hex())[:80], "ts": when,
        "level": str(ev.get("level") or "WARNING")[:16], "service": str(ev.get("service") or "")[:32],
        "event": str(ev.get("event") or "")[:120], "error_code": (ev.get("error_code") or None),
        "message": str(ev.get("msg") or "")[:2000], "logger": str(ev.get("logger") or "")[:120],
        "tenant_id": ev.get("tenant_id"), "request_id": ev.get("request_id"), "scan_id": ev.get("scan_id"),
        "stage_id": ev.get("stage_id"), "job_id": ev.get("job_id"), "pool": ev.get("pool"), "data": data,
    }


def store(events: list[dict[str, Any]]) -> None:
    from sqlalchemy.dialects.postgresql import insert

    from app.db.session import system_session
    from app.models import OpsEvent

    rows = [_row(e) for e in events]
    for r in rows:
        for k in ("tenant_id", "scan_id", "stage_id"):
            r[k] = _uuid(r[k])
    with system_session() as db:
        db.execute(insert(OpsEvent).values(rows).on_conflict_do_nothing(index_elements=["event_id"]))
        db.commit()


def _uuid(value: Any) -> Any:
    import uuid

    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def prune(db: Any, now: datetime | None = None) -> int:
    """Maintenance: age and size limits."""
    from datetime import timedelta

    from sqlalchemy import delete, func, select

    from app.models import OpsEvent

    now = now or datetime.now(UTC)
    n = db.execute(delete(OpsEvent).where(OpsEvent.ts < now - timedelta(days=RETENTION_DAYS))).rowcount or 0
    count = db.scalar(select(func.count()).select_from(OpsEvent)) or 0
    if count > MAX_ROWS:
        cutoff = db.scalar(select(OpsEvent.id).order_by(OpsEvent.id.desc()).offset(MAX_ROWS).limit(1))
        if cutoff is not None:
            n += db.execute(delete(OpsEvent).where(OpsEvent.id <= cutoff)).rowcount or 0
    return n
