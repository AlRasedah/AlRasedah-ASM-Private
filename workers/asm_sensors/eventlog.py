"""Operational event logging shared by every Exteriq process (platform and scanners).

One JSON object per line on stdout, schema ``exteriq.event/1`` (docs/LOGGING.md):

    {"schema": "exteriq.event/1", "ts": "2026-09-25T10:00:00.123Z", "event_id": "…",
     "event": "scan.stage.finished", "level": "INFO", "stream": "scans",
     "service": "worker", "version": "0.1.0", "logger": "exteriq.scans", "msg": "…",
     "tenant_id": "…", "request_id": "…", "correlation_id": "…", "scan_id": "…",
     "stage_id": "…", "job_id": "…", "pool": "default", "error_code": "…",
     "duration_ms": 1234, "target_count": 5, "retries": 0, "coverage": "complete", …}

Only allowlisted fields are ever written: a record's unknown ``extra`` attributes are
dropped (and counted in ``dropped_fields``), never serialized. The finished event is then
redacted as a whole — message, exception, nested values and URLs — before it is written.

The ``stream`` decides where a native install files the event (journald → rsyslog →
``/var/log/exteriq/<stream>.json``): ``application`` (default), ``scans``, ``alerts`` and
``audit``; every WARNING and above is also filed in ``errors.json``. Operational ``level``
is never a finding's severity — findings carry ``severity`` separately.

Correlation: :func:`bind` / :func:`annotate` put tenant, request, scan, stage, job and pool
ids in a context variable that every event picks up. The context is a small mutable dict
per request or task (so a value set by an authentication dependency running in a worker
thread is seen by the whole request) and is replaced — never inherited — at the start of
each request and task.

Writing never blocks the caller: events go through a bounded in-memory queue to a writer
thread. When the queue is full (stdout stalled, collector down) events are dropped and
counted; the count is reported by the next event that gets through and on shutdown.
"""

from __future__ import annotations

import atexit
import contextlib
import json
import logging
import os
import queue
import re
import sys
import threading
import traceback
import uuid
from collections.abc import Iterator
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Any, TextIO

SCHEMA = "exteriq.event/1"
STREAMS = ("application", "scans", "alerts", "audit")
MAX_EVENT_BYTES = 16 * 1024
QUEUE_SIZE = 10_000

# Correlation fields, taken from the bound context (or explicitly from a record's extra).
CONTEXT_FIELDS = ("tenant_id", "organization_id", "user_id", "request_id", "correlation_id", "task_id", "task",
                  "scan_id", "stage_id", "job_id", "pool")
# Everything else an event may carry. Anything not listed here is never serialized.
EXTRA_FIELDS = (
    "event", "stream", "error_code", "status", "coverage", "duration_ms", "queue_wait_ms", "execution_ms",
    "ingestion_ms", "target_count", "rejected_count", "observation_count", "retries", "attempt", "count",
    "queue", "http_status", "method", "route", "component", "component_version", "severity", "finding_id",
    "asset_id", "activity", "advisory_id", "capture_id", "bundle_id", "action", "object_type", "object_id",
    "actor", "success", "chain_seq", "entry_hash", "previous", "new", "title", "rule_id", "stage_type",
    "adapter", "reason", "limit", "size_bytes", "data",
)
_ID = re.compile(r"^[A-Za-z0-9._:@-]{1,128}$")

# ---------------------------------------------------------------- redaction
_SECRET_KEY = re.compile(r"(pass(word|wd)?|secret|token|authori[sz]ation|cookie|api[_-]?key|apikey|credential|"
                         r"private[_-]?key|session|dsn|connection[_-]?string|signature)", re.I)
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    # scheme://user:password@host → scheme://[redacted]@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1[redacted]@"),
    # query / form values whose name says secret
    (re.compile(r"(?i)([?&;\s]|^)((?:access_|refresh_|id_)?(?:token|key|api_?key|apikey|secret|password|pass|pwd|"
                r"auth|signature|sig|session|code|replacement)=)[^&\s\"'<>]+"), r"\1\2[redacted]"),
    # header-style lines
    (re.compile(r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token)"
                r"(\"?\s*[:=]\s*\"?)[^\"\n]+"), r"\1\2[redacted]"),
    (re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [redacted]"),
    # key: value / key=value pairs in free text
    (re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|token|private[_-]?key)(\s*[:=]\s*)(?!\[redacted\])"
                r"[^\s,;&\"']+"), r"\1\2[redacted]"),
    # JSON web tokens and PEM private keys wherever they appear
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[redacted-jwt]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[redacted-key]"),
]


def redact_text(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


def redact(value: Any, depth: int = 0) -> Any:
    """Redact a whole structure: sensitive keys lose their values, every string is scrubbed."""
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        return {str(k)[:64]: ("[redacted]" if _SECRET_KEY.search(str(k)) and not isinstance(v, bool | int | float)
                              and str(k) not in ("request_id", "correlation_id", "task_id", "error_code")
                              else redact(v, depth + 1)) for k, v in list(value.items())[:100]}
    if isinstance(value, list | tuple | set):
        return [redact(v, depth + 1) for v in list(value)[:100]]
    if isinstance(value, str):
        return redact_text(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    return redact_text(str(value))


# ----------------------------------------------------------------- context
_CTX: ContextVar[dict[str, Any] | None] = ContextVar("exteriq_event_ctx", default=None)


def current() -> dict[str, Any]:
    return dict(_CTX.get() or {})


def _clean_id(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value)
    return s if _ID.match(s) else None


def bind(**fields: Any) -> Token:
    """Start a fresh context (a request, a task, a job). Use :func:`reset` with the token."""
    return _CTX.set({k: v for k in CONTEXT_FIELDS if (v := _clean_id(fields.get(k))) is not None})


def reset(token: Token) -> None:
    with contextlib.suppress(ValueError, RuntimeError):
        _CTX.reset(token)


def clear() -> None:
    _CTX.set(None)


def annotate(**fields: Any) -> None:
    """Add to the current context in place (visible to everything sharing this request/task)."""
    ctx = _CTX.get()
    if ctx is None:
        ctx = {}
        _CTX.set(ctx)
    for k, v in fields.items():
        if k in CONTEXT_FIELDS and (clean := _clean_id(v)) is not None:
            ctx[k] = clean


@contextlib.contextmanager
def bound(**fields: Any) -> Iterator[None]:
    token = bind(**{**current(), **fields})
    try:
        yield
    finally:
        reset(token)


# --------------------------------------------------------------- formatting
# Every write to the process's output stream holds this, so lines are never interleaved.
_stream_lock = threading.Lock()


class _LineQueue(queue.Queue):  # type: ignore[type-arg]
    """The bounded hand-off between callers and one writer thread. Lines that could not be
    queued (full, or unformattable) are counted here, per writer, and the writer reports the
    count before the next line that does get through."""

    def __init__(self, maxsize: int) -> None:
        super().__init__(maxsize=maxsize)
        self._dropped = 0
        self._dropped_lock = threading.Lock()

    def count_drop(self) -> None:
        with self._dropped_lock:
            self._dropped += 1

    def take_drops(self) -> int:
        with self._dropped_lock:
            n, self._dropped = self._dropped, 0
        return n

    @property
    def dropped(self) -> int:
        return self._dropped


def _exception(exc_info: Any) -> dict[str, Any] | None:
    if not exc_info or not exc_info[0]:
        return None
    etype, evalue, tb = exc_info
    frames = [f"{os.path.basename(f.filename)}:{f.lineno} in {f.name}" for f in traceback.extract_tb(tb)][-20:]
    return {"type": getattr(etype, "__name__", str(etype)), "message": str(evalue)[:2000], "frames": frames}


class EventFormatter(logging.Formatter):
    def __init__(self, service: str, version: str) -> None:
        super().__init__()
        self.service, self.version = service, version

    def event(self, record: logging.LogRecord) -> dict[str, Any]:
        ev: dict[str, Any] = {
            "schema": SCHEMA,
            "ts": datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%S.") +
            f"{int(record.msecs):03d}Z",
            "event_id": str(getattr(record, "event_id", "") or uuid.uuid4().hex)[:80],
            "event": str(getattr(record, "event", "") or record.name)[:120],
            "level": record.levelname,
            "stream": getattr(record, "stream", None) if getattr(record, "stream", None) in STREAMS else (
                "scans" if record.name.startswith("exteriq.scans") else "application"),
            "service": self.service,
            "version": self.version,
            "logger": record.name[:120],
            "msg": record.getMessage()[:4000],
        }
        ctx = _CTX.get() or {}
        for k in CONTEXT_FIELDS:
            v = _clean_id(getattr(record, k, None)) or ctx.get(k)
            if v:
                ev[k] = v
        for k in EXTRA_FIELDS:
            if k in ("event", "stream"):
                continue
            if hasattr(record, k):
                ev[k] = getattr(record, k)
        known = set(CONTEXT_FIELDS) | set(EXTRA_FIELDS) | {"event_id"}
        dropped = [k for k in record.__dict__ if k not in _STANDARD and k not in known and not k.startswith("_")]
        if dropped:
            ev["dropped_fields"] = len(dropped)
        exc = _exception(record.exc_info)
        if exc:
            ev["exc"] = exc
        return redact(ev)

    def format(self, record: logging.LogRecord) -> str:
        ev = self.event(record)
        line = json.dumps(ev, ensure_ascii=False, default=str, separators=(",", ":"))
        if len(line.encode()) > MAX_EVENT_BYTES:
            ev["msg"] = ev["msg"][:1000]
            if "exc" in ev:
                ev["exc"]["frames"] = ev["exc"]["frames"][-5:]
                ev["exc"]["message"] = ev["exc"]["message"][:500]
            for k in ("previous", "new", "data"):
                if k in ev:
                    ev[k] = "[truncated]"
            ev["truncated"] = True
            line = json.dumps(ev, ensure_ascii=False, default=str, separators=(",", ":"))[:MAX_EVENT_BYTES]
        return line


_STANDARD = set(logging.LogRecord("x", 0, "", 0, "", (), None).__dict__) | {"message", "asctime", "taskName"}


# ------------------------------------------------------------------ writing
class _QueueHandler(logging.Handler):
    """Formats in the caller (so context is captured) and hands the line to a writer thread."""

    def __init__(self, q: _LineQueue) -> None:
        super().__init__()
        self.q = q

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = self.format(record)
        except Exception:  # noqa: BLE001 - a bad record must never break the caller
            self.q.count_drop()
            return
        try:
            self.q.put_nowait(line)
        except queue.Full:
            self.q.count_drop()


class _Writer:
    def __init__(self, stream: TextIO) -> None:
        self.stream = stream
        self.q = _LineQueue(QUEUE_SIZE)
        self.thread: threading.Thread | None = None
        self.start()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name="exteriq-event-writer", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        q = self.q
        while True:
            line = q.get()
            if line is None:
                return
            try:
                drops = q.take_drops()
                with _stream_lock:  # whole lines only, even with write_sync() writing too
                    if drops:  # said before the next line that does get through
                        self.stream.write(_drop_event(drops) + "\n")
                    self.stream.write(line + "\n")
                    self.stream.flush()
            except Exception:  # noqa: BLE001 - stdout closed or broken: count, keep draining
                q.count_drop()

    def after_fork(self) -> None:
        # A forked child (Celery prefork) inherits the queue but not the thread.
        self.q = _LineQueue(QUEUE_SIZE)
        for h in logging.getLogger().handlers:
            if isinstance(h, _QueueHandler):
                h.q = self.q
        self.start()

    def close(self, timeout: float = 2.0) -> None:
        with contextlib.suppress(queue.Full):
            self.q.put_nowait(None)
        if self.thread is not None:
            self.thread.join(timeout)
        drops = self.q.take_drops()
        if drops:
            with contextlib.suppress(Exception):
                self.stream.write(_drop_event(drops) + "\n")
                self.stream.flush()


def _drop_event(count: int) -> str:
    return json.dumps({"schema": SCHEMA, "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                       "event_id": uuid.uuid4().hex, "event": "logging.events_dropped", "level": "WARNING",
                       "stream": "application", "error_code": "ASM-OPS-003", "count": count,
                       "msg": f"{count} log event(s) were dropped: the log writer could not keep up"})


_writer: _Writer | None = None


def configure(service: str, version: str, level: str = "INFO", json_logs: bool = True,
              stream: TextIO | None = None, extra_handlers: list[logging.Handler] | None = None) -> None:
    """Route every log record of this process through the event formatter. Idempotent."""
    global _writer
    root = logging.getLogger()
    if json_logs:
        if _writer is None:
            _writer = _Writer(stream or sys.stdout)
            atexit.register(_writer.close)
            if hasattr(os, "register_at_fork"):
                os.register_at_fork(after_in_child=lambda: _writer.after_fork() if _writer else None)
        handler: logging.Handler = _QueueHandler(_writer.q)
        handler.setFormatter(EventFormatter(service, version))
    else:
        handler = logging.StreamHandler(stream or sys.stdout)
        handler.setFormatter(_PlainFormatter())
    root.handlers[:] = [handler, *(extra_handlers or [])]
    root.setLevel(level.upper())
    for noisy in ("httpx", "httpcore", "urllib3", "urllib3.connectionpool", "kombu", "amqp"):
        logging.getLogger(noisy).setLevel("WARNING")


class _PlainFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ctx = " ".join(f"{k}={v}" for k, v in (_CTX.get() or {}).items() if k in ("tenant_id", "scan_id", "request_id"))
        line = f"{datetime.fromtimestamp(record.created, UTC).isoformat()} {record.levelname} {record.name} " \
               f"{redact_text(record.getMessage())}{' ' + ctx if ctx else ''}"
        if record.exc_info:
            exc = _exception(record.exc_info) or {}
            line += f" [{exc.get('type')}: {redact_text(str(exc.get('message')))}]"
        return line


def flush(timeout: float = 2.0) -> None:
    """Wait (bounded) until queued events are written — for tests and orderly shutdown."""
    if _writer is None:
        return
    deadline = threading.Event()
    end = datetime.now(UTC).timestamp() + timeout
    while not _writer.q.empty() and datetime.now(UTC).timestamp() < end:
        deadline.wait(0.01)


def write_sync(logger_name: str, level: int, msg: str, **fields: Any) -> bool:
    """Write one event directly (bypassing the queue) and report whether stdout accepted it.

    For exports whose source marks a row as exported only after a successful write
    (alerts, audit): a dropped event there would be a lost committed event."""
    record = logging.LogRecord(logger_name, level, "", 0, msg, (), None)
    for k, v in fields.items():
        setattr(record, k, v)
    fmt = _formatter()
    if fmt is None:
        return False
    try:
        line = fmt.format(record)
        out = _writer.stream if _writer is not None else sys.stdout
        with _stream_lock:
            out.write(line + "\n")
            out.flush()
        return True
    except Exception:  # noqa: BLE001 - reported as a failed export by the caller
        return False


def _formatter() -> EventFormatter | None:
    for h in logging.getLogger().handlers:
        if isinstance(h.formatter, EventFormatter):
            return h.formatter
    return EventFormatter("unconfigured", "0")
