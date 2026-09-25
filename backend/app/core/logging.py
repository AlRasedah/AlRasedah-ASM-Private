"""Structured logging with secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
from contextvars import ContextVar
from datetime import UTC, datetime

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)

_SENSITIVE_KEYS = re.compile(r"(password|secret|token|authorization|api[_-]?key|cookie|credential)", re.IGNORECASE)
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", re.IGNORECASE)
_KV = re.compile(r"((?:password|secret|token|api[_-]?key)\s*[=:]\s*)([^\s,;&]+)", re.IGNORECASE)


def redact(value: object) -> object:
    if isinstance(value, dict):
        return {k: ("***" if _SENSITIVE_KEYS.search(str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _KV.sub(r"\1***", _BEARER.sub(r"\1***", value))
    return value


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)  # type: ignore[assignment]
        if record.args:
            args = record.args
            record.args = tuple(redact(a) for a in args) if isinstance(args, tuple) else redact(args)  # type: ignore[assignment]
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        rid = request_id_var.get()
        if rid:
            payload["request_id"] = rid
        for key in ("tenant_id", "scan_id", "stage_id", "event"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", json_logs: bool = True, service: str = "api") -> None:
    """Every process now logs ``exteriq.event/1`` events (see app/observability, docs/LOGGING.md).

    ``redact``, ``RedactingFilter`` and ``JsonFormatter`` above stay for the audit log's
    value redaction (its output is part of the hash chain) and for compatibility."""
    from app.observability.setup import configure

    configure(service)
