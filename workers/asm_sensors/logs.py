"""Keep secrets out of the sensor worker's logs.

Sensors talk to APIs that take a credential as a query parameter — Shodan accepts
its key no other way — and HTTP clients log the request line, URL and all, at INFO.
That copy is outside every protection the platform has: the key is encrypted at
rest, sealed in the job envelope and scrubbed from returned errors, and then
written verbatim to stdout by a library.

So the worker silences routine request logging before any client exists, and
redacts anything sensitive that still reaches a record.
"""

from __future__ import annotations

import logging
import re

# Query parameters whose value is a secret, wherever they appear in a logged line.
_SENSITIVE = re.compile(
    r"(?i)\b(key|apikey|api_key|token|secret|password|replacement|auth)=([^&\s\"'>]+)")
_REDACTED = r"\1=[redacted]"

# These log one line per request, including the full URL with its query string.
_CHATTY = ("httpx", "httpcore", "urllib3", "urllib3.connectionpool")


def redact(text: str) -> str:
    return _SENSITIVE.sub(_REDACTED, text)


class RedactingFilter(logging.Filter):
    """Last line of defence: redact secrets in any record, whoever emitted it.

    The message is rendered first and the result redacted, rather than the format
    string and the arguments separately: a secret is usually an argument, and
    redacting ``"...?key=%s"`` would delete the placeholder and break formatting.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg, record.args = redacted, ()
        return True


def configure() -> None:
    """Call once, before any HTTP client is created. Safe to call repeatedly."""
    for name in _CHATTY:
        logging.getLogger(name).setLevel(logging.WARNING)
    root = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for f in root.filters):
        root.addFilter(RedactingFilter())
    # A filter on the root logger does not apply to records from child loggers, so
    # attach it where the records are actually written out.
    for handler in root.handlers:
        if not any(isinstance(f, RedactingFilter) for f in handler.filters):
            handler.addFilter(RedactingFilter())
