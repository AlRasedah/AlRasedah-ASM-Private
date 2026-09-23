"""What the scanners look like on the wire.

Traffic that carries the product's name tells anyone watching — a target's blue
team, but also anyone who wants to fingerprint or evade the platform — exactly
what is scanning them and which tools it wraps. Both the request header and the
user agent are therefore deployment settings:

* ``ASM_SCANNER_IDENTITY`` — an identifying request header for active scans.
  Empty (the default) sends none. Set it to ``value`` for ``X-Scanner: value``,
  or to a complete ``Header: value`` line to choose the header name too. Useful
  when a customer's SOC needs to recognise authorized scanning.
* ``ASM_SCANNER_USER_AGENT`` — the user agent for the platform's own API calls
  (certificate logs, exposure databases, the web application scanner's control
  API). Defaults to a neutral string that does not name the product.
"""

from __future__ import annotations

from typing import Any

DEFAULT_USER_AGENT = "Mozilla/5.0 (compatible; security-scanner)"
DEFAULT_HEADER_NAME = "X-Scanner"


def user_agent(settings: dict[str, Any] | None = None) -> str:
    configured = str((settings or {}).get("scanner_user_agent") or "").strip()
    return configured if configured and "\n" not in configured else DEFAULT_USER_AGENT


def identity_header(settings: dict[str, Any] | None = None) -> str | None:
    """``"Header: value"`` for tools that take raw headers, or None when disabled."""
    raw = str((settings or {}).get("scanner_identity") or "").strip()
    if not raw:
        return None
    if ":" in raw:
        name, _, value = raw.partition(":")
        name, value = name.strip(), value.strip()
    else:
        name, value = DEFAULT_HEADER_NAME, raw
    if not name or not value or any(c in raw for c in "\r\n"):
        return None
    return f"{name}: {value}"
