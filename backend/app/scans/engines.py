"""Engine identity: capability labels for people, opaque tokens for the wire.

The product describes what it does in its own terms ("Exposed service
discovery"). *Which* open-source engine implements a capability is an
implementation detail, and an implementation detail that leaks tells anyone
with the browser's network tab which tools to study, fingerprint or evade. So:

* every stage carries a neutral capability **label** (the adapter's display
  name, which never names the tool);
* API responses identify engines by an opaque **token** — an HMAC of the engine
  name under the deployment's secret key, so tokens differ per deployment and
  cannot be mapped back by inspecting traffic. The profile editor round-trips
  the token; the API still accepts real engine names, so scripts and the CLI
  keep working.

Sanitizing user-visible text is the other half of this and lives in
:mod:`app.scans.messages`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from functools import lru_cache

from asm_sensors.registry import describe_adapters, get_adapter

from app.core.config import get_settings


def token_for(engine: str) -> str:
    digest = hmac.new(get_settings().secret_key.get_secret_value().encode(), f"engine:{engine}".encode(),
                      hashlib.sha256)
    return "eng_" + digest.hexdigest()[:16]


@lru_cache(maxsize=1)
def _by_token() -> dict[str, str]:
    return {token_for(a["name"]): a["name"] for a in describe_adapters()}


def engine_for(value: str) -> str:
    """Resolve a token (or a plain engine name) to the engine name."""
    return _by_token().get(value, value)


def label_for(engine: str, fallback: str = "") -> str:
    """The capability label shown to users — never the engine's own name."""
    try:
        return get_adapter(engine).display_name
    except KeyError:
        return fallback or "Scan stage"


def sanitize_schema(schema: dict, display_name: str) -> dict:
    """A configuration schema with the engine's own names taken out.

    Pydantic titles the model after its class (``NucleiConfig``), and nested models
    carry their own titles, so the schema is as revealing as the engine name itself.
    """
    text = json.dumps(schema)
    for name in _engine_words():
        text = re.sub(re.escape(name), "Capability", text, flags=re.IGNORECASE)
    out = json.loads(text)
    out["title"] = display_name
    return out


@lru_cache(maxsize=1)
def _engine_words() -> tuple[str, ...]:
    """Engine names and the tool names behind them, longest first (so substrings don't win)."""
    words = {a["name"] for a in describe_adapters()}
    words.update({"nuclei", "subfinder", "amass", "dnsx", "httpx", "naabu", "zaproxy", "zap", "spiderfoot",
                  "bbot", "shodan", "crtsh", "asnlookup", "projectdiscovery", "owasp"})
    return tuple(sorted(words, key=len, reverse=True))


def accepts_login(engine: str) -> bool:
    """Whether this engine can use a sign-in cookie/token supplied for a scan."""
    try:
        return "zap_auth" in get_adapter(engine).credential_providers
    except KeyError:
        return False
