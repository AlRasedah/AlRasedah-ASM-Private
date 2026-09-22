"""Turn sensor errors into something a user can act on.

Raw sensor output is written for whoever wrote the tool: ``nuclei exit code 1:
[FTL] Could not run nuclei: no templates provided for scan``. Shown in the
product it is two problems at once — it says nothing useful to the person
reading it, and it names the engine, which is an implementation detail (see
:mod:`app.scans.engines`).

Every message a stage shows therefore goes through :func:`friendly`, which maps
the failures we know to an explanation and a next step, and otherwise reports
the capability that failed without the tool's name. The raw text stays in the
worker logs for whoever operates the deployment.
"""

from __future__ import annotations

import re

# (pattern, replacement) — first match wins. Patterns are matched case-insensitively
# against one error line.
_KNOWN: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"no templates provided|templates directory.*empty|no templates were found", re.I),
     "Detection content is not installed yet. It downloads when the scanner starts (about 1 GB) — check that the "
     "scanner has internet access, then run the scan again."),
    (re.compile(r"is not installed in this sensor worker|BinaryNotFound", re.I),
     "This capability is not installed in the scanner deployed here."),
    # Most specific first: several capabilities report "not enabled in this deployment".
    (re.compile(r"(open-source intelligence|osint|spiderfoot).{0,40}not enabled|spiderfoot_url", re.I),
     "Open-source intelligence enrichment is not enabled in this deployment."),
    (re.compile(r"(web application scanner|zap).{0,40}not enabled|zap_url unset|integration is not enabled", re.I),
     "The web application scanner is not enabled in this deployment."),
    (re.compile(r"not enabled in this deployment", re.I),
     "This capability is not enabled in this deployment."),
    (re.compile(r"no Shodan API key|api key is configured for this tenant", re.I),
     "No API key is stored for this data source (Integrations → Data-source API keys)."),
    (re.compile(r"key was rejected|HTTP 401|HTTP 403|Invalid API key", re.I),
     "The stored API key for this data source was rejected. Check it under Integrations → Data-source API keys."),
    (re.compile(r"rate limit", re.I),
     "The data source rate-limited this scan, so its results are incomplete."),
    (re.compile(r"HTTPStatusError|HTTP \d{3}|ConnectError|ConnectTimeout|ReadTimeout|unreachable", re.I),
     "A data source did not answer, so its results are incomplete."),
    (re.compile(r"timed out|TimeoutError|deadline", re.I),
     "This stage ran out of time before it finished, so its results are incomplete."),
    (re.compile(r"output exceeded the capture limit", re.I),
     "This stage produced more output than the deployment's limit allows, so its results are incomplete."),
    (re.compile(r"stayed busy with another job", re.I),
     "The web application scanner was busy with another scan and could not run here."),
    (re.compile(r"cannot sign in to the application|missing the request-replacer", re.I),
     "The scanner could not sign in to the application, so the pages behind the login were not tested. The web "
     "application scanner in this deployment is missing the component that injects the sign-in header — install it, "
     "or run the scan without a sign-in value."),
    (re.compile(r"credential envelope|failed authentication", re.I),
     "The scanner could not open this job's credentials. Check that the platform and scanner keys match."),
    (re.compile(r"egress policy", re.I),
     "Some targets were not scanned because they resolve to addresses this deployment may not contact."),
    (re.compile(r"not scanned by egress policy", re.I),
     "Some targets were not scanned because they resolve to addresses this deployment may not contact."),
]

_FALLBACK = "This stage did not finish successfully."
# Engine and tool names must never reach the interface, even inside an unmapped message.
_ENGINE_WORDS = re.compile(
    r"\b(nuclei|subfinder|amass|dnsx|httpx|naabu|zap|zaproxy|spiderfoot|bbot|shodan|crt\.?sh|asnlookup|"
    r"projectdiscovery|owasp)\b", re.I)


def friendly(messages: list[str] | str | None, capability: str = "") -> str | None:
    """One readable sentence per distinct problem, with no engine names in it."""
    if not messages:
        return None
    lines = [messages] if isinstance(messages, str) else list(messages)
    out: list[str] = []
    for line in lines:
        text = str(line).strip()
        if not text:
            continue
        mapped = next((replacement for pattern, replacement in _KNOWN if pattern.search(text)), None)
        if mapped is None:
            mapped = f"{capability} did not finish successfully." if capability else _FALLBACK
        if mapped not in out:
            out.append(mapped)
    if not out:
        return None
    return _ENGINE_WORDS.sub("the scan engine", " ".join(out))[:4000]
