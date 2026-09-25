"""OWASP ZAP adapters (web application crawling, passive & active scanning; Apache-2.0).

ZAP (the Zed Attack Proxy) brings dynamic application security testing (DAST) to
Exteriq ASM: it *crawls* a web application to discover its pages and endpoints,
*passively* inspects the responses for hygiene problems (missing security
headers, insecure cookies, information disclosure) and *actively* probes the
discovered surface for injection-class vulnerabilities (SQLi, XSS, path
traversal, ...). It is the ASM analogue of the ZAP proxy's spider, passive
scanner and active scanner.

Like SpiderFoot, ZAP runs as its own container in daemon mode and is driven over
its REST API. The API base URL (``zap_url``) and API key (``zap_api_key``) are
**deployment settings**, never user supplied — this keeps the integration free
of SSRF (a scan profile can never point the platform at an arbitrary URL) and
keeps the API key out of scan profiles and the message broker.

Two adapters are provided:

* :class:`ZapSpiderAdapter` (``zap_spider``) — the ``web_crawl`` stage. Runs the
  traditional spider (and, optionally, the AJAX spider for JavaScript-heavy
  apps), then drains the passive scanner and reports its alerts. Every crawled
  URL becomes an ``http_endpoint`` observation, so the crawl expands the known
  attack surface for later stages.
* :class:`ZapActiveAdapter` (``zap_active``) — the ``vulnerability_detection``
  stage. Runs the active scanner against the already-known endpoints and reports
  its alerts as findings.

Both adapters are strictly origin-scoped: a ZAP *context* is created per target
whose anchored inclusion regex matches exactly the authorized
``scheme://host[:port]`` (no look-alike hosts, other ports or userinfo), the
scanners are told to stay ``inScopeOnly`` / ``subtreeOnly`` within that context,
and the site is seeded without following redirects.

**Isolation.** A ZAP daemon's session (history, alerts, contexts), scanner
options and Replacer rules are global. Each job therefore holds a pool-wide
lease on the daemon for its whole run and works in a fresh session that is
replaced again when it finishes, so concurrent or consecutive jobs — possibly
for different tenants — never see each other's traffic, alerts or credentials.
Deployments that must isolate tenants from each other give each worker pool its
own daemon.

**Authenticated scanning.** If the tenant stores a ``zap_auth`` credential, both
adapters crawl and attack as an authenticated user: the secret is injected into
every in-scope request via a ZAP Replacer rule scoped by the same anchored
origin regex (so it never leaks off-origin). The header defaults to ``Cookie`` (paste a logged-in
session cookie such as ``PHPSESSID=...; security=low``) and can be set to
``Authorization`` (for ``Bearer ...`` tokens) via ``auth_header_name``. The secret
travels through the normal sealed-credential channel — never in a scan profile.
This is session/token-based auth; automatic form login/renewal is a future step.

The API endpoints used (``/JSON/spider/*``, ``/JSON/ajaxSpider/*``,
``/JSON/pscan/*``, ``/JSON/ascan/*``, ``/JSON/context/*``, ``/JSON/core/*``)
match ZAP 2.14+/2.15. Verify against the version you deploy — see
docs/SENSORS.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
import time
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Annotated, Any, Literal

import httpx
from pydantic import AfterValidator, Field

from ...base import AdapterConfig, ConfigurationError, ExecutionContext, RawOutput, ScannerAdapter, StageType
from ...coordination import LeaseLost, LeaseUnavailable
from ...identity import DEFAULT_USER_AGENT, user_agent
from ...observations import (
    AssetRef,
    FindingCategory,
    FindingCoverage,
    FindingObservation,
    NormalizedOutput,
    ObservedType,
    Severity,
)
from ...registry import register
from ...stagelog import note
from ...targets import Target, TargetKind, split_host_port
from .._common import ObservationSet
from ..httpx import endpoint_base

# ZAP risk levels -> platform severity. ZAP has no "critical"; High is its top.
_RISK = {"high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW, "informational": Severity.INFO}
# ZAP confidence -> a 0-100 confidence score.
_CONFIDENCE = {"false positive": 10, "low": 40, "medium": 65, "high": 85, "confirmed": 99}

# TLS ports whose bare host:port should be probed over https rather than http.
_TLS_PORTS = {443, 4443, 8443, 9443, 10443}

# Credential provider that carries the authenticated-scan secret (a session cookie
# value or an authorization header value). It is stored per tenant, encrypted at
# rest, and delivered to the sensor in a sealed envelope like any other credential.
AUTH_PROVIDER = "zap_auth"
# Pages a crawl records on its endpoint, so the active scanner can rebuild the tree.
MAX_PAGES_PER_ENDPOINT = 2000
MAX_PAGE_LENGTH = 512
# Injecting the sign-in header needs the daemon's request-replacer component, which some
# distributions omit. Without it an "authenticated" scan silently crawls the login page,
# so the scan is failed instead: no coverage is better than coverage that is not real.
AUTH_UNAVAILABLE = ("The web application scanner cannot sign in to the application: this deployment's scanner is "
                    "missing the request-replacer component, so an authenticated scan is not possible. Install it, "
                    "or start the scan without a sign-in value to test only what is reachable logged out.")
_HEADER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")


def _valid_header_name(v: str) -> str:
    v = v.strip()
    if not _HEADER_RE.match(v):
        raise ValueError(f"invalid header name: {v!r}")
    return v


# An HTTP header name (e.g. "Authorization" or "Cookie") — validated to prevent injection.
HeaderName = Annotated[str, AfterValidator(_valid_header_name)]


def auth_secret(ctx: ExecutionContext) -> str | None:
    """The authenticated-scan secret from the sealed credentials, if provided.

    This is the value ZAP injects into every in-scope request (a session cookie
    string such as ``PHPSESSID=...; security=low`` for the ``Cookie`` header, or a
    token such as ``Bearer ...`` for the ``Authorization`` header). Returns
    ``None`` for an unauthenticated scan. CRLF is rejected to prevent header
    injection.
    """
    values = (ctx.credentials or {}).get(AUTH_PROVIDER) or []
    for v in values:
        s = str(v).strip()
        if s and "\r" not in s and "\n" not in s:
            return s
    return None


def target_url(t: Target) -> str | None:
    """Best-effort absolute http(s) URL for a crawl/scan target."""
    if t.kind == TargetKind.URL:
        return t.value
    if t.kind == TargetKind.HOST_PORT:
        try:
            host, port = split_host_port(t.value)
        except ValueError:
            return None
        scheme = "https" if port in _TLS_PORTS else "http"
        netloc = f"[{host}]" if ":" in host else host
        default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        return f"{scheme}://{netloc}" + ("" if default else f":{port}")
    if t.kind == TargetKind.HOSTNAME:
        return f"http://{t.value}"
    return None


def _category(alert: dict[str, Any], severity: Severity) -> FindingCategory:
    name = str(alert.get("name") or alert.get("alert") or "").lower()
    tags = " ".join(str(k) for k in (alert.get("tags") or {})).lower()
    hay = f"{name} {tags}"
    if any(w in hay for w in ("certificate", "tls", "ssl ", "cipher", "hsts")):
        return FindingCategory.CERTIFICATE
    if any(w in hay for w in ("injection", "sqli", "sql injection", "xss", "cross site scripting",
                              "path traversal", "remote code", "rce", "command injection", "ssrf",
                              "deserial", "xxe", "csrf")):
        return FindingCategory.VULNERABILITY
    if any(w in hay for w in ("header", "cookie", "cache", "csp", "content security", "clickjack",
                              "cors", "method", "misconfig")):
        return FindingCategory.MISCONFIGURATION
    if any(w in hay for w in ("disclosure", "leak", "exposed", "exposure", "directory", "listing", "debug")):
        return FindingCategory.EXPOSURE
    return FindingCategory.VULNERABILITY if severity.rank >= Severity.MEDIUM.rank else FindingCategory.INFORMATION


def _refs(value: Any) -> list[str]:
    if not value:
        return []
    parts = str(value).replace("\r", "\n").split("\n")
    return [p.strip() for p in parts if p.strip().startswith(("http://", "https://"))][:20]


def alert_to_finding(alert: dict[str, Any], source: str) -> tuple[AssetRef, FindingObservation] | None:
    """Map a single ZAP alert onto an ``http_endpoint`` finding, or ``None`` if unmappable."""
    url = str(alert.get("url") or "")
    base = endpoint_base(url)
    if not base:
        return None
    asset_ref = AssetRef(type=ObservedType.HTTP_ENDPOINT, value=base[0])

    severity = _RISK.get(str(alert.get("risk") or "").strip().lower(), Severity.INFO)
    plugin_id = str(alert.get("pluginId") or alert.get("pluginid") or "").strip()
    alert_ref = str(alert.get("alertRef") or "").strip()
    rule_key = alert_ref or plugin_id or re.sub(r"[^a-z0-9]+", "-", str(alert.get("name") or "alert").lower())[:64]
    rule_id = f"zap:{rule_key}"[:512]

    cwe_id = str(alert.get("cweid") or alert.get("cweId") or "").strip()
    cwe = [f"CWE-{cwe_id}"] if cwe_id.isdigit() and int(cwe_id) > 0 else []
    param = str(alert.get("param") or "").strip()
    evidence = {
        "url": url[:1024] or None,
        "param": param or None,
        "attack": str(alert.get("attack") or "")[:500] or None,
        "evidence": str(alert.get("evidence") or "")[:500] or None,
        "other": str(alert.get("other") or "")[:500] or None,
        "confidence": alert.get("confidence"),
        "wasc_id": alert.get("wascid") or alert.get("wascId"),
        "plugin_id": plugin_id or None,
    }
    finding = FindingObservation(
        asset=asset_ref,
        rule_id=rule_id,
        title=str(alert.get("name") or alert.get("alert") or "ZAP alert")[:512],
        description=alert.get("description"),
        severity=severity,
        category=_category(alert, severity),
        cwe=cwe,
        references=_refs(alert.get("reference")),
        remediation=alert.get("solution"),
        evidence={k: v for k, v in evidence.items() if v not in (None, "")},
        # Content tags from the scanner, plus a neutral marker — never the engine's name.
        tags=sorted({"web-application", *(str(k).lower() for k in (alert.get("tags") or {}))})[:50],
        location=(f"{url} [{param}]" if param else url)[:1024] or None,
        confidence=_CONFIDENCE.get(str(alert.get("confidence") or "").strip().lower(), 60),
    )
    return asset_ref, finding


class _ZapClient:
    """Thin async wrapper over the ZAP daemon JSON API.

    The API key travels in the ``X-ZAP-API-Key`` header (never in the URL/query,
    so it cannot leak into logs). ``follow_redirects`` is off so the client only
    ever talks to the configured ZAP daemon.
    """

    def __init__(self, base_url: str, api_key: str | None, timeout: float, agent: str | None = None) -> None:
        headers = {"Accept": "application/json", "User-Agent": agent or DEFAULT_USER_AGENT}
        if api_key:
            headers["X-ZAP-API-Key"] = api_key
        self._c = httpx.AsyncClient(base_url=base_url.rstrip("/"), timeout=timeout,
                                    follow_redirects=False, headers=headers)

    async def __aenter__(self) -> _ZapClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._c.aclose()

    async def call(self, component: str, kind: str, action: str, params: dict[str, Any] | None = None,
                   *, secret: bool = False) -> dict[str, Any]:
        """One API call. ``secret=True`` sends the parameters as a form body instead of
        a query string, so a credential among them never reaches a request log."""
        path = f"/JSON/{component}/{kind}/{action}/"
        values = {k: str(v) for k, v in (params or {}).items()}
        resp = (await self._c.post(path, data=values) if secret
                else await self._c.get(path, params=values))
        resp.raise_for_status()
        body = resp.json()
        return body if isinstance(body, dict) else {}

    async def new_context(self, name: str, include_regex: str) -> str:
        ctx = await self.call("context", "action", "newContext", {"contextName": name})
        context_id = str(ctx.get("contextId") or "")
        await self.call("context", "action", "includeInContext", {"contextName": name, "regex": include_regex})
        await self.call("context", "action", "setContextInScope", {"contextName": name, "booleanInScope": "true"})
        return context_id

    async def add_auth_header(self, description: str, header_name: str, value: str, url_regex: str) -> None:
        """Inject an auth header into every request whose URL matches ``url_regex``.

        Uses ZAP's Replacer so both the spider and the active scanner send the
        session token/cookie. ``url_regex`` scopes it to the authorized origin, so
        the secret never travels to any other host.
        """
        await self.call("replacer", "action", "addRule", {
            "description": description, "enabled": "true", "matchType": "REQ_HEADER",
            "matchString": header_name, "matchRegex": "false", "replacement": value,
            "initiators": "", "url": url_regex}, secret=True)  # the session value is in here

    async def remove_auth_header(self, description: str) -> None:
        await self.call("replacer", "action", "removeRule", {"description": description})

    async def remove_context(self, name: str) -> None:
        await self.call("context", "action", "removeContext", {"contextName": name})

    async def new_session(self) -> None:
        """Replace the daemon's session: drops all history, sites, alerts and contexts."""
        await self.call("core", "action", "newSession", {"name": "", "overwrite": "true"})

    async def alerts(self, url: str, max_alerts: int, raw: RawOutput, source: str) -> None:
        """Collect this origin's alerts into ``raw`` (only alerts whose URL is on the origin)."""
        origin = endpoint_base(url)
        body = await self.call("core", "view", "alerts", {"baseurl": url, "start": 0, "count": max_alerts})
        found = [a for a in body.get("alerts") or [] if isinstance(a, dict)]
        if len(found) >= max_alerts:
            raw.errors.append(f"{source}: alert limit ({max_alerts}) reached for {url}; results are incomplete")
        for a in found:
            base = endpoint_base(str(a.get("url") or ""))
            if origin and base and base[0] == origin[0]:
                raw.records.append({"kind": "alert", **a})


def _include_regex(url: str) -> str:
    """A ZAP regex matching exactly the target's origin (scheme://host[:port]) and its paths.

    Anchored at both ends with an explicit authority boundary, so look-alike hosts
    (``example.com.attacker.test``), other ports, and ``user@host`` tricks never
    match. The same regex scopes the ZAP context *and* the credential Replacer rule.
    """
    base = endpoint_base(url)
    if not base:
        raise ValueError(f"not an http(s) URL: {url!r}")
    _origin, scheme, host, port = base
    netloc = f"[{host}]" if ":" in host else host
    default = 443 if scheme == "https" else 80
    port_part = rf"(?::{default})?" if port == default else f":{port}"
    return "^" + re.escape(f"{scheme}://{netloc}") + port_part + r"(?:[/?#].*)?$"


def _require_zap(ctx: ExecutionContext) -> None:
    # ConfigurationError (not RuntimeError): the platform reports its message to the
    # user, so "not enabled" reads as advice instead of "unexpected sensor error".
    if not ctx.settings.get("zap_url"):
        raise ConfigurationError("The web application scanner is not enabled in this deployment")


def _lease_name(ctx: ExecutionContext) -> str:
    return "zap:" + hashlib.sha256(str(ctx.settings["zap_url"]).encode()).hexdigest()[:16]


@contextlib.asynccontextmanager
async def _exclusive_daemon(zap: _ZapClient, ctx: ExecutionContext) -> AsyncIterator[None]:
    """Hold the ZAP daemon exclusively for this job, in a fresh, empty session.

    A daemon's session (history, sites tree, alerts, contexts), scanner options
    and Replacer rules are global, so jobs never share it: the pool-wide lease
    serializes them, and the session is replaced before and after the job so no
    job sees another's traffic, alerts or credentials.

    If the lease is lost mid-run (a broker outage outlasting the TTL), another job
    may already own the daemon. The cleanup session reset is then skipped — it would
    wipe the *new* owner's crawl — and the job fails rather than carrying on against
    a daemon it no longer controls.
    """
    async with ctx.coordinator.lease(_lease_name(ctx), ttl=120,
                                     wait=max(60, ctx.timeout_seconds // 2)) as lost:
        await zap.new_session()
        try:
            yield
        finally:
            if not lost.is_set():
                with contextlib.suppress(httpx.HTTPError):
                    await zap.new_session()


async def _stop(zap: _ZapClient, component: str, params: dict[str, Any]) -> None:
    with contextlib.suppress(httpx.HTTPError):
        await zap.call(component, "action", "stop", params)


class ZapSpiderConfig(AdapterConfig):
    max_depth: int = Field(default=5, ge=1, le=20)
    max_children: int = Field(default=0, ge=0, le=5000)  # 0 = unlimited children per node
    max_duration_minutes: int = Field(default=15, ge=1, le=240)
    threads: int = Field(default=5, ge=1, le=50)  # clamped by ctx.max_rate via apply_limits
    ajax_spider: bool = False
    passive_scan: bool = True
    poll_interval_seconds: int = Field(default=5, ge=2, le=60)
    max_alerts: int = Field(default=2000, ge=1, le=20000)
    # Authenticated scanning: the header carrying the session secret from the
    # `zap_auth` credential (e.g. "Cookie" for a session cookie, "Authorization"
    # for a bearer token). No effect unless a `zap_auth` credential is configured.
    auth_header_name: HeaderName = "Cookie"


@register
class ZapSpiderAdapter(ScannerAdapter):
    name = "zap_spider"
    display_name = "Web application crawling"
    stage_types = frozenset({StageType.WEB_CRAWL})
    target_kinds = frozenset({TargetKind.URL, TargetKind.HOST_PORT, TargetKind.HOSTNAME})
    active = True
    credential_providers = (AUTH_PROVIDER,)
    config_model = ZapSpiderConfig

    async def validate_configuration(self, config: ZapSpiderConfig, ctx: ExecutionContext) -> None:  # type: ignore[override]
        _require_zap(ctx)

    async def execute(self, targets: list[Target], config: ZapSpiderConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        raw = RawOutput()
        base_url = str(ctx.settings["zap_url"])
        api_key = (ctx.settings.get("zap_api_key") or None)
        # Per-request timeout is short; the long waits are bounded by explicit deadlines below.
        auth = auth_secret(ctx)
        try:
            async with _ZapClient(base_url, api_key, 60, user_agent(ctx.settings)) as zap, \
                    _exclusive_daemon(zap, ctx):
                await self._set_options(zap, config, raw)
                for i, t in enumerate(targets):
                    url = target_url(t)
                    if not url:
                        raw.errors.append(f"zap_spider: cannot derive a URL for {t.value}")
                        continue
                    try:
                        await self._crawl_one(zap, url, config, raw, ctx_name=f"asm-{ctx.job_id}-{i}", auth=auth)
                    except (httpx.HTTPError, ValueError, KeyError) as exc:
                        raw.errors.append(f"zap_spider error for {url}: {type(exc).__name__}")
        except LeaseUnavailable:
            raw.errors.append("zap_spider: the ZAP daemon stayed busy with another job; nothing was crawled")
        except LeaseLost:
            raw.errors.append("zap_spider: lost exclusive use of the web application scanner mid-crawl; "
                              "another job may now hold it, so this crawl is incomplete")
        except httpx.HTTPError as exc:
            raw.errors.append(f"zap_spider: ZAP daemon unavailable: {type(exc).__name__}")
        return raw

    async def _set_options(self, zap: _ZapClient, config: ZapSpiderConfig, raw: RawOutput) -> None:
        try:
            await zap.call("spider", "action", "setOptionMaxDepth", {"Integer": config.max_depth})
            await zap.call("spider", "action", "setOptionThreadCount", {"Integer": config.threads})
            await zap.call("spider", "action", "setOptionMaxDuration", {"Integer": config.max_duration_minutes})
        except httpx.HTTPError as exc:
            raw.errors.append(f"zap_spider: could not set options: {type(exc).__name__}")

    async def _crawl_one(self, zap: _ZapClient, url: str, config: ZapSpiderConfig, raw: RawOutput, ctx_name: str,
                         auth: str | None = None) -> None:
        origin = _include_regex(url)
        await zap.new_context(ctx_name, origin)
        rule = None
        scan_id = ""
        spider_done = ajax_done = True
        try:
            if auth:
                rule = f"asm-auth-{ctx_name}"
                try:
                    await zap.add_auth_header(rule, config.auth_header_name, auth, origin)
                except httpx.HTTPError as exc:
                    # Never crawl logged-out while reporting an authenticated scan: the result
                    # would be a login page and a false sense of coverage.
                    raise ConfigurationError(AUTH_UNAVAILABLE) from exc
            # Seed without following redirects: a redirect must never put another host on the request path.
            note(f"Crawling {url}" + (" (signed in)" if auth else ""))
            await zap.call("core", "action", "accessUrl", {"url": url, "followRedirects": "false"})

            started = await zap.call("spider", "action", "scan", {
                "url": url, "maxChildren": config.max_children or "", "recurse": "true",
                "subtreeOnly": "true", "contextName": ctx_name})
            scan_id = str(started.get("scan") or "")
            if not scan_id or not scan_id.isdigit():
                raw.errors.append(f"zap_spider: daemon refused to crawl {url}")
                scan_id = ""
            else:
                spider_done = False
                spider_done = await self._await_status(zap, "spider", {"scanId": scan_id}, config)
                if not spider_done:
                    raw.errors.append(f"zap_spider: crawl of {url} did not finish before its deadline")
                results = await zap.call("spider", "view", "results", {"scanId": scan_id})
                pages = results.get("results") or []
                for u in pages:
                    raw.records.append({"kind": "url", "root": url, "value": str(u)})
                note(f"Crawl of {url} found {len(pages)} page(s)")

            if config.ajax_spider:
                ajax_done = False
                await zap.call("ajaxSpider", "action", "scan", {"url": url, "inScope": "true", "contextName": ctx_name})
                deadline = time.monotonic() + config.max_duration_minutes * 60
                while time.monotonic() < deadline:
                    st = await zap.call("ajaxSpider", "view", "status", {})
                    if str(st.get("status") or "").lower() != "running":
                        ajax_done = True
                        break
                    await asyncio.sleep(config.poll_interval_seconds)
                if not ajax_done:
                    raw.errors.append(f"zap_spider: AJAX crawl of {url} did not finish before its deadline")
                full = await zap.call("ajaxSpider", "view", "fullResults", {})
                for item in (full.get("inScope") or []) if isinstance(full, dict) else []:
                    u = (item or {}).get("requestHeader", "").split(" ")[1:2]
                    if u:
                        raw.records.append({"kind": "url", "root": url, "value": u[0]})

            if config.passive_scan:
                if not await self._drain_passive(zap, config):
                    raw.errors.append(f"zap_spider: passive analysis of {url} did not finish before its deadline")
                await zap.alerts(url, config.max_alerts, raw, "zap_spider")
        finally:
            if scan_id and not spider_done:
                await _stop(zap, "spider", {"scanId": scan_id})
            if not ajax_done:
                await _stop(zap, "ajaxSpider", {})
            with contextlib.suppress(httpx.HTTPError):
                if rule:
                    await zap.remove_auth_header(rule)
            with contextlib.suppress(httpx.HTTPError):
                await zap.remove_context(ctx_name)

    async def _drain_passive(self, zap: _ZapClient, config: ZapSpiderConfig) -> bool:
        deadline = time.monotonic() + config.max_duration_minutes * 60
        while time.monotonic() < deadline:
            st = await zap.call("pscan", "view", "recordsToScan", {})
            try:
                remaining = int(st.get("recordsToScan") or 0)
            except (TypeError, ValueError):
                return False
            if remaining <= 0:
                return True
            await asyncio.sleep(config.poll_interval_seconds)
        return False

    async def _await_status(self, zap: _ZapClient, component: str, params: dict[str, Any],
                            config: ZapSpiderConfig) -> bool:
        """Poll until the scan reports 100%; False if the deadline passed or the status was unreadable."""
        # The scanner's own max-duration option stops it; this is the outer safety deadline.
        deadline = time.monotonic() + config.max_duration_minutes * 60 + 60
        shown = -1
        while time.monotonic() < deadline:
            st = await zap.call(component, "view", "status", params)
            try:
                pct = int(st.get("status") or 0)
            except (TypeError, ValueError):
                return False
            if pct // 10 != shown:
                shown = pct // 10
                note(f"Crawl {min(pct, 100)}% complete")
            if pct >= 100:
                return True
            await asyncio.sleep(config.poll_interval_seconds)
        return False

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(raw.records)

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: ZapSpiderConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        scanned: list[AssetRef] = []
        seen_bases: set[str] = set()
        # An endpoint asset is an origin, so every crawled URL collapses into one. The
        # pages themselves are kept on that origin: the active scanner starts from a
        # blank daemon session and cannot see this crawl's site tree, so without them it
        # would have nothing to attack but the site root.
        pages: dict[str, set[str]] = defaultdict(set)
        for rec in parsed:
            if rec.get("kind") == "url":
                raw_url = str(rec.get("value") or "")
                base = endpoint_base(raw_url)
                if not base:
                    continue
                endpoint, scheme, host, _port = base
                obs.add(ObservedType.HTTP_ENDPOINT, endpoint, {"url": endpoint, "scheme": scheme, "host": host,
                                                               "discovery_sources": ["web_crawl"]}, confidence=80)
                path = raw_url[len(endpoint):] if raw_url.startswith(endpoint) else ""
                if path and len(path) <= MAX_PAGE_LENGTH:
                    pages[endpoint].add(path)
                if endpoint not in seen_bases:
                    seen_bases.add(endpoint)
                    scanned.append(AssetRef(type=ObservedType.HTTP_ENDPOINT, value=endpoint))
            elif rec.get("kind") == "alert":
                mapped = alert_to_finding(rec, self.name)
                if mapped:
                    asset_ref, finding = mapped
                    obs.findings.append(finding)
                    obs.add(asset_ref.type, asset_ref.value)

        for endpoint, found in pages.items():
            obs.add(ObservedType.HTTP_ENDPOINT, endpoint,
                    {"crawled_pages": sorted(found)[:MAX_PAGES_PER_ENDPOINT]})

        # Seed target endpoints into coverage so a resolved passive alert can auto-close.
        for t in targets:
            u = target_url(t)
            base = endpoint_base(u) if u else None
            if base and base[0] not in seen_bases:
                seen_bases.add(base[0])
                scanned.append(AssetRef(type=ObservedType.HTTP_ENDPOINT, value=base[0]))

        coverage: list = []
        if config.passive_scan and scanned:
            coverage.append(FindingCoverage(assets=scanned))
        return NormalizedOutput(observations=obs.all(), coverage=coverage)


class ZapActiveConfig(AdapterConfig):
    scan_policy: str = ""  # empty = ZAP's default policy; a named policy must exist in the daemon
    max_duration_minutes: int = Field(default=60, ge=1, le=480)
    max_rule_duration_minutes: int = Field(default=5, ge=0, le=120)
    threads: int = Field(default=2, ge=1, le=20)  # threads per host; clamped by apply_limits
    attack_strength: Literal["low", "medium", "high"] = "medium"
    alert_threshold: Literal["low", "medium", "high"] = "medium"
    in_scope_only: bool = True
    recurse: bool = True
    # Pages reloaded into the daemon before the scan starts (see _scan_origin).
    max_seed_pages: int = Field(default=1000, ge=1, le=5000)
    poll_interval_seconds: int = Field(default=10, ge=2, le=60)
    max_alerts: int = Field(default=5000, ge=1, le=50000)
    # Authenticated scanning: header carrying the `zap_auth` session secret
    # ("Cookie" for a session cookie, "Authorization" for a bearer token).
    auth_header_name: HeaderName = "Cookie"


@register
class ZapActiveAdapter(ScannerAdapter):
    name = "zap_active"
    display_name = "Active web vulnerability scanning"
    stage_types = frozenset({StageType.VULNERABILITY_DETECTION})
    target_kinds = frozenset({TargetKind.URL, TargetKind.HOST_PORT})
    active = True
    wants_crawled_pages = True  # it tests request parameters; origins alone tell it nothing
    credential_providers = (AUTH_PROVIDER,)
    config_model = ZapActiveConfig

    async def validate_configuration(self, config: ZapActiveConfig, ctx: ExecutionContext) -> None:  # type: ignore[override]
        _require_zap(ctx)

    async def execute(self, targets: list[Target], config: ZapActiveConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        raw = RawOutput()
        base_url = str(ctx.settings["zap_url"])
        api_key = (ctx.settings.get("zap_api_key") or None)
        auth = auth_secret(ctx)
        try:
            async with _ZapClient(base_url, api_key, 60, user_agent(ctx.settings)) as zap, \
                    _exclusive_daemon(zap, ctx):
                await self._set_options(zap, config, raw)
                # One scan per origin, not per URL: the pages of an application are
                # branches of one tree, and ZAP walks it once with `recurse`.
                by_origin: dict[str, list[str]] = {}
                for t in targets:
                    url = target_url(t)
                    if not url:
                        raw.errors.append(f"zap_active: cannot derive a URL for {t.value}")
                        continue
                    base = endpoint_base(url)
                    if not base:
                        raw.errors.append(f"zap_active: cannot derive an origin for {t.value}")
                        continue
                    by_origin.setdefault(base[0], []).append(url)
                for i, (origin_url, urls) in enumerate(sorted(by_origin.items())):
                    try:
                        await self._scan_origin(zap, origin_url, urls, config, raw,
                                                ctx_name=f"asm-{ctx.job_id}-{i}", auth=auth)
                    except (httpx.HTTPError, ValueError, KeyError) as exc:
                        raw.errors.append(f"zap_active error for {origin_url}: {type(exc).__name__}")
        except LeaseUnavailable:
            raw.errors.append("zap_active: the ZAP daemon stayed busy with another job; nothing was scanned")
        except LeaseLost:
            raw.errors.append("zap_active: lost exclusive use of the web application scanner mid-scan; "
                              "another job may now hold it, so this scan is incomplete")
        except httpx.HTTPError as exc:
            raw.errors.append(f"zap_active: ZAP daemon unavailable: {type(exc).__name__}")
        return raw

    async def _set_options(self, zap: _ZapClient, config: ZapActiveConfig, raw: RawOutput) -> None:
        try:
            await zap.call("ascan", "action", "setOptionMaxScanDurationInMins", {"Integer": config.max_duration_minutes})
            await zap.call("ascan", "action", "setOptionMaxRuleDurationInMins", {"Integer": config.max_rule_duration_minutes})
            await zap.call("ascan", "action", "setOptionThreadPerHost", {"Integer": config.threads})
        except httpx.HTTPError as exc:
            raw.errors.append(f"zap_active: could not set options: {type(exc).__name__}")

    async def _scan_origin(self, zap: _ZapClient, url: str, urls: list[str], config: ZapActiveConfig,
                           raw: RawOutput, ctx_name: str, auth: str | None = None) -> None:
        origin = _include_regex(url)
        context_id = await zap.new_context(ctx_name, origin)
        rule = None
        scan_id = ""
        finished = False
        try:
            if auth:
                rule = f"asm-auth-{ctx_name}"
                try:
                    await zap.add_auth_header(rule, config.auth_header_name, auth, origin)
                except httpx.HTTPError as exc:
                    raise ConfigurationError(AUTH_UNAVAILABLE) from exc
            # Rebuild the sites tree before attacking it. Every job starts from a blank
            # daemon session (jobs must not see each other's traffic), so the crawl's tree
            # is gone by now: without re-seeding, `recurse` would walk a tree of one node
            # and the scanner would test the site root alone — no page and no parameter of
            # the application behind it. Redirects are never followed, so no other host
            # can enter the request path.
            failed = 0
            for seed in [url, *sorted(set(urls) - {url})][:config.max_seed_pages]:
                try:
                    await zap.call("core", "action", "accessUrl", {"url": seed, "followRedirects": "false"})
                except httpx.HTTPError:
                    failed += 1
            if failed:
                raw.errors.append(f"zap_active: {failed} known pages of {url} could not be reloaded before the scan; "
                                  "its results are incomplete")
            note(f"Active testing of {url} started ({len(urls)} known page(s))")
            started = await zap.call("ascan", "action", "scan", {
                "url": url, "recurse": str(config.recurse).lower(), "inScopeOnly": str(config.in_scope_only).lower(),
                "scanPolicyName": config.scan_policy, "method": "", "postData": "", "contextId": context_id})
            scan_id = str(started.get("scan") or "")
            if not scan_id.isdigit():
                raw.errors.append(f"zap_active: daemon refused active scan for {url}")
                scan_id = ""
                return
            deadline = time.monotonic() + config.max_duration_minutes * 60 + 120
            shown = -1
            while time.monotonic() < deadline:
                st = await zap.call("ascan", "view", "status", {"scanId": scan_id})
                try:
                    pct = int(st.get("status") or 0)
                except (TypeError, ValueError):
                    break
                if pct // 10 != shown:
                    shown = pct // 10
                    note(f"Active testing of {url}: {min(pct, 100)}% complete")
                if pct >= 100:
                    finished = True
                    break
                await asyncio.sleep(config.poll_interval_seconds)
            if not finished:
                raw.errors.append(f"zap_active: active scan of {url} did not finish before its deadline")
            before = len(raw.records)
            await zap.alerts(url, config.max_alerts, raw, "zap_active")
            note(f"Active testing of {url} {'finished' if finished else 'stopped at its deadline'}: "
                 f"{len(raw.records) - before} alert(s)")
        finally:
            if scan_id and not finished:
                await _stop(zap, "ascan", {"scanId": scan_id})
            with contextlib.suppress(httpx.HTTPError):
                if rule:
                    await zap.remove_auth_header(rule)
            with contextlib.suppress(httpx.HTTPError):
                await zap.remove_context(ctx_name)

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(raw.records)

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: ZapActiveConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        scanned: list[AssetRef] = []
        seen: set[str] = set()
        for rec in parsed:
            if rec.get("kind") != "alert":
                continue
            mapped = alert_to_finding(rec, self.name)
            if not mapped:
                continue
            asset_ref, finding = mapped
            obs.findings.append(finding)
            obs.add(asset_ref.type, asset_ref.value)

        for t in targets:
            u = target_url(t)
            base = endpoint_base(u) if u else None
            if base and base[0] not in seen:
                seen.add(base[0])
                scanned.append(AssetRef(type=ObservedType.HTTP_ENDPOINT, value=base[0]))
        coverage: list = []
        if scanned:
            coverage.append(FindingCoverage(assets=scanned))
        return NormalizedOutput(observations=obs.all(), coverage=coverage)
