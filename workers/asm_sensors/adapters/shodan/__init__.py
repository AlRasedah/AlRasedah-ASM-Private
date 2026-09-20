"""Shodan host intelligence (internet-exposure data, no traffic to the target).

Shodan continuously scans the internet and keeps what it saw per IP address:
open ports, service banners and versions, TLS certificates, reverse DNS names,
the hosting ASN/organization, and CVEs it believes those service versions carry.
This adapter asks Shodan about every authorized IP, exactly like Nmap's
``shodan-api`` script does (``GET /shodan/host/<ip>``), and turns the answer into
platform observations.

Two properties make it different from the active sensors:

* It is **passive**: the only host contacted is ``api.shodan.io``. It therefore
  works for scope where active scanning is not authorized, and it is the fastest
  way to see an exposure the platform has not scanned yet.
* Its data is **historical**. Shodan reports what it last saw, possibly weeks
  ago, so the result is marked ``historical``: the platform adds what is new but
  never refreshes "last seen", revives an inactive asset, or closes anything
  based on it. Every port/service records Shodan's own observation date.

Findings from Shodan's ``vulns`` are **unverified**: they come from version
matching, not from testing the service, so they are kept out of the main
findings list (and out of risk scores) until a scanner confirms them.

The API key is a tenant credential (Integrations → Data-source API keys),
delivered in the sealed job envelope like every other scanner credential.
Shodan only accepts it as a query parameter, so URLs are never logged: errors
carry the status code only.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from pydantic import Field

from ...base import AdapterConfig, ConfigurationError, ExecutionContext, RawOutput, ScannerAdapter, StageType
from ...observations import (
    AssetRef,
    FindingCategory,
    FindingCoverage,
    FindingObservation,
    NormalizedOutput,
    ObservedType,
    RelationType,
    Severity,
)
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_asn, clean_hostname, clean_ip, port_value

PROVIDER = "shodan"
API = "https://api.shodan.io"
# Shodan's API is rate limited (about one request per second on most plans).
_MIN_INTERVAL = 1.05


class ShodanConfig(AdapterConfig):
    # Host lookups per scan: a guard for both the account's credits and scan duration.
    max_lookups: int = Field(default=1000, ge=1, le=20000)
    # Ignore service records Shodan last saw longer ago than this (stale exposure).
    max_age_days: int = Field(default=180, ge=1, le=3650)
    include_vulnerabilities: bool = True
    timeout_seconds: float = Field(default=20.0, ge=5, le=120)
    retries: int = Field(default=2, ge=0, le=5)


def _severity(cvss: float | None) -> Severity:
    if cvss is None:
        return Severity.MEDIUM  # Shodan flagged it, but gave us no score
    if cvss >= 9:
        return Severity.CRITICAL
    if cvss >= 7:
        return Severity.HIGH
    if cvss >= 4:
        return Severity.MEDIUM
    return Severity.LOW if cvss > 0 else Severity.INFO


def _float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> datetime | None:
    """Shodan timestamps look like ``2026-09-01T10:11:12.345678`` (UTC, no offset)."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


class _ShodanClient:
    """Minimal Shodan REST client. The key travels as a query parameter (Shodan
    offers no header form), so nothing here ever puts a URL in a log or error."""

    def __init__(self, key: str, timeout: float, retries: int) -> None:
        self._key = key
        self._retries = retries
        self._client = httpx.AsyncClient(base_url=API, timeout=timeout, follow_redirects=False,
                                         headers={"Accept": "application/json", "User-Agent": "Exteriq-ASM"})
        self._next_call = 0.0

    async def __aenter__(self) -> _ShodanClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def get(self, path: str) -> tuple[int, dict[str, Any] | None]:
        """Returns (status, body). Retries rate limits and transient server errors."""
        for attempt in range(self._retries + 1):
            wait = self._next_call - asyncio.get_running_loop().time()
            if wait > 0:
                await asyncio.sleep(wait)
            self._next_call = asyncio.get_running_loop().time() + _MIN_INTERVAL
            try:
                resp = await self._client.get(path, params={"key": self._key})
            except httpx.HTTPError as exc:
                if attempt >= self._retries:
                    raise ShodanUnavailable(type(exc).__name__) from exc
                await asyncio.sleep(2 ** attempt)
                continue
            if resp.status_code in (429, 502, 503, 504) and attempt < self._retries:
                await asyncio.sleep(2 ** attempt * 2)
                continue
            if resp.status_code != 200:
                return resp.status_code, None
            try:
                body = resp.json()
            except ValueError:
                return resp.status_code, None
            return resp.status_code, body if isinstance(body, dict) else None
        return 0, None


class ShodanUnavailable(RuntimeError):
    pass


@register
class ShodanAdapter(ScannerAdapter):
    name = "shodan"
    display_name = "Internet exposure intelligence"
    stage_types = frozenset({StageType.IP_ENRICHMENT})
    target_kinds = frozenset({TargetKind.IP})
    active = False  # queries Shodan's database, never the target
    historical = True  # what Shodan last saw, not what is live now
    credential_providers = (PROVIDER,)
    config_model = ShodanConfig

    def _key(self, ctx: ExecutionContext) -> str:
        for value in (ctx.credentials or {}).get(PROVIDER, []):
            candidate = str(value).strip()
            if candidate:
                return candidate
        raise ConfigurationError(
            "No Shodan API key is configured for this tenant (Integrations → Data-source API keys)")

    async def validate_configuration(self, config: ShodanConfig, ctx: ExecutionContext) -> None:  # type: ignore[override]
        self._key(ctx)

    async def execute(self, targets: list[Target], config: ShodanConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        raw = RawOutput()
        lookups = targets[: config.max_lookups]
        if len(targets) > len(lookups):
            raw.errors.append(f"shodan: only the first {config.max_lookups} of {len(targets)} addresses were looked "
                              f"up (max_lookups)")
        async with _ShodanClient(self._key(ctx), config.timeout_seconds, config.retries) as client:
            # Check the key first (as Nmap's shodan-api script does): a bad key must
            # be one clear error, not one per address.
            try:
                status, info = await client.get("/api-info")
            except ShodanUnavailable as exc:
                raw.errors.append(f"shodan: API unreachable ({exc})")
                return raw
            if status in (401, 403):
                raw.errors.append("shodan: the API key was rejected (HTTP 401/403) — check it in Integrations")
                return raw
            if status != 200 or info is None:
                raw.errors.append(f"shodan: unexpected answer from the account endpoint (HTTP {status})")
                return raw
            raw.records.append({"kind": "account", "plan": info.get("plan"),
                                "query_credits": info.get("query_credits"), "scan_credits": info.get("scan_credits")})

            found = 0
            for target in lookups:
                try:
                    status, body = await client.get(f"/shodan/host/{target.value}")
                except ShodanUnavailable as exc:
                    raw.errors.append(f"shodan: API unreachable ({exc}); {len(lookups) - found} addresses not looked up")
                    break
                if status == 404:
                    continue  # Shodan has never seen this address: a normal answer
                if status in (401, 403):
                    raw.errors.append("shodan: the API key was rejected part-way through (HTTP 401/403)")
                    break
                if status == 429:
                    raw.errors.append("shodan: rate limit reached; the remaining addresses were not looked up")
                    break
                if status != 200 or body is None:
                    raw.errors.append(f"shodan: lookup failed with HTTP {status}")
                    continue
                found += 1
                raw.records.append({"kind": "host", "queried_ip": target.value, **body})
            raw.records.append({"kind": "stats", "looked_up": len(lookups), "with_data": found})
        return raw

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(raw.records)

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: ShodanConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        cutoff = datetime.now(UTC) - timedelta(days=config.max_age_days)
        looked_up: list[AssetRef] = []
        for rec in parsed:
            if rec.get("kind") != "host":
                continue
            ip = clean_ip(rec.get("ip_str") or rec.get("queried_ip"))
            if not ip:
                continue
            looked_up.append(AssetRef(type=ObservedType.IP_ADDRESS, value=ip))
            self._host(obs, ip, rec, config, cutoff, looked_up)
        # Shodan never proves a port is closed or a host is gone, so it declares no
        # liveness or relation coverage. It *is* authoritative for its own CVE list:
        # a Shodan finding it no longer reports may be resolved (tag-scoped, so no
        # other sensor's findings are ever closed by this).
        coverage: list = [FindingCoverage(assets=looked_up, include_tags=["shodan"])] if looked_up else []
        return NormalizedOutput(observations=obs.all(), coverage=coverage)

    def _host(self, obs: ObservationSet, ip: str, rec: dict[str, Any], config: ShodanConfig,
              cutoff: datetime, covered: list[AssetRef]) -> None:
        asn = clean_asn(rec.get("asn"))
        last_update = _timestamp(rec.get("last_update"))
        obs.add(ObservedType.IP_ADDRESS, ip, {
            "asn": asn, "as_name": rec.get("org"), "isp": rec.get("isp"), "country": rec.get("country_code"),
            "os": rec.get("os"), "shodan_last_seen": last_update.isoformat() if last_update else None,
        }, confidence=70)
        if asn:
            obs.add(ObservedType.ASN, asn, {"organization": rec.get("org"), "country": rec.get("country_code")})
            obs.link(ObservedType.IP_ADDRESS, ip, RelationType.BELONGS_TO_ASN, ObservedType.ASN, asn)
        for name in rec.get("hostnames") or []:
            host = clean_hostname(name)
            if host:
                obs.add(ObservedType.HOSTNAME, host, {"discovery_sources": ["shodan"]}, confidence=60)
                obs.link(ObservedType.IP_ADDRESS, ip, RelationType.PTR, ObservedType.HOSTNAME, host)

        on_ports: set[str] = set()
        for entry in rec.get("data") or []:
            if isinstance(entry, dict):
                self._service(obs, ip, entry, config, cutoff, covered, on_ports)
        host_vulns = rec.get("vulns")
        if config.include_vulnerabilities and isinstance(host_vulns, list):
            # Shodan's host-level CVE list: report only what no service entry already
            # carried, and attach it to the address itself.
            for cve in host_vulns:
                if str(cve).strip().upper() in on_ports:
                    continue
                finding = self._vuln(str(cve), {}, ip, None)
                if finding:
                    obs.findings.append(finding)

    def _service(self, obs: ObservationSet, ip: str, entry: dict[str, Any], config: ShodanConfig,
                 cutoff: datetime, covered: list[AssetRef], on_ports: set[str]) -> None:
        try:
            port = int(entry.get("port"))
        except (TypeError, ValueError):
            return
        seen = _timestamp(entry.get("timestamp"))
        if seen and seen < cutoff:
            return  # too old to be worth reporting as current exposure
        proto = str(entry.get("transport") or "tcp").lower()
        if proto not in ("tcp", "udp"):
            proto = "tcp"
        pv = port_value(ip, port, proto)
        seen_iso = seen.isoformat() if seen else None
        obs.add(ObservedType.PORT, pv, {"port": port, "protocol": proto, "ip": ip, "state": "open",
                                        "shodan_last_seen": seen_iso}, confidence=70)
        obs.link(ObservedType.IP_ADDRESS, ip, RelationType.HAS_PORT, ObservedType.PORT, pv)
        covered.append(AssetRef(type=ObservedType.PORT, value=pv))

        http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
        ssl = entry.get("ssl") if isinstance(entry.get("ssl"), dict) else {}
        cpes = [str(c) for c in (entry.get("cpe23") or entry.get("cpe") or []) if c][:10]
        service = {
            "name": entry.get("_shodan", {}).get("module") if isinstance(entry.get("_shodan"), dict) else None,
            "product": entry.get("product"),
            "version": entry.get("version"),
            "cpe": cpes or None,
            "tls": bool(ssl) or None,
            "title": (http or {}).get("title"),
            "banner": (str(entry.get("data") or "")[:500] or None),
            "detection": "shodan",
            "shodan_last_seen": seen_iso,
        }
        obs.add(ObservedType.SERVICE, pv, {k: v for k, v in service.items() if v is not None}, confidence=70)
        obs.link(ObservedType.PORT, pv, RelationType.RUNS_SERVICE, ObservedType.SERVICE, pv)

        cert = (ssl.get("cert") or {}) if isinstance(ssl.get("cert"), dict) else {}
        fingerprint = str((cert.get("fingerprint") or {}).get("sha256") or "").lower().replace(":", "")
        if fingerprint:
            subject = cert.get("subject") or {}
            issuer = cert.get("issuer") or {}
            obs.add(ObservedType.CERTIFICATE, fingerprint, {
                "subject_cn": subject.get("CN"), "issuer_cn": issuer.get("CN"), "issuer_org": issuer.get("O"),
                "not_after": cert.get("expires"), "serial": str(cert.get("serial") or "") or None,
                "self_signed": cert.get("issued") == cert.get("expires") or None, "source": "shodan",
            })
            obs.link(ObservedType.SERVICE, pv, RelationType.PRESENTS_CERTIFICATE, ObservedType.CERTIFICATE, fingerprint)

        if config.include_vulnerabilities and isinstance(entry.get("vulns"), dict):
            for cve, detail in entry["vulns"].items():
                finding = self._vuln(str(cve), detail if isinstance(detail, dict) else {}, ip, pv)
                if finding:
                    obs.findings.append(finding)
                    on_ports.add(str(cve).strip().upper())

    def _vuln(self, cve: str, detail: dict[str, Any], ip: str, pv: str | None) -> FindingObservation | None:
        cve = cve.strip().upper()
        if not cve.startswith("CVE-"):
            return None
        cvss = _float(detail.get("cvss"))
        asset = (AssetRef(type=ObservedType.PORT, value=pv) if pv
                 else AssetRef(type=ObservedType.IP_ADDRESS, value=ip))
        return FindingObservation(
            asset=asset,
            rule_id=f"shodan:{cve}",
            title=f"{cve} reported by Shodan (unverified)",
            description=(str(detail.get("summary"))[:2000] if detail.get("summary") else
                         "Shodan associates this CVE with the service version it observed. It has not been "
                         "verified against the live service."),
            severity=_severity(cvss),
            category=FindingCategory.VULNERABILITY,
            cve=[cve],
            cvss_score=cvss if cvss is not None and 0 <= cvss <= 10 else None,
            references=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            evidence={k: v for k, v in {"source": "shodan", "cvss": cvss,
                                        "verified": False, "port": pv}.items() if v is not None},
            # Version-matched, never tested: kept out of the main findings list and risk scores.
            tags=["shodan", "unverified"],
            location=pv or ip,
            confidence=40,
        )
