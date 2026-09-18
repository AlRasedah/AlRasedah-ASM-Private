"""SpiderFoot adapter (OPTIONAL OSINT enrichment, MIT).

SpiderFoot runs as its own container (``--profile enrichment`` in
docker-compose) and is driven through its web API. The SpiderFoot URL is a
deployment setting (``spiderfoot_url``) and is never user supplied.

The API endpoints used (``/startscan``, ``/scanstatus``,
``/scanexportjsonmulti``) are those of SpiderFoot 4.x. Verify against the
version you deploy – see docs/SCANNERS.md.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Literal

import httpx
from pydantic import Field

from ...base import AdapterConfig, ExecutionContext, RawOutput, ScannerAdapter, StageType
from ...observations import (
    FindingCategory,
    FindingObservation,
    NormalizedOutput,
    ObservedType,
    RelationType,
    Severity,
)
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_asn, clean_cidr, clean_hostname, clean_ip, ref

_FINISHED = {"FINISHED", "ABORTED", "ERROR-FAILED"}


class SpiderFootConfig(AdapterConfig):
    use_case: Literal["passive", "footprint", "investigate"] = "passive"
    max_wait_minutes: int = Field(default=120, ge=5, le=1440)
    poll_interval_seconds: int = Field(default=20, ge=5, le=300)


def _host_in(roots: list[str], host: str) -> bool:
    return any(host == r or host.endswith("." + r) for r in roots)


@register
class SpiderFootAdapter(ScannerAdapter):
    name = "spiderfoot"
    display_name = "OSINT enrichment"
    stage_types = frozenset({StageType.OSINT_ENRICHMENT, StageType.SUBDOMAIN_DISCOVERY})
    target_kinds = frozenset({TargetKind.DOMAIN})
    active = False
    config_model = SpiderFootConfig

    def is_active(self, config: SpiderFootConfig) -> bool:  # type: ignore[override]
        # "footprint"/"investigate" enable modules that touch the target.
        return config.use_case != "passive"

    async def validate_configuration(self, config: SpiderFootConfig, ctx: ExecutionContext) -> None:  # type: ignore[override]
        if not ctx.settings.get("spiderfoot_url"):
            raise RuntimeError("SpiderFoot integration is not enabled in this deployment (spiderfoot_url unset)")

    async def execute(self, targets: list[Target], config: SpiderFootConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        base = str(ctx.settings["spiderfoot_url"]).rstrip("/")
        raw = RawOutput()
        headers = {"Accept": "application/json", "User-Agent": "Exteriq-ASM"}
        async with httpx.AsyncClient(base_url=base, timeout=60, headers=headers) as client:
            for t in targets:
                try:
                    resp = await client.post("/startscan", data={
                        "scanname": f"asm-{t.value}", "scantarget": t.value, "usecase": config.use_case.capitalize(),
                        "modulelist": "", "typelist": ""})
                    resp.raise_for_status()
                    body = resp.json()
                    scan_id = body[1] if isinstance(body, list) and len(body) > 1 else None
                    if not scan_id:
                        raw.errors.append(f"SpiderFoot refused scan for {t.value}")
                        continue
                    deadline = time.monotonic() + config.max_wait_minutes * 60
                    status = ""
                    while time.monotonic() < deadline:
                        st = (await client.get("/scanstatus", params={"id": scan_id})).json()
                        status = str(st[5]) if isinstance(st, list) and len(st) > 5 else ""
                        if status in _FINISHED:
                            break
                        await asyncio.sleep(config.poll_interval_seconds)
                    if status not in _FINISHED:
                        await client.get("/stopscan", params={"id": scan_id})
                        raw.errors.append(f"SpiderFoot scan for {t.value} exceeded max wait; partial results")
                    export = await client.get("/scanexportjsonmulti", params={"ids": scan_id})
                    export.raise_for_status()
                    rows = export.json()
                    raw.records.extend({"root": t.value, **r} for r in rows if isinstance(r, dict))
                except (httpx.HTTPError, ValueError) as exc:
                    raw.errors.append(f"SpiderFoot error for {t.value}: {type(exc).__name__}")
        return raw

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return [r for r in raw.records if not r.get("false_positive")]

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: SpiderFootConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        roots = [t.value for t in targets]
        for r in parsed:
            et = str(r.get("event_type") or r.get("type") or "")
            data = str(r.get("data") or "").strip()
            origin = f"osint:{r.get('module') or 'spiderfoot'}"
            if et in ("INTERNET_NAME", "DOMAIN_NAME", "INTERNET_NAME_UNRESOLVED"):
                h = clean_hostname(data)
                if h and _host_in(roots, h):
                    obs.add(ObservedType.HOSTNAME, h, {"discovery_sources": ["osint"]}, origin=origin, confidence=60)
            elif et in ("AFFILIATE_INTERNET_NAME", "AFFILIATE_DOMAIN_NAME", "SIMILARDOMAIN", "CO_HOSTED_SITE"):
                h = clean_hostname(data)
                if h:
                    obs.add(ObservedType.HOSTNAME, h, {"relationship_hint": et.lower()}, origin=origin, confidence=30)
            elif et in ("IP_ADDRESS", "IPV6_ADDRESS"):
                ip = clean_ip(data)
                if ip:
                    obs.add(ObservedType.IP_ADDRESS, ip, origin=origin)
                    src = clean_hostname(str(r.get("source_data") or ""))
                    if src and _host_in(roots, src):
                        obs.add(ObservedType.HOSTNAME, src)
                        obs.link(ObservedType.HOSTNAME, src, RelationType.RESOLVES_TO, ObservedType.IP_ADDRESS, ip)
            elif et in ("NETBLOCK_OWNER", "NETBLOCK_MEMBER", "NETBLOCKV6_OWNER"):
                c = clean_cidr(data)
                if c:
                    obs.add(ObservedType.CIDR, c, origin=origin)
            elif et == "BGP_AS_OWNER" or et == "BGP_AS_MEMBER":
                a = clean_asn(data)
                if a:
                    obs.add(ObservedType.ASN, a, origin=origin)
            elif et == "WEBSERVER_TECHNOLOGY" or et == "SOFTWARE_USED":
                if 0 < len(data) < 128:
                    obs.add(ObservedType.TECHNOLOGY, data.lower(), {"name": data}, origin=origin)
            elif et == "CLOUD_STORAGE_BUCKET":
                if 0 < len(data) < 512:
                    obs.add(ObservedType.CLOUD_RESOURCE, data.lower(), {"kind": "storage_bucket"}, origin=origin)
            elif et.startswith("VULNERABILITY_CVE_"):
                host = clean_hostname(str(r.get("source_data") or "")) or clean_ip(str(r.get("source_data") or ""))
                if not host:
                    continue
                sev = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM,
                       "LOW": Severity.LOW}.get(et.rsplit("_", 1)[-1], Severity.MEDIUM)
                cve = data.split()[0].upper()
                t = ObservedType.IP_ADDRESS if clean_ip(host) else ObservedType.HOSTNAME
                obs.add(t, host)
                obs.findings.append(FindingObservation(
                    asset=ref(t, host), rule_id=f"osint-cve:{cve}", title=f"{cve} reported by passive intelligence",
                    severity=sev, category=FindingCategory.VULNERABILITY,
                    cve=[cve] if cve.startswith("CVE-") else [], evidence={"source": origin, "data": data[:500]},
                    tags=["osint", "unverified"], confidence=40))
            elif et in ("SSL_CERTIFICATE_EXPIRED",):
                host = clean_hostname(str(r.get("source_data") or ""))
                if host and _host_in(roots, host):
                    obs.add(ObservedType.HOSTNAME, host)
                    obs.findings.append(FindingObservation(
                        asset=ref(ObservedType.HOSTNAME, host), rule_id="osint:ssl-certificate-expired",
                        title="Expired TLS certificate", severity=Severity.MEDIUM,
                        category=FindingCategory.CERTIFICATE, evidence={"data": data[:500]}, confidence=60))
        return NormalizedOutput(observations=obs.all(), coverage=[])
