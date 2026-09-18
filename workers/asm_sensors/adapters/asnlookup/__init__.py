"""IP -> ASN / network enrichment using the Team Cymru IP-to-ASN DNS service.

Free, passive (DNS TXT lookups against cymru.com, never the target), and
requires no API key. Enables hosting-provider/ASN change detection.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
from pydantic import Field

from ...base import AdapterConfig, ExecutionContext, RawOutput, ScannerAdapter, StageType
from ...observations import NormalizedOutput, ObservedType, RelationCoverage, RelationType
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_asn, clean_cidr, clean_ip


class AsnLookupConfig(AdapterConfig):
    concurrency: int = Field(default=20, ge=1, le=100)
    timeout_seconds: float = Field(default=5.0, ge=1, le=30)


def origin_query_name(ip: str) -> str:
    addr = ipaddress.ip_address(ip)
    if addr.version == 4:
        return ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    nibbles = addr.exploded.replace(":", "")
    return ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"


def parse_origin_txt(txt: str) -> dict[str, str] | None:
    # "13335 | 104.16.0.0/13 | US | arin | 2014-03-28"  (multiple ASNs may be space separated)
    parts = [p.strip() for p in txt.strip('"').split("|")]
    if len(parts) < 3:
        return None
    asn = clean_asn(parts[0].split()[0]) if parts[0] else None
    return {"asn": asn or "", "cidr": parts[1], "country": parts[2], "registry": parts[3] if len(parts) > 3 else ""}


def parse_asname_txt(txt: str) -> str | None:
    # "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    parts = [p.strip() for p in txt.strip('"').split("|")]
    return parts[4] if len(parts) >= 5 else None


@register
class AsnLookupAdapter(ScannerAdapter):
    name = "asnlookup"
    display_name = "Network ownership enrichment"
    stage_types = frozenset({StageType.IP_ENRICHMENT})
    target_kinds = frozenset({TargetKind.IP})
    active = False
    config_model = AsnLookupConfig

    async def _txt(self, resolver: dns.asyncresolver.Resolver, name: str) -> list[str]:
        try:
            answer = await resolver.resolve(name, "TXT")
            return [b"".join(r.strings).decode("utf-8", "replace") for r in answer]  # type: ignore[attr-defined]
        except (dns.exception.DNSException, dns.resolver.NoAnswer):
            return []

    async def execute(self, targets: list[Target], config: AsnLookupConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = config.timeout_seconds
        sem = asyncio.Semaphore(config.concurrency)
        records: list[dict[str, Any]] = []
        as_names: dict[str, str | None] = {}

        async def one(ip: str) -> None:
            async with sem:
                for txt in await self._txt(resolver, origin_query_name(ip)):
                    parsed = parse_origin_txt(txt)
                    if parsed and parsed["asn"]:
                        records.append({"ip": ip, **parsed})
                        break

        await asyncio.gather(*(one(t.value) for t in targets))

        async def name_of(asn: str) -> None:
            async with sem:
                txts = await self._txt(resolver, f"{asn}.asn.cymru.com")
                as_names[asn] = parse_asname_txt(txts[0]) if txts else None

        await asyncio.gather(*(name_of(a) for a in {r["asn"] for r in records}))
        for r in records:
            r["as_name"] = as_names.get(r["asn"])
        return RawOutput(records=records)

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return raw.records

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: AsnLookupConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        for r in parsed:
            ip, asn, cidr = clean_ip(r.get("ip")), clean_asn(r.get("asn")), clean_cidr(r.get("cidr"))
            if not (ip and asn):
                continue
            obs.add(ObservedType.IP_ADDRESS, ip, {"asn": asn, "as_name": r.get("as_name"), "country": r.get("country")})
            obs.add(ObservedType.ASN, asn, {"organization": r.get("as_name"), "country": r.get("country"),
                                            "registry": r.get("registry")})
            obs.link(ObservedType.IP_ADDRESS, ip, RelationType.BELONGS_TO_ASN, ObservedType.ASN, asn)
            if cidr:
                obs.add(ObservedType.CIDR, cidr, {"asn": asn})
                obs.link(ObservedType.CIDR, cidr, RelationType.CONTAINS, ObservedType.IP_ADDRESS, ip)
                obs.link(ObservedType.ASN, asn, RelationType.ANNOUNCES, ObservedType.CIDR, cidr)
        answered = sorted({r["ip"] for r in parsed})
        coverage = [RelationCoverage(parent_type=ObservedType.IP_ADDRESS, parents=answered,
                                     relation=RelationType.BELONGS_TO_ASN, child_type=ObservedType.ASN)] if answered else []
        return NormalizedOutput(observations=obs.all(), coverage=coverage)
