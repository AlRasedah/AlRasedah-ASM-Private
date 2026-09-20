"""OWASP Amass adapter (subdomain discovery / network mapping).

Supports the three output shapes produced by Amass releases:

* v4+ graph lines:  ``www.example.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)``
* v3 JSON lines:    ``{"name": "...", "addresses": [{"ip": ..., "cidr": ..., "asn": ...}]}``
* plain names:      ``www.example.com``

Amass runs as a separate binary in the sensor worker; no Amass code is linked
into the platform (Apache-2.0, see THIRD_PARTY_LICENSES.md).
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import Field, model_validator

from ...base import (
    AdapterConfig,
    ExecutionContext,
    RawOutput,
    ScannerAdapter,
    StageType,
    tool_output,
    write_targets_file,
)
from ...execution import minimal_env, resolve_binary, run_process
from ...observations import NormalizedOutput, ObservedType, RelationType
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_asn, clean_cidr, clean_hostname, clean_ip

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_GRAPH = re.compile(
    r"^(?P<src>.+?) \((?P<src_type>[A-Za-z]+)\) --> (?P<rel>[a-z_]+) --> (?P<dst>.+?) \((?P<dst_type>[A-Za-z]+)\)$"
)

_REL_MAP = {
    "a_record": RelationType.RESOLVES_TO,
    "aaaa_record": RelationType.RESOLVES_TO,
    "cname_record": RelationType.CNAME,
    "ns_record": RelationType.NS_RECORD,
    "mx_record": RelationType.MX_RECORD,
    "ptr_record": RelationType.PTR,
    "srv_record": RelationType.RELATED_TO,
    "contains": RelationType.CONTAINS,
    "announces": RelationType.ANNOUNCES,
}


class AmassConfig(AdapterConfig):
    mode: Literal["passive", "active"] = "passive"
    brute_force: bool = False
    timeout_minutes: int = Field(default=30, ge=1, le=720)
    dns_qps: int | None = Field(default=None, ge=1, le=20000)

    @model_validator(mode="after")
    def _brute_requires_active(self) -> AmassConfig:
        if self.brute_force and self.mode != "active":
            raise ValueError("brute_force requires mode=active")
        return self


def parse_amass_output(data: bytes) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for raw_line in data.decode("utf-8", "replace").splitlines():
        line = _ANSI.sub("", raw_line).strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and obj.get("name"):
                records.append({"format": "json", **obj})
            continue
        m = _GRAPH.match(line)
        if m:
            records.append({"format": "graph", **m.groupdict()})
            continue
        if " " not in line and clean_hostname(line):
            records.append({"format": "name", "name": line})
    return records


@register
class AmassAdapter(ScannerAdapter):
    name = "amass"
    display_name = "Deep subdomain enumeration"
    stage_types = frozenset({StageType.SUBDOMAIN_DISCOVERY})
    target_kinds = frozenset({TargetKind.DOMAIN})
    active = False  # passive by default; active mode is gated by the platform (see is_active)
    binaries = ("amass",)
    config_model = AmassConfig

    def is_active(self, config: AmassConfig) -> bool:  # type: ignore[override]
        return config.mode == "active"

    def build_argv(self, binary: str, targets_file: str, out_file: str, db_dir: str, cfg: AmassConfig) -> list[str]:
        argv = [binary, "enum", "-df", targets_file, "-o", out_file, "-dir", db_dir,
                "-timeout", str(cfg.timeout_minutes), "-nocolor"]
        if cfg.mode == "active":
            argv.append("-active")
        if cfg.brute_force:
            argv.append("-brute")
        if cfg.dns_qps:
            argv += ["-dns-qps", str(cfg.dns_qps)]
        return argv

    async def execute(self, targets: list[Target], config: AmassConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("amass", self.binaries)
        tfile = write_targets_file(ctx.workdir, targets)
        out = ctx.workdir / "amass.txt"
        db_dir = ctx.workdir / "amass-db"
        db_dir.mkdir(exist_ok=True)
        argv = self.build_argv(binary, str(tfile), str(out), str(db_dir), config)
        timeout = min(ctx.timeout_seconds, config.timeout_minutes * 60 + 300)
        proc = await run_process(argv, timeout=timeout, cwd=str(ctx.workdir),
                                 env=minimal_env(home=str(ctx.workdir)), max_output_bytes=ctx.max_output_bytes)
        data, truncated = tool_output(out, proc, ctx.max_output_bytes)
        return RawOutput(process=proc, files={"amass.txt": data}, truncated=truncated)

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return parse_amass_output(raw.primary)

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: AmassConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        asn_orgs: dict[str, str] = {}
        netblock_asn: dict[str, str] = {}
        ip_netblock: dict[str, str] = {}

        def node(value: str, kind: str) -> tuple[ObservedType, str] | None:
            if kind == "FQDN":
                h = clean_hostname(value)
                if h and not h.endswith((".in-addr.arpa", ".ip6.arpa")):
                    return ObservedType.HOSTNAME, h
            elif kind == "IPAddress":
                ip = clean_ip(value)
                if ip:
                    return ObservedType.IP_ADDRESS, ip
            elif kind == "Netblock":
                c = clean_cidr(value)
                if c:
                    return ObservedType.CIDR, c
            elif kind == "ASN":
                a = clean_asn(value)
                if a:
                    return ObservedType.ASN, a
            return None

        for rec in parsed:
            fmt = rec["format"]
            if fmt == "name":
                h = clean_hostname(rec["name"])
                if h:
                    obs.add(ObservedType.HOSTNAME, h, origin="amass")
            elif fmt == "json":
                h = clean_hostname(rec.get("name"))
                if not h:
                    continue
                sources = rec.get("sources") or ([rec["source"]] if rec.get("source") else [])
                obs.add(ObservedType.HOSTNAME, h, {"discovery_sources": sources} if sources else None)
                for addr in rec.get("addresses") or []:
                    ip = clean_ip(addr.get("ip"))
                    if not ip:
                        continue
                    obs.add(ObservedType.IP_ADDRESS, ip)
                    obs.link(ObservedType.HOSTNAME, h, RelationType.RESOLVES_TO, ObservedType.IP_ADDRESS, ip)
                    cidr = clean_cidr(addr.get("cidr"))
                    asn = clean_asn(addr.get("asn"))
                    if cidr:
                        obs.add(ObservedType.CIDR, cidr)
                        obs.link(ObservedType.CIDR, cidr, RelationType.CONTAINS, ObservedType.IP_ADDRESS, ip)
                    if asn:
                        obs.add(ObservedType.ASN, asn, {"organization": addr.get("desc")} if addr.get("desc") else None)
                        obs.link(ObservedType.IP_ADDRESS, ip, RelationType.BELONGS_TO_ASN, ObservedType.ASN, asn)
                        if cidr:
                            obs.link(ObservedType.ASN, asn, RelationType.ANNOUNCES, ObservedType.CIDR, cidr)
            else:  # graph
                rel = rec["rel"]
                if rel == "managed_by" and rec["dst_type"] == "RIROrganization":
                    a = clean_asn(rec["src"])
                    if a:
                        asn_orgs[a] = rec["dst"].strip()
                    continue
                src = node(rec["src"], rec["src_type"])
                dst = node(rec["dst"], rec["dst_type"])
                for n in (src, dst):
                    if n:
                        obs.add(n[0], n[1])
                mapped = _REL_MAP.get(rel)
                if not (src and dst and mapped):
                    continue
                obs.link(src[0], src[1], mapped, dst[0], dst[1])
                if mapped is RelationType.CONTAINS and src[0] is ObservedType.CIDR:
                    ip_netblock[dst[1]] = src[1]
                elif mapped is RelationType.ANNOUNCES and src[0] is ObservedType.ASN:
                    netblock_asn[dst[1]] = src[1]

        for a, org in asn_orgs.items():
            obs.add(ObservedType.ASN, a, {"organization": org})
        for ip, cidr in ip_netblock.items():
            if cidr in netblock_asn:
                obs.link(ObservedType.IP_ADDRESS, ip, RelationType.BELONGS_TO_ASN, ObservedType.ASN, netblock_asn[cidr])

        # Passive enumeration is inherently incomplete: no coverage is declared,
        # so absence from one run never marks anything as gone.
        return NormalizedOutput(observations=obs.all(), coverage=[])
