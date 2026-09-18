"""ProjectDiscovery dnsx adapter (DNS resolution, MIT).

dnsx is the platform's authoritative *liveness* sensor for hostnames: every
known in-scope hostname is re-resolved on each run, so a hostname that stops
resolving is detected (LivenessCoverage) and IP changes are detected through
RelationCoverage on ``resolves_to``.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Literal

from pydantic import Field, field_validator

from ...base import (
    AdapterConfig,
    ExecutionContext,
    RawOutput,
    ScannerAdapter,
    StageType,
    iter_json_lines,
    read_output_file,
    write_targets_file,
)
from ...execution import minimal_env, resolve_binary, run_process
from ...observations import LivenessCoverage, NormalizedOutput, ObservedType, RelationCoverage, RelationType
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_hostname, clean_ip

RecordType = Literal["a", "aaaa", "cname", "mx", "ns", "txt", "caa", "soa"]


class DnsxConfig(AdapterConfig):
    record_types: list[RecordType] = Field(default_factory=lambda: ["a", "aaaa", "cname", "mx", "ns"])
    resolvers: list[str] = Field(default_factory=list, max_length=16)
    rate_limit: int = Field(default=300, ge=1, le=5000)
    threads: int = Field(default=50, ge=1, le=500)
    retries: int = Field(default=2, ge=1, le=10)

    @field_validator("resolvers")
    @classmethod
    def _resolvers_are_ips(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_address(r)) for r in v]

    @field_validator("record_types")
    @classmethod
    def _need_address_records(cls, v: list[str]) -> list[str]:
        v = sorted(set(v))
        if "a" not in v:
            v.append("a")
        return v


@register
class DnsxAdapter(ScannerAdapter):
    name = "dnsx"
    display_name = "DNS resolution"
    stage_types = frozenset({StageType.DNS_RESOLUTION})
    target_kinds = frozenset({TargetKind.HOSTNAME, TargetKind.DOMAIN})
    active = False  # queries resolvers, not the target's hosts
    binaries = ("dnsx",)
    config_model = DnsxConfig

    async def execute(self, targets: list[Target], config: DnsxConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("dnsx", self.binaries)
        tfile = write_targets_file(ctx.workdir, targets)
        out = ctx.workdir / "dnsx.jsonl"
        argv = [binary, "-l", str(tfile), "-json", "-o", str(out), "-silent", "-nc", "-resp",
                "-rl", str(config.rate_limit), "-t", str(config.threads), "-retry", str(config.retries)]
        argv += [f"-{rt}" for rt in config.record_types]
        if config.resolvers:
            argv += ["-r", ",".join(config.resolvers)]
        proc = await run_process(argv, timeout=ctx.timeout_seconds, cwd=str(ctx.workdir),
                                 env=minimal_env(home=str(ctx.workdir)), max_output_bytes=ctx.max_output_bytes)
        data = read_output_file(out, ctx.max_output_bytes) or proc.stdout
        return RawOutput(process=proc, files={"dnsx.jsonl": data})

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(iter_json_lines(raw.primary))

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: DnsxConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        for rec in parsed:
            host = clean_hostname(rec.get("host"))
            if not host:
                continue
            status = str(rec.get("status_code") or "NOERROR").upper()
            records: dict[str, list[str]] = {}
            for rt in config.record_types:
                values = rec.get(rt)
                if not values:
                    continue
                if rt == "soa":
                    values = [v.get("name", "") if isinstance(v, dict) else str(v) for v in values]
                records[rt] = sorted({str(v).strip().rstrip(".").lower() if rt != "txt" else str(v) for v in values})
            ips = [ip for ip in (clean_ip(v) for v in records.get("a", []) + records.get("aaaa", [])) if ip]
            if status != "NOERROR" or not any(records.values()):
                continue  # not resolving: absence is handled by liveness coverage
            obs.add(ObservedType.HOSTNAME, host, {"dns": records, "resolves": True}, confidence=95)
            for ip in ips:
                obs.add(ObservedType.IP_ADDRESS, ip)
                obs.link(ObservedType.HOSTNAME, host, RelationType.RESOLVES_TO, ObservedType.IP_ADDRESS, ip)
            for target in records.get("cname", []):
                t = clean_hostname(target)
                if t:
                    obs.add(ObservedType.HOSTNAME, t)
                    obs.link(ObservedType.HOSTNAME, host, RelationType.CNAME, ObservedType.HOSTNAME, t)

        queried = sorted({t.value for t in targets})
        coverage = [
            LivenessCoverage(asset_type=ObservedType.HOSTNAME, values=queried),
            RelationCoverage(parent_type=ObservedType.HOSTNAME, parents=queried, relation=RelationType.RESOLVES_TO,
                             child_type=ObservedType.IP_ADDRESS),
        ]
        if "cname" in config.record_types:
            coverage.append(RelationCoverage(parent_type=ObservedType.HOSTNAME, parents=queried,
                                             relation=RelationType.CNAME, child_type=ObservedType.HOSTNAME))
        return NormalizedOutput(observations=obs.all(), coverage=coverage)
