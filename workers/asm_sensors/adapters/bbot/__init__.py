"""BBOT adapter (OPTIONAL discovery/enrichment).

BBOT is GPL-3.0 licensed. It is executed strictly as a separate program in the
sensor container (never imported); it is not installed in the default sensor
image. Build with ``--build-arg INSTALL_BBOT=true`` to enable it. See
THIRD_PARTY_LICENSES.md for the licensing note.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field

from ...base import AdapterConfig, ExecutionContext, RawOutput, ScannerAdapter, StageType, iter_json_lines
from ...execution import minimal_env, resolve_binary, run_process
from ...observations import (
    FindingCategory,
    FindingObservation,
    NormalizedOutput,
    ObservedType,
    RelationType,
    Severity,
)
from ...registry import register
from ...targets import Target, TargetKind, split_host_port
from .._common import ObservationSet, clean_asn, clean_hostname, clean_ip, port_value, ref
from ..httpx import endpoint_base


class BbotConfig(AdapterConfig):
    preset: Literal["subdomain-enum", "cloud-enum", "email-enum"] = "subdomain-enum"
    passive_only: bool = True
    timeout_minutes: int = Field(default=60, ge=5, le=720)


@register
class BbotAdapter(ScannerAdapter):
    name = "bbot"
    display_name = "Recursive OSINT discovery"
    stage_types = frozenset({StageType.SUBDOMAIN_DISCOVERY, StageType.OSINT_ENRICHMENT})
    target_kinds = frozenset({TargetKind.DOMAIN})
    active = False
    binaries = ("bbot",)
    config_model = BbotConfig

    def is_active(self, config: BbotConfig) -> bool:  # type: ignore[override]
        return not config.passive_only

    async def execute(self, targets: list[Target], config: BbotConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("bbot", self.binaries)
        outdir = ctx.workdir / "bbot"
        outdir.mkdir(exist_ok=True)
        argv = [binary, "-t", *[t.value for t in targets], "-p", config.preset, "-y", "--silent",
                "-om", "json", "-o", str(outdir), "-n", "asm"]
        if config.passive_only:
            argv += ["-rf", "passive"]
        proc = await run_process(argv, timeout=min(ctx.timeout_seconds, config.timeout_minutes * 60),
                                 cwd=str(ctx.workdir), env=minimal_env(home=str(ctx.workdir)),
                                 max_output_bytes=ctx.max_output_bytes)
        out = outdir / "asm" / "output.json"
        data = out.read_bytes()[: ctx.max_output_bytes] if out.exists() else proc.stdout
        return RawOutput(process=proc, files={"output.json": data})

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(iter_json_lines(raw.primary))

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: BbotConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        roots = [t.value for t in targets]
        for ev in parsed:
            et = ev.get("type")
            data = ev.get("data")
            if et == "DNS_NAME":
                h = clean_hostname(data)
                if h and any(h == r or h.endswith("." + r) for r in roots):
                    obs.add(ObservedType.HOSTNAME, h, {"discovery_sources": ["bbot"]}, origin=ev.get("module"))
                    for rh in ev.get("resolved_hosts") or []:
                        ip = clean_ip(rh)
                        if ip:
                            obs.add(ObservedType.IP_ADDRESS, ip)
                            obs.link(ObservedType.HOSTNAME, h, RelationType.RESOLVES_TO, ObservedType.IP_ADDRESS, ip)
            elif et == "IP_ADDRESS":
                ip = clean_ip(data)
                if ip:
                    obs.add(ObservedType.IP_ADDRESS, ip)
            elif et == "OPEN_TCP_PORT" and isinstance(data, str):
                try:
                    host, port = split_host_port(data)
                except ValueError:
                    continue
                ip = clean_ip(host)
                if ip:
                    pv = port_value(ip, port)
                    obs.add(ObservedType.PORT, pv, {"port": port, "protocol": "tcp", "ip": ip, "state": "open"})
                    obs.link(ObservedType.IP_ADDRESS, ip, RelationType.HAS_PORT, ObservedType.PORT, pv)
            elif et == "URL" and isinstance(data, str):
                base = endpoint_base(data)
                if base:
                    obs.add(ObservedType.HTTP_ENDPOINT, base[0], {"url": base[0], "scheme": base[1], "port": base[3]})
            elif et == "TECHNOLOGY" and isinstance(data, dict):
                name = str(data.get("technology") or "").strip()
                base = endpoint_base(str(data.get("url") or ""))
                if name and base:
                    obs.add(ObservedType.TECHNOLOGY, name.lower(), {"name": name})
                    obs.link(ObservedType.HTTP_ENDPOINT, base[0], RelationType.USES_TECHNOLOGY,
                             ObservedType.TECHNOLOGY, name.lower())
            elif et == "ASN" and isinstance(data, dict):
                a = clean_asn(data.get("asn"))
                if a:
                    obs.add(ObservedType.ASN, a, {"organization": data.get("name") or data.get("description")})
            elif et in ("FINDING", "VULNERABILITY") and isinstance(data, dict):
                host = clean_hostname(data.get("host")) or clean_ip(data.get("host"))
                if not host:
                    continue
                t = ObservedType.IP_ADDRESS if clean_ip(host) else ObservedType.HOSTNAME
                desc = str(data.get("description") or "BBOT finding")[:2000]
                obs.add(t, host)
                obs.findings.append(FindingObservation(
                    asset=ref(t, host), rule_id=f"bbot:{ev.get('module') or 'finding'}:{desc[:80]}",
                    title=desc[:200], description=desc,
                    severity=Severity.parse(data.get("severity"), Severity.INFO if et == "FINDING" else Severity.MEDIUM),
                    category=FindingCategory.EXPOSURE, evidence={"url": data.get("url")}, tags=["bbot"],
                    confidence=60))
        return NormalizedOutput(observations=obs.all(), coverage=[])
