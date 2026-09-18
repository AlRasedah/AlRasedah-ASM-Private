"""ProjectDiscovery Naabu adapter (TCP port discovery, MIT).

Runs connect scans by default so the sensor container does not need raw-socket
capabilities. Port sets are always explicit (see :mod:`asm_sensors.ports`).
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

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
from ...observations import NormalizedOutput, ObservedType, RelationCoverage, RelationType
from ...ports import PORT_SETS, normalize_spec, validate_port_spec
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_hostname, clean_ip, port_value


class NaabuConfig(AdapterConfig):
    port_set: Literal["web", "common", "extended", "full", "custom"] = "common"
    custom_ports: str | None = None
    rate: int = Field(default=500, ge=1, le=10000)
    workers: int = Field(default=25, ge=1, le=500)
    retries: int = Field(default=2, ge=1, le=10)
    timeout_ms: int = Field(default=1000, ge=100, le=30000)
    scan_type: Literal["connect", "syn"] = "connect"
    exclude_cdn: bool = True

    @field_validator("custom_ports")
    @classmethod
    def _valid_ports(cls, v: str | None) -> str | None:
        return validate_port_spec(v) if v else v

    @model_validator(mode="after")
    def _custom_needs_ports(self) -> NaabuConfig:
        if self.port_set == "custom" and not self.custom_ports:
            raise ValueError("custom_ports is required when port_set=custom")
        return self

    @property
    def port_spec(self) -> str:
        return normalize_spec(self.custom_ports if self.port_set == "custom" else PORT_SETS[self.port_set])  # type: ignore[arg-type]


def parse_naabu_record(rec: dict[str, Any]) -> tuple[str | None, int | None, str, str | None]:
    """Return (ip, port, protocol, hostname) from both old and new naabu JSON shapes."""
    port_field = rec.get("port")
    proto = str(rec.get("protocol") or "tcp").lower()
    if isinstance(port_field, dict):  # {"Port": 443, "Protocol": 0, "TLS": false}
        port = port_field.get("Port") or port_field.get("port")
        p = port_field.get("Protocol")
        proto = "udp" if p in (1, "udp") else "tcp"
    else:
        port = port_field
    try:
        port_i = int(port) if port is not None else None
    except (TypeError, ValueError):
        port_i = None
    ip = clean_ip(rec.get("ip")) or clean_ip(rec.get("host"))
    host = rec.get("host")
    hostname = clean_hostname(host) if host and not clean_ip(host) else None
    if proto not in ("tcp", "udp"):
        proto = "tcp"
    return ip, port_i, proto, hostname


@register
class NaabuAdapter(ScannerAdapter):
    name = "naabu"
    display_name = "Port discovery"
    stage_types = frozenset({StageType.PORT_DISCOVERY})
    target_kinds = frozenset({TargetKind.IP, TargetKind.CIDR})
    active = True
    binaries = ("naabu",)
    config_model = NaabuConfig

    def build_argv(self, binary: str, tfile: str, out: str, cfg: NaabuConfig) -> list[str]:
        argv = [binary, "-l", tfile, "-json", "-o", out, "-silent", "-nc",
                "-p", cfg.port_spec, "-rate", str(cfg.rate), "-c", str(cfg.workers),
                "-retries", str(cfg.retries), "-timeout", str(cfg.timeout_ms),
                "-s", "s" if cfg.scan_type == "syn" else "c"]
        if cfg.exclude_cdn:
            argv.append("-ec")
        return argv

    async def execute(self, targets: list[Target], config: NaabuConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("naabu", self.binaries)
        tfile = write_targets_file(ctx.workdir, targets)
        out = ctx.workdir / "naabu.jsonl"
        proc = await run_process(self.build_argv(binary, str(tfile), str(out), config), timeout=ctx.timeout_seconds,
                                 cwd=str(ctx.workdir), env=minimal_env(home=str(ctx.workdir)),
                                 max_output_bytes=ctx.max_output_bytes)
        data = read_output_file(out, ctx.max_output_bytes) or proc.stdout
        return RawOutput(process=proc, files={"naabu.jsonl": data})

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(iter_json_lines(raw.primary))

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: NaabuConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        for rec in parsed:
            ip, port, proto, _hostname = parse_naabu_record(rec)
            if not ip or not port or not 1 <= port <= 65535:
                continue
            pv = port_value(ip, port, proto)
            attrs: dict[str, Any] = {"port": port, "protocol": proto, "ip": ip, "state": "open"}
            if rec.get("tls") is not None:
                attrs["tls"] = bool(rec.get("tls"))
            obs.add(ObservedType.IP_ADDRESS, ip)
            obs.add(ObservedType.PORT, pv, attrs, confidence=90)
            obs.link(ObservedType.IP_ADDRESS, ip, RelationType.HAS_PORT, ObservedType.PORT, pv)

        ip_targets = sorted({t.value for t in targets if t.kind == TargetKind.IP})
        cidr_targets = sorted({t.value for t in targets if t.kind == TargetKind.CIDR})
        constraints: dict[str, Any] = {"port_spec": config.port_spec, "protocol": "tcp"}
        if config.exclude_cdn:
            # naabu only probes 80/443 on CDN/WAF addresses; the platform narrows
            # coverage accordingly for IPs it knows to be CDN edges.
            constraints["cdn_port_spec"] = "80,443"
        if cidr_targets:
            constraints["parent_cidrs"] = cidr_targets
        coverage = [RelationCoverage(parent_type=ObservedType.IP_ADDRESS, parents=ip_targets,
                                     relation=RelationType.HAS_PORT, child_type=ObservedType.PORT,
                                     constraints=constraints)]
        return NormalizedOutput(observations=obs.all(), coverage=coverage)
