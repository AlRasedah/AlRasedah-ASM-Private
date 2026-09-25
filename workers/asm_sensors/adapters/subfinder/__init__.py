"""ProjectDiscovery Subfinder adapter (passive subdomain discovery, MIT)."""

from __future__ import annotations

from typing import Any

from pydantic import Field

from ...base import (
    AdapterConfig,
    ExecutionContext,
    RawOutput,
    ScannerAdapter,
    StageType,
    iter_json_lines,
    tool_output,
    write_targets_file,
)
from ...execution import minimal_env, resolve_binary, run_process
from ...observations import NormalizedOutput, ObservedType
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_hostname

# Providers whose API keys can be supplied per tenant (subfinder provider-config names).
PROVIDERS = (
    "alienvault", "binaryedge", "bufferover", "c99", "censys", "certspotter", "chaos", "chinaz",
    "dnsdb", "dnsrepo", "facebook", "fofa", "fullhunt", "github", "hunter", "intelx", "leakix",
    "netlas", "quake", "redhuntlabs", "robtex", "securitytrails", "shodan", "threatbook",
    "virustotal", "whoisxmlapi", "zoomeyeapi",
)


class SubfinderConfig(AdapterConfig):
    all_sources: bool = False
    recursive: bool = False
    source_timeout_seconds: int = Field(default=30, ge=5, le=300)
    max_time_minutes: int = Field(default=10, ge=1, le=240)
    rate_limit: int | None = Field(default=None, ge=1, le=1000)


def _provider_yaml(creds: dict[str, list[str]]) -> str:
    lines = []
    for provider in PROVIDERS:
        keys = [k for k in creds.get(provider, []) if k and "\n" not in k]
        if keys:
            lines.append(f"{provider}:")
            lines += [f"  - {_yaml_quote(k)}" for k in keys]
    return "\n".join(lines) + "\n"


def _yaml_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@register
class SubfinderAdapter(ScannerAdapter):
    name = "subfinder"
    display_name = "Passive subdomain discovery"
    stage_types = frozenset({StageType.SUBDOMAIN_DISCOVERY})
    target_kinds = frozenset({TargetKind.DOMAIN})
    active = False
    binaries = ("subfinder",)
    credential_providers = PROVIDERS
    config_model = SubfinderConfig

    async def execute(self, targets: list[Target], config: SubfinderConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("subfinder", self.binaries)
        tfile = write_targets_file(ctx.workdir, targets)
        out = ctx.workdir / "subfinder.jsonl"
        argv = [binary, "-dL", str(tfile), "-oJ", "-o", str(out), "-v", "-nc", "-cs",
                "-timeout", str(config.source_timeout_seconds), "-max-time", str(config.max_time_minutes)]
        if config.all_sources:
            argv.append("-all")
        if config.recursive:
            argv.append("-recursive")
        if config.rate_limit:
            argv += ["-rl", str(config.rate_limit)]
        pc = ctx.workdir / "provider-config.yaml"
        pc.write_text(_provider_yaml(ctx.credentials), encoding="utf-8")
        pc.chmod(0o600)
        argv += ["-pc", str(pc)]
        proc = await run_process(argv, timeout=min(ctx.timeout_seconds, config.max_time_minutes * 60 + 120),
                                 cwd=str(ctx.workdir), env=minimal_env(home=str(ctx.workdir)),
                                 max_output_bytes=ctx.max_output_bytes)
        pc.unlink(missing_ok=True)
        data, truncated = tool_output(out, proc, ctx.max_output_bytes)
        return RawOutput(process=proc, files={"subfinder.jsonl": data}, truncated=truncated)

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(iter_json_lines(raw.primary))

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: SubfinderConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        for rec in parsed:
            host = clean_hostname(rec.get("host"))
            if not host:
                continue
            sources = rec.get("sources") or ([rec["source"]] if rec.get("source") else [])
            obs.add(ObservedType.HOSTNAME, host, {"discovery_sources": sorted(set(sources))} if sources else None)
        return NormalizedOutput(observations=obs.all(), coverage=[])
