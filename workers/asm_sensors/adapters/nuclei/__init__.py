"""ProjectDiscovery Nuclei adapter (vulnerability / exposure detection, MIT).

Safe-by-default:

* intrusive template classes are excluded (dos, fuzz, intrusive, brute force…);
* out-of-band interaction (interactsh) is disabled by default, which also keeps
  scan data inside the deployment's jurisdiction;
* code/headless/file templates are never enabled;
* request/response bodies are not captured (``-omit-raw``).

Info-severity ``tech``-tagged detections are converted to technology
observations instead of findings.
"""

from __future__ import annotations

import re
from typing import Any

from pydantic import Field, field_validator

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
from ...identity import identity_header
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
from ...targets import Target, TargetKind, split_host_port
from .._common import ObservationSet, clean_hostname, clean_ip, port_value
from ..httpx import endpoint_base

_TOKEN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
SAFE_EXCLUDED_TAGS = ["dos", "fuzz", "fuzzing", "intrusive", "bruteforce", "brute-force", "default-login", "osint"]
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class NucleiConfig(AdapterConfig):
    severities: list[Severity] = Field(default_factory=lambda: [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])
    tags: list[str] = Field(default_factory=list, max_length=50)
    exclude_tags: list[str] = Field(default_factory=lambda: list(SAFE_EXCLUDED_TAGS), max_length=100)
    template_ids: list[str] = Field(default_factory=list, max_length=500)
    include_tech_detection: bool = True
    rate_limit: int = Field(default=50, ge=1, le=2000)
    concurrency: int = Field(default=10, ge=1, le=200)
    bulk_size: int = Field(default=10, ge=1, le=200)
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    retries: int = Field(default=1, ge=0, le=5)
    interactsh: bool = False
    identify_scanner: bool = True

    @field_validator("tags", "exclude_tags", "template_ids")
    @classmethod
    def _tokens(cls, v: list[str]) -> list[str]:
        out = []
        for t in v:
            t = t.strip().lower()
            if not _TOKEN.match(t):
                raise ValueError(f"invalid tag/template id: {t!r}")
            out.append(t)
        return sorted(set(out))

    @field_validator("exclude_tags")
    @classmethod
    def _always_exclude_dos(cls, v: list[str]) -> list[str]:
        # Denial-of-service templates are never allowed, regardless of profile.
        return sorted(set(v) | {"dos"})


def _category(tags: list[str], severity: Severity) -> FindingCategory:
    t = set(tags)
    if "cve" in t or "vuln" in t or "rce" in t or "sqli" in t or "xss" in t or "lfi" in t:
        return FindingCategory.VULNERABILITY
    if "ssl" in t or "tls" in t:
        return FindingCategory.CERTIFICATE
    if "misconfig" in t or "config" in t:
        return FindingCategory.MISCONFIGURATION
    if "exposure" in t or "panel" in t or "exposed" in t or "takeover" in t or "unauth" in t:
        return FindingCategory.EXPOSURE
    return FindingCategory.INFORMATION if severity == Severity.INFO else FindingCategory.VULNERABILITY


def _as_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [s.strip() for s in v.split(",") if s.strip()]
    return [str(x) for x in v if x]


def resolve_asset(rec: dict[str, Any]) -> tuple[AssetRef, str | None]:
    """Map a nuclei result onto the most specific platform asset."""
    for key in ("url", "host", "matched-at"):
        base = endpoint_base(str(rec.get(key) or ""))
        if base:
            return AssetRef(type=ObservedType.HTTP_ENDPOINT, value=base[0]), None
    host = str(rec.get("host") or rec.get("matched-at") or "")
    ip = clean_ip(rec.get("ip"))
    try:
        h, port = split_host_port(host)
        target_ip = clean_ip(h) or ip
        if target_ip:
            return AssetRef(type=ObservedType.PORT, value=port_value(target_ip, port)), target_ip
        return AssetRef(type=ObservedType.HOSTNAME, value=h), None
    except ValueError:
        pass
    hn = clean_hostname(host)
    if hn:
        return AssetRef(type=ObservedType.HOSTNAME, value=hn), None
    if ip:
        return AssetRef(type=ObservedType.IP_ADDRESS, value=ip), ip
    raise ValueError("unmappable nuclei result")


@register
class NucleiAdapter(ScannerAdapter):
    name = "nuclei"
    display_name = "Vulnerability & exposure detection"
    stage_types = frozenset({StageType.VULNERABILITY_DETECTION})
    target_kinds = frozenset({TargetKind.URL, TargetKind.HOST_PORT, TargetKind.HOSTNAME, TargetKind.IP})
    active = True
    binaries = ("nuclei",)
    config_model = NucleiConfig

    def build_argv(self, binary: str, tfile: str, out: str, cfg: NucleiConfig, templates_dir: str | None,
                   identity: str | None = None) -> list[str]:
        argv = [binary, "-l", tfile, "-jsonl", "-o", out, "-silent", "-nc", "-duc", "-omit-raw",
                "-severity", ",".join(s.value for s in cfg.severities),
                "-rl", str(cfg.rate_limit), "-c", str(cfg.concurrency), "-bs", str(cfg.bulk_size),
                "-timeout", str(cfg.timeout_seconds), "-retries", str(cfg.retries)]
        if templates_dir:
            argv += ["-t", templates_dir]
        if cfg.tags:
            argv += ["-tags", ",".join(cfg.tags)]
        if cfg.exclude_tags:
            argv += ["-etags", ",".join(cfg.exclude_tags)]
        if cfg.template_ids:
            argv += ["-id", ",".join(cfg.template_ids)]
        if not cfg.interactsh:
            argv.append("-ni")
        # Only identifies the scan when the deployment configured an identity.
        if cfg.identify_scanner and identity:
            argv += ["-H", identity]
        return argv

    async def execute(self, targets: list[Target], config: NucleiConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("nuclei", self.binaries)
        tfile = write_targets_file(ctx.workdir, targets)
        out = ctx.workdir / "nuclei.jsonl"
        argv = self.build_argv(binary, str(tfile), str(out), config, ctx.settings.get("nuclei_templates_dir"),
                               identity_header(ctx.settings))
        proc = await run_process(argv, timeout=ctx.timeout_seconds, cwd=str(ctx.workdir),
                                 env=minimal_env(home=str(ctx.settings.get("nuclei_home") or ctx.workdir)),
                                 max_output_bytes=ctx.max_output_bytes)
        data, truncated = tool_output(out, proc, ctx.max_output_bytes)
        return RawOutput(process=proc, files={"nuclei.jsonl": data}, truncated=truncated)

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return list(iter_json_lines(raw.primary))

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: NucleiConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        for rec in parsed:
            template_id = str(rec.get("template-id") or rec.get("templateID") or "").strip()
            info = rec.get("info") or {}
            if not template_id or not isinstance(info, dict):
                continue
            try:
                asset_ref, _ip = resolve_asset(rec)
            except ValueError:
                continue
            severity = Severity.parse(info.get("severity"))
            tags = [t.lower() for t in _as_list(info.get("tags"))]
            matcher = rec.get("matcher-name") or rec.get("matcher_name")
            extracted = rec.get("extracted-results") or []

            if config.include_tech_detection and "tech" in tags and severity == Severity.INFO \
                    and asset_ref.type == ObservedType.HTTP_ENDPOINT:
                tech = str(matcher or info.get("name") or template_id).strip()
                obs.add(ObservedType.TECHNOLOGY, tech.lower(), {"name": tech})
                obs.link(ObservedType.HTTP_ENDPOINT, asset_ref.value, RelationType.USES_TECHNOLOGY,
                         ObservedType.TECHNOLOGY, tech.lower(),
                         {"version": extracted[0]} if extracted and len(str(extracted[0])) < 64 else None)
                continue

            cls = info.get("classification") or {}
            cves = sorted({c.upper() for c in _as_list(cls.get("cve-id")) if _CVE.match(c)})
            cvss = cls.get("cvss-score")
            epss = cls.get("epss-score")
            rule_id = f"{template_id}:{matcher}" if matcher else template_id
            location = str(rec.get("matched-at") or rec.get("host") or "")[:1024] or None
            evidence = {
                "matched_at": location,
                "matcher": matcher,
                "extracted": [str(e)[:500] for e in extracted][:20],
                "template": template_id,
                "type": rec.get("type"),
                "ip": rec.get("ip"),
                "timestamp": rec.get("timestamp"),
            }
            obs.findings.append(FindingObservation(
                asset=asset_ref,
                rule_id=rule_id[:512],
                title=str(info.get("name") or template_id)[:512],
                description=info.get("description"),
                severity=severity,
                category=_category(tags, severity),
                cve=cves,
                cwe=[c.upper() for c in _as_list(cls.get("cwe-id"))],
                cvss_score=float(cvss) if isinstance(cvss, int | float) and 0 <= cvss <= 10 else None,
                cvss_vector=cls.get("cvss-metrics"),
                epss_score=float(epss) if isinstance(epss, int | float) and 0 <= epss <= 1 else None,
                references=[r for r in _as_list(info.get("reference")) if r.startswith(("http://", "https://"))][:20],
                remediation=info.get("remediation"),
                evidence={k: v for k, v in evidence.items() if v},
                tags=tags,
                location=location,
            ))
            obs.add(asset_ref.type, asset_ref.value)

        assets = []
        for t in targets:
            if t.kind == TargetKind.URL:
                base = endpoint_base(t.value)
                if base:
                    assets.append(AssetRef(type=ObservedType.HTTP_ENDPOINT, value=base[0]))
            elif t.kind == TargetKind.HOSTNAME:
                assets.append(AssetRef(type=ObservedType.HOSTNAME, value=t.value))
        coverage = []
        if assets:
            coverage.append(FindingCoverage(
                assets=assets,
                severities=config.severities,
                include_tags=config.tags or None,
                exclude_tags=config.exclude_tags or None,
                rule_ids=config.template_ids or None,
            ))
        return NormalizedOutput(observations=obs.all(), coverage=coverage)
