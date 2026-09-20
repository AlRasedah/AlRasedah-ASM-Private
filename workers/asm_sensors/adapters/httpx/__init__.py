"""ProjectDiscovery httpx adapter (HTTP service discovery & fingerprinting, MIT).

Note: the Python ``httpx`` library ships a CLI with the same name. The sensor
image installs ProjectDiscovery's binary under ``/opt/asm/bin`` and sets
``ASM_BIN_HTTPX`` so the right executable is always used.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

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
from ...observations import NormalizedOutput, ObservedType, RelationCoverage, RelationType
from ...ports import WEB, normalize_spec, validate_port_spec
from ...registry import register
from ...targets import Target, TargetKind, split_host_port
from .._common import ObservationSet, clean_hostname, clean_ip, port_value

SCANNER_HEADER = "X-ASM-Scanner: Exteriq-ASM"


class HttpxConfig(AdapterConfig):
    ports: str = WEB  # used for hostname/IP targets without an explicit port
    follow_host_redirects: bool = True
    tech_detect: bool = True
    tls_grab: bool = True
    favicon: bool = True
    rate_limit: int = Field(default=150, ge=1, le=5000)
    threads: int = Field(default=50, ge=1, le=500)
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    retries: int = Field(default=1, ge=0, le=5)
    identify_scanner: bool = True

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: str) -> str:
        return normalize_spec(validate_port_spec(v))


def split_product(server: str | None) -> tuple[str | None, str | None]:
    """'nginx/1.25.3 (Ubuntu)' -> ('nginx', '1.25.3')."""
    if not server:
        return None, None
    first = server.strip().split(" ")[0]
    if "/" in first:
        name, _, ver = first.partition("/")
        return name.lower() or None, ver or None
    return first.lower() or None, None


def split_tech(entry: str) -> tuple[str, str | None]:
    name, sep, ver = str(entry).partition(":")
    return name.strip(), (ver.strip() or None) if sep else None


def endpoint_base(url: str) -> tuple[str, str, str, int] | None:
    try:
        p = urlsplit(url)
        port = p.port
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.hostname:
        return None
    host = p.hostname.lower()
    port = port or (443 if p.scheme == "https" else 80)
    default = (p.scheme == "https" and port == 443) or (p.scheme == "http" and port == 80)
    h = f"[{host}]" if ":" in host else host
    base = f"{p.scheme}://{h}" + ("" if default else f":{port}")
    return base, p.scheme, host, port


@register
class HttpxAdapter(ScannerAdapter):
    name = "httpx"
    display_name = "Web service discovery"
    stage_types = frozenset({StageType.HTTP_DISCOVERY})
    target_kinds = frozenset({TargetKind.HOSTNAME, TargetKind.IP, TargetKind.HOST_PORT, TargetKind.URL})
    active = True
    binaries = ("httpx",)
    config_model = HttpxConfig

    def build_argv(self, binary: str, tfile: str, out: str, cfg: HttpxConfig, need_ports: bool) -> list[str]:
        argv = [binary, "-l", tfile, "-json", "-o", out, "-silent", "-nc",
                "-sc", "-cl", "-ct", "-title", "-server", "-ip", "-cname", "-cdn", "-location",
                "-rl", str(cfg.rate_limit), "-t", str(cfg.threads),
                "-timeout", str(cfg.timeout_seconds), "-retries", str(cfg.retries)]
        if cfg.tech_detect:
            argv.append("-td")
        if cfg.tls_grab:
            argv.append("-tls-grab")
        if cfg.favicon:
            argv.append("-favicon")
        if cfg.follow_host_redirects:
            argv.append("-fhr")
        if need_ports:
            argv += ["-p", cfg.ports]
        if cfg.identify_scanner:
            argv += ["-H", SCANNER_HEADER]
        return argv

    async def execute(self, targets: list[Target], config: HttpxConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        binary = resolve_binary("httpx", self.binaries)
        out = ctx.workdir / "httpx.jsonl"
        raw = RawOutput()
        # Targets with explicit ports and bare hosts need different invocations.
        groups = {
            "explicit": [t for t in targets if t.kind in (TargetKind.HOST_PORT, TargetKind.URL)],
            "bare": [t for t in targets if t.kind in (TargetKind.HOSTNAME, TargetKind.IP)],
        }
        chunks: list[bytes] = []
        for label, group in groups.items():
            if not group:
                continue
            tfile = write_targets_file(ctx.workdir, group, name=f"targets-{label}.txt")
            gout = ctx.workdir / f"httpx-{label}.jsonl"
            proc = await run_process(self.build_argv(binary, str(tfile), str(gout), config, label == "bare"),
                                     timeout=ctx.timeout_seconds, cwd=str(ctx.workdir),
                                     env=minimal_env(home=str(ctx.workdir)), max_output_bytes=ctx.max_output_bytes)
            raw.process = proc if raw.process is None or not proc.ok else raw.process
            data, truncated = tool_output(gout, proc, ctx.max_output_bytes)
            raw.truncated = raw.truncated or truncated
            chunks.append(data)
        raw.files[out.name] = b"\n".join(chunks)
        return raw

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return [r for r in iter_json_lines(raw.primary) if not r.get("failed")]

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: HttpxConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        observed_endpoints: list[str] = []
        tls_endpoints: list[str] = []
        for rec in parsed:
            base = endpoint_base(str(rec.get("url") or ""))
            if not base:
                continue
            endpoint, scheme, host, port = base
            host_ip = clean_ip(host)
            ip = host_ip or clean_ip(rec.get("host")) or clean_ip(rec.get("host_ip")) or next(
                (clean_ip(a) for a in rec.get("a") or [] if clean_ip(a)), None)
            product, version = split_product(rec.get("webserver"))
            techs = [split_tech(t) for t in rec.get("tech") or [] if t]
            tls = rec.get("tls") if isinstance(rec.get("tls"), dict) else None
            attrs: dict[str, Any] = {
                "url": endpoint,
                "scheme": scheme,
                "host": host,
                "port": port,
                "ip": ip,
                "status_code": rec.get("status_code"),
                "title": (rec.get("title") or "")[:512] or None,
                "webserver": rec.get("webserver"),
                "content_type": rec.get("content_type"),
                "content_length": rec.get("content_length"),
                "location": rec.get("location"),
                "final_url": rec.get("final_url"),
                "cdn": bool(rec.get("cdn")),
                "cdn_name": rec.get("cdn_name"),
                "favicon_hash": rec.get("favicon"),
                "technologies": sorted({n for n, _ in techs}),
            }
            if tls:
                attrs["tls_version"] = tls.get("tls_version")
                attrs["tls_cipher"] = tls.get("cipher")
            obs.add(ObservedType.HTTP_ENDPOINT, endpoint, {k: v for k, v in attrs.items() if v is not None}, confidence=95)
            observed_endpoints.append(endpoint)

            if host_ip:
                obs.add(ObservedType.IP_ADDRESS, host_ip)
                obs.link(ObservedType.IP_ADDRESS, host_ip, RelationType.SERVES, ObservedType.HTTP_ENDPOINT, endpoint)
            else:
                h = clean_hostname(host)
                if h:
                    obs.add(ObservedType.HOSTNAME, h)
                    obs.link(ObservedType.HOSTNAME, h, RelationType.SERVES, ObservedType.HTTP_ENDPOINT, endpoint)
            if ip:
                pv = port_value(ip, port)
                obs.add(ObservedType.IP_ADDRESS, ip, {"cdn": True, "cdn_name": rec.get("cdn_name")} if rec.get("cdn") else None)
                obs.link(ObservedType.HTTP_ENDPOINT, endpoint, RelationType.HOSTED_ON, ObservedType.IP_ADDRESS, ip)
                obs.add(ObservedType.PORT, pv, {"port": port, "protocol": "tcp", "ip": ip, "state": "open"})
                obs.link(ObservedType.IP_ADDRESS, ip, RelationType.HAS_PORT, ObservedType.PORT, pv)
                svc = {"name": scheme, "product": product, "version": version, "banner": rec.get("webserver"),
                       "tls": scheme == "https", "detection": "http_probe"}
                obs.add(ObservedType.SERVICE, pv, {k: v for k, v in svc.items() if v is not None}, confidence=90)
                obs.link(ObservedType.PORT, pv, RelationType.RUNS_SERVICE, ObservedType.SERVICE, pv)

            for name, ver in techs:
                if not name:
                    continue
                obs.add(ObservedType.TECHNOLOGY, name.lower(), {"name": name})
                obs.link(ObservedType.HTTP_ENDPOINT, endpoint, RelationType.USES_TECHNOLOGY, ObservedType.TECHNOLOGY,
                         name.lower(), {"version": ver} if ver else None)

            fp = ((tls or {}).get("fingerprint_hash") or {}).get("sha256") if tls else None
            if tls and fp:
                tls_endpoints.append(endpoint)
                cert = {
                    "subject_cn": tls.get("subject_cn"),
                    "subject_dn": tls.get("subject_dn"),
                    "sans": sorted(set(tls.get("subject_an") or [])),
                    "issuer_cn": tls.get("issuer_cn"),
                    "issuer_dn": tls.get("issuer_dn"),
                    "issuer_org": tls.get("issuer_org"),
                    "serial": tls.get("serial"),
                    "not_before": tls.get("not_before"),
                    "not_after": tls.get("not_after"),
                    "self_signed": tls.get("self_signed"),
                    "wildcard": tls.get("wildcard_certificate"),
                }
                fp = str(fp).lower().replace(":", "")
                obs.add(ObservedType.CERTIFICATE, fp, {k: v for k, v in cert.items() if v is not None})
                obs.link(ObservedType.HTTP_ENDPOINT, endpoint, RelationType.PRESENTS_CERTIFICATE,
                         ObservedType.CERTIFICATE, fp, {"tls_version": tls.get("tls_version"), "cipher": tls.get("cipher")})

        coverage: list = []
        # Which ports were probed on which parent host.
        probed: dict[tuple[ObservedType, str], set[int]] = defaultdict(set)
        bare_ports = {int(p) for p in _expand(config.ports)}
        for t in targets:
            if t.kind in (TargetKind.HOSTNAME, TargetKind.IP):
                kind = ObservedType.IP_ADDRESS if t.kind == TargetKind.IP else ObservedType.HOSTNAME
                probed[(kind, t.value)] |= bare_ports
            elif t.kind == TargetKind.HOST_PORT:
                h, p = split_host_port(t.value)
                kind = ObservedType.IP_ADDRESS if clean_ip(h) else ObservedType.HOSTNAME
                probed[(kind, h)].add(p)
        grouped: dict[tuple[ObservedType, str], list[str]] = defaultdict(list)
        for (kind, host), ports in probed.items():
            grouped[(kind, normalize_spec(",".join(str(p) for p in sorted(ports))))].append(host)
        for (kind, spec), hosts in grouped.items():
            coverage.append(RelationCoverage(parent_type=kind, parents=sorted(hosts), relation=RelationType.SERVES,
                                             child_type=ObservedType.HTTP_ENDPOINT, constraints={"port_spec": spec}))
        if config.tech_detect and observed_endpoints:
            coverage.append(RelationCoverage(parent_type=ObservedType.HTTP_ENDPOINT, parents=sorted(set(observed_endpoints)),
                                             relation=RelationType.USES_TECHNOLOGY, child_type=ObservedType.TECHNOLOGY))
        if config.tls_grab and tls_endpoints:
            coverage.append(RelationCoverage(parent_type=ObservedType.HTTP_ENDPOINT, parents=sorted(set(tls_endpoints)),
                                             relation=RelationType.PRESENTS_CERTIFICATE, child_type=ObservedType.CERTIFICATE))
        return NormalizedOutput(observations=obs.all(), coverage=coverage)


def _expand(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            out.extend(range(int(a), int(b) + 1))
        else:
            out.append(int(part))
    return out
