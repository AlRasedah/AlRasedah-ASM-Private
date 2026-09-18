"""Certificate Transparency discovery via the public crt.sh JSON interface.

Pure-python, passive: queries crt.sh, never the target. The base URL is a
deployment setting (``crtsh_url``) so air-gapped installs can point it at a
mirror or disable the sensor entirely.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from pydantic import Field

from ...base import AdapterConfig, ExecutionContext, RawOutput, ScannerAdapter, StageType
from ...observations import NormalizedOutput, ObservedType
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_hostname

DEFAULT_URL = "https://crt.sh/"


class CrtshConfig(AdapterConfig):
    exclude_expired: bool = False
    request_timeout_seconds: int = Field(default=60, ge=5, le=300)
    retries: int = Field(default=2, ge=0, le=5)


@register
class CrtshAdapter(ScannerAdapter):
    name = "crtsh"
    display_name = "Certificate transparency"
    stage_types = frozenset({StageType.SUBDOMAIN_DISCOVERY})
    target_kinds = frozenset({TargetKind.DOMAIN})
    active = False
    config_model = CrtshConfig

    async def execute(self, targets: list[Target], config: CrtshConfig, ctx: ExecutionContext) -> RawOutput:  # type: ignore[override]
        base = ctx.settings.get("crtsh_url", DEFAULT_URL)
        raw = RawOutput()
        async with httpx.AsyncClient(timeout=config.request_timeout_seconds, follow_redirects=False,
                                     headers={"User-Agent": "Exteriq-ASM"}) as client:
            for t in targets:
                params = {"q": f"%.{t.value}", "output": "json"}
                if config.exclude_expired:
                    params["exclude"] = "expired"
                for attempt in range(config.retries + 1):
                    try:
                        resp = await client.get(base, params=params)
                        resp.raise_for_status()
                        rows = resp.json()
                        if isinstance(rows, list):
                            raw.records.extend({"query": t.value, **r} for r in rows if isinstance(r, dict))
                        break
                    except (httpx.HTTPError, ValueError) as exc:
                        if attempt == config.retries:
                            raw.errors.append(f"crt.sh query for {t.value} failed: {type(exc).__name__}")
                        else:
                            await asyncio.sleep(2 * (attempt + 1))
        return raw

    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]:
        return raw.records

    async def normalize(self, parsed: list[dict[str, Any]], targets: list[Target], config: CrtshConfig) -> NormalizedOutput:  # type: ignore[override]
        obs = ObservationSet()
        roots = [t.value for t in targets]
        for rec in parsed:
            names = str(rec.get("name_value") or "").split("\n") + [str(rec.get("common_name") or "")]
            for name in names:
                wildcard = name.strip().startswith("*.")
                host = clean_hostname(name)
                if not host or not any(host == r or host.endswith("." + r) for r in roots):
                    continue
                attrs: dict[str, Any] = {"discovery_sources": ["certificate_transparency"]}
                if wildcard:
                    attrs["wildcard_certificate_seen"] = True
                obs.add(ObservedType.HOSTNAME, host, attrs, confidence=60)
        return NormalizedOutput(observations=obs.all(), coverage=[])
