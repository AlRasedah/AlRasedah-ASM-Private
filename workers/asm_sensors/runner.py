"""Execute a :class:`SensorJob` in-process. Used by the Celery sensor worker and
by the platform's inline mode (development/tests)."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import socket
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import ConfigurationError, ExecutionContext
from .coordination import Coordinator, local_coordinator
from .execution import BinaryNotFound, ExecutionError
from .jobs import SealingError, SensorJob, unseal_credentials
from .observations import SensorResult
from .registry import get_adapter
from .targets import Target, TargetKind

log = logging.getLogger(__name__)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def deployment_settings() -> dict[str, Any]:
    """Deployment-level (never user-supplied) sensor settings from the environment."""
    return {
        k: v
        for k, v in {
            "nuclei_templates_dir": os.environ.get("ASM_NUCLEI_TEMPLATES_DIR"),
            "nuclei_home": os.environ.get("ASM_NUCLEI_HOME"),
            "spiderfoot_url": os.environ.get("ASM_SPIDERFOOT_URL"),
            "crtsh_url": os.environ.get("ASM_CRTSH_URL"),
            "zap_url": os.environ.get("ASM_ZAP_URL"),
            "zap_api_key": os.environ.get("ASM_ZAP_API_KEY"),
            # How scans look on the wire (see asm_sensors/identity.py).
            "scanner_identity": os.environ.get("ASM_SCANNER_IDENTITY"),
            "scanner_user_agent": os.environ.get("ASM_SCANNER_USER_AGENT"),
            # Lab/testing only: permit active scanning of private/reserved addresses.
            "allow_non_public_targets": os.environ.get("ASM_SCANNER_ALLOW_NON_PUBLIC", "").lower() in ("1", "true", "yes"),
        }.items()
        if v
    }


def _failed(job: SensorJob, message: str, started: datetime) -> SensorResult:
    return SensorResult(adapter=job.adapter, status="failed", started_at=started, finished_at=datetime.now(UTC),
                        target_count=len(job.targets), errors=[message[:2000]])


# ------------------------------------------------------------------ egress guard
async def _resolve(host: str, timeout: float = 5.0) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout)
    except (OSError, TimeoutError, UnicodeError):
        return set()
    out = set()
    for info in infos:
        try:
            out.add(ipaddress.ip_address(str(info[4][0]).split("%", 1)[0]))
        except ValueError:
            continue
    return out


async def egress_filter(targets: Sequence[Target], *, allow_non_public: bool,
                        excluded: Sequence[IPNetwork] = ()) -> tuple[list[Target], list[str]]:
    """Drop active-scan targets whose *connection destination* is not allowed.

    The platform authorizes names; this checks where they point *now*, just before
    the tool connects: every address a hostname resolves to must be publicly
    routable (unless the deployment allows non-public scanning) and outside the
    scope's excluded ranges. Returns ``(kept, reasons_for_dropped)``.

    This narrows, but cannot close, the window for DNS answers that change between
    this check and the tool's own lookup; deployments enforce the same rule with
    an egress firewall on the scanner network (docs/DEPLOYMENT.md).
    """
    if allow_non_public and not excluded:
        return list(targets), []
    sem = asyncio.Semaphore(50)

    def verdict(addrs: set[ipaddress.IPv4Address | ipaddress.IPv6Address]) -> str | None:
        for a in addrs:
            if not allow_non_public and not a.is_global:
                return f"resolves to non-public address {a}"
            if any(a.version == n.version and a in n for n in excluded):
                return f"resolves to excluded address {a}"
        return None

    async def check(t: Target) -> str | None:
        if t.kind == TargetKind.CIDR:
            net = ipaddress.ip_network(t.value, strict=False)
            if not allow_non_public and not net.is_global:
                return "non-public network"
            if any(net.version == n.version and net.overlaps(n) for n in excluded):
                return "overlaps an excluded range"
            return None
        host = t.host
        try:
            return verdict({ipaddress.ip_address(host)})
        except ValueError:
            pass
        async with sem:
            return verdict(await _resolve(host))

    verdicts = await asyncio.gather(*(check(t) for t in targets))
    kept = [t for t, v in zip(targets, verdicts, strict=True) if v is None]
    dropped = [f"{t.value}: {v}" for t, v in zip(targets, verdicts, strict=True) if v is not None]
    return kept, dropped


async def execute_job(
    job: SensorJob, settings: dict[str, Any] | None = None, transport_key: bytes | None = None,
    coordinator: Coordinator | None = None,
) -> SensorResult:
    started = datetime.now(UTC)
    try:
        adapter = get_adapter(job.adapter)
    except KeyError as exc:
        return _failed(job, str(exc), started)
    credentials: dict[str, list[str]] = {}
    if job.sealed_credentials:
        try:
            credentials = unseal_credentials(job.sealed_credentials, job.job_id, transport_key)
        except (SealingError, ValueError) as exc:
            return _failed(job, f"could not open the job's credential envelope: {exc}", started)
    max_rate = int(os.environ.get("ASM_SCANNER_MAX_RATE", "2000"))
    max_out = int(os.environ.get("ASM_SCANNER_MAX_OUTPUT_MB", "64")) * 1024 * 1024
    max_raw = int(os.environ.get("ASM_RAW_OUTPUT_MAX_MB", "20")) * 1024 * 1024
    merged = {**deployment_settings(), **(settings or {})}
    with tempfile.TemporaryDirectory(prefix="asm-sensor-") as wd:
        ctx = ExecutionContext(
            workdir=Path(wd),
            timeout_seconds=job.timeout_seconds,
            credentials=credentials,
            max_output_bytes=max_out,
            retain_raw_output=job.retain_raw_output,
            max_raw_output_bytes=max_raw,
            max_rate=max_rate,
            settings=merged,
            coordinator=coordinator or local_coordinator(),
            job_id=job.job_id[:16],
        )
        try:
            targets = list(job.targets)
            blocked: list[str] = []
            if adapter.is_active(adapter.parse_config(job.config)):
                targets, blocked = await egress_filter(
                    targets, allow_non_public=bool(merged.get("allow_non_public_targets")),
                    excluded=[ipaddress.ip_network(n, strict=False) for n in job.excluded_networks])
                if blocked:
                    log.warning("job %s: %d target(s) not scanned (egress policy)", job.job_id, len(blocked))
            if not targets:
                now = datetime.now(UTC)
                return SensorResult(adapter=job.adapter, status="completed", started_at=started, finished_at=now,
                                    target_count=0, errors=_blocked_note(blocked))
            result = await adapter.run(targets, job.config, ctx)
            if blocked:
                result.errors = _blocked_note(blocked) + result.errors
                result.stats["egress_blocked"] = len(blocked)
            return result
        except (ConfigurationError, BinaryNotFound, ExecutionError) as exc:
            return _failed(job, f"{type(exc).__name__}: {exc}", started)
        except Exception as exc:  # noqa: BLE001 - a sensor must never crash the worker
            log.exception("sensor %s failed", job.adapter)
            return _failed(job, f"unexpected sensor error: {type(exc).__name__}", started)


def _blocked_note(blocked: list[str]) -> list[str]:
    if not blocked:
        return []
    shown = "; ".join(blocked[:10]) + (f"; and {len(blocked) - 10} more" if len(blocked) > 10 else "")
    return [f"{len(blocked)} target(s) not scanned by egress policy: {shown}"]
