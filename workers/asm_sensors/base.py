"""The scanner adapter contract.

An adapter wraps one reconnaissance/vulnerability tool and is responsible for
four steps, mirroring the platform design:

1. ``validate_configuration`` – reject unsafe/invalid configuration up front.
2. ``execute``                – run the tool (subprocess, container or API).
3. ``parse_results``          – turn native output into python dicts.
4. ``normalize``              – map those dicts onto the observation schema.

``run`` drives the whole sequence and produces a :class:`SensorResult`. Adding
a new scanner means writing one subclass and registering it; the platform does
not need to change.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import logging
import secrets
from abc import ABC, abstractmethod
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, ValidationError

from .coordination import Coordinator, local_coordinator
from .execution import ExecutionError, ProcessResult, resolve_binary
from .observations import NormalizedOutput, RawArtifact, SensorResult
from .targets import Target, TargetKind

log = logging.getLogger(__name__)


class StageType(StrEnum):
    SUBDOMAIN_DISCOVERY = "subdomain_discovery"
    DNS_RESOLUTION = "dns_resolution"
    IP_ENRICHMENT = "ip_enrichment"
    PORT_DISCOVERY = "port_discovery"
    HTTP_DISCOVERY = "http_discovery"
    WEB_CRAWL = "web_crawl"
    VULNERABILITY_DETECTION = "vulnerability_detection"
    OSINT_ENRICHMENT = "osint_enrichment"


class AdapterConfig(BaseModel):
    """Base class for adapter configuration models.

    ``extra="forbid"`` is essential: configuration comes from scan profiles
    edited by users, and unknown keys must never be silently passed through to
    a tool. There is intentionally no free-form "extra arguments" field.
    """

    model_config = ConfigDict(extra="forbid")


class ConfigurationError(ValueError):
    pass


@dataclass
class ExecutionContext:
    workdir: Path
    timeout_seconds: int = 3600
    credentials: dict[str, list[str]] = field(default_factory=dict)
    max_output_bytes: int = 64 * 1024 * 1024
    retain_raw_output: bool = False
    max_raw_output_bytes: int = 20 * 1024 * 1024
    # Global safety cap for any rate parameter (requests or packets per second).
    max_rate: int = 2000
    # Deployment-level settings (never user supplied), e.g. service URLs.
    settings: dict[str, Any] = field(default_factory=dict)
    # Pool-wide leases for shared resources (e.g. a ZAP daemon); see coordination.py.
    coordinator: Coordinator = field(default_factory=local_coordinator)
    # Identifies this job in shared resources (context names, rule names).
    job_id: str = field(default_factory=lambda: secrets.token_hex(8))


@dataclass
class RawOutput:
    process: ProcessResult | None = None
    files: dict[str, bytes] = field(default_factory=dict)
    # Pure-python adapters (API based) put decoded records here.
    records: list[Any] = field(default_factory=list)
    # Anything in ``errors`` means the run did not finish everything it set out to
    # do (a failed API call, a deadline, a result limit), so it is reported as
    # partial and cannot vouch for the absence of anything.
    errors: list[str] = field(default_factory=list)
    # Output was clipped at the capture limit: records past the cut were lost.
    truncated: bool = False
    tool_version: str | None = None

    @property
    def primary(self) -> bytes:
        if self.files:
            return next(iter(self.files.values()))
        if self.process is not None:
            return self.process.stdout
        return json.dumps(self.records, default=str).encode()


class ScannerAdapter(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    adapter_version: ClassVar[str] = "1.0"
    stage_types: ClassVar[frozenset[StageType]]
    target_kinds: ClassVar[frozenset[TargetKind]]
    # Active sensors send traffic to the target itself and therefore require an
    # explicit active-scanning authorization in the organization's scope.
    active: ClassVar[bool] = False
    # Reports what a third party last saw, not what is live now (e.g. Shodan). The
    # platform then adds new knowledge but never refreshes liveness from it.
    historical: ClassVar[bool] = False
    binaries: ClassVar[tuple[str, ...]] = ()
    credential_providers: ClassVar[tuple[str, ...]] = ()
    config_model: ClassVar[type[AdapterConfig]]

    # ------------------------------------------------------------------ config
    def parse_config(self, raw: dict[str, Any] | None) -> AdapterConfig:
        try:
            return self.config_model.model_validate(raw or {})
        except ValidationError as exc:
            raise ConfigurationError(f"{self.name}: invalid configuration: {exc}") from exc

    def is_active(self, config: AdapterConfig) -> bool:
        """Whether this configuration sends traffic to the targets themselves.

        The platform requires explicit active-scanning authorization in scope
        for active runs. Adapters with a passive/active switch override this.
        """
        return self.active

    def apply_limits(self, config: AdapterConfig, ctx: ExecutionContext) -> AdapterConfig:
        """Clamp rate-like settings to the deployment's global cap."""
        updates = {}
        for fname in ("rate_limit", "rate", "threads", "concurrency"):
            if hasattr(config, fname):
                val = getattr(config, fname)
                if isinstance(val, int) and val > ctx.max_rate:
                    updates[fname] = ctx.max_rate
        return config.model_copy(update=updates) if updates else config

    async def validate_configuration(self, config: AdapterConfig, ctx: ExecutionContext) -> None:
        for binary in self.binaries:
            resolve_binary(binary, self.binaries)

    # --------------------------------------------------------------- pipeline
    @abstractmethod
    async def execute(self, targets: list[Target], config: AdapterConfig, ctx: ExecutionContext) -> RawOutput: ...

    @abstractmethod
    async def parse_results(self, raw: RawOutput) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def normalize(
        self, parsed: list[dict[str, Any]], targets: list[Target], config: AdapterConfig
    ) -> NormalizedOutput: ...

    # ------------------------------------------------------------------ driver
    def check_targets(self, targets: Iterable[Target]) -> list[Target]:
        out = []
        for t in targets:
            if t.kind not in self.target_kinds:
                raise ConfigurationError(f"{self.name} does not accept {t.kind} targets")
            out.append(t)
        return out

    async def run(
        self, targets: list[Target], raw_config: dict[str, Any] | None, ctx: ExecutionContext
    ) -> SensorResult:
        started = datetime.now(UTC)
        errors: list[str] = []
        targets = self.check_targets(targets)
        config = self.apply_limits(self.parse_config(raw_config), ctx)
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        await self.validate_configuration(config, ctx)

        raw = await self.execute(targets, config, ctx)
        errors.extend(raw.errors)
        # Completeness must be proven: any error, a failed/timed-out process or
        # clipped output makes the run partial (and therefore coverage-free).
        status = "partial" if raw.errors else "completed"
        if raw.process is not None and not raw.process.ok:
            detail = "timed out" if raw.process.timed_out else f"exit code {raw.process.returncode}"
            errors.append(f"{self.name} {detail}: {_tail(raw.process.stderr)}")
            status = "partial"
        if raw.truncated or (raw.process is not None and raw.process.stdout_truncated and not raw.files):
            errors.append(f"{self.name}: output exceeded the capture limit and was truncated")
            status = "partial"

        parsed = await self.parse_results(raw)
        normalized = await self.normalize(parsed, targets, config)
        if status == "partial" and not normalized.observations:
            status = "failed"
        if status != "completed":
            # A failed/partial run cannot vouch for absence of anything, so we
            # drop coverage to avoid false "port closed"/"asset gone" events.
            normalized.coverage = []

        artifacts = []
        if ctx.retain_raw_output:
            artifacts.append(make_artifact(f"{self.name}-output", raw.primary, ctx.max_raw_output_bytes))

        return SensorResult(
            adapter=self.name,
            adapter_version=self.adapter_version,
            tool_version=raw.tool_version,
            status=status,  # type: ignore[arg-type]
            historical=self.historical,
            started_at=started,
            finished_at=datetime.now(UTC),
            target_count=len(targets),
            observations=normalized.observations,
            coverage=normalized.coverage,
            errors=errors,
            stats={"parsed_records": len(parsed), "observations": len(normalized.observations)},
            artifacts=artifacts,
        )


# ---------------------------------------------------------------------- helpers
def _tail(data: bytes, limit: int = 500) -> str:
    return data[-limit:].decode("utf-8", "replace").strip()


def write_targets_file(workdir: Path, targets: Iterable[Target], name: str = "targets.txt") -> Path:
    path = workdir / name
    values = sorted({t.value for t in targets})
    for v in values:
        if "\n" in v or "\r" in v or v.startswith("-"):
            raise ExecutionError("refusing to write unsafe target")
    path.write_text("\n".join(values) + "\n", encoding="utf-8")
    return path


def read_output_file(path: Path, limit: int) -> tuple[bytes, bool]:
    """Read at most ``limit`` bytes; the flag is True when the file was longer."""
    if not path.exists():
        return b"", False
    with path.open("rb") as fh:
        data = fh.read(limit)
        return data, bool(fh.read(1))


def tool_output(path: Path, proc: ProcessResult, limit: int) -> tuple[bytes, bool]:
    """A tool's results from its ``-o`` file, falling back to captured stdout.

    Returns ``(data, truncated)``; callers must propagate ``truncated`` into
    :attr:`RawOutput.truncated` so a clipped run never claims coverage.
    """
    data, truncated = read_output_file(path, limit)
    if data:
        return data, truncated
    return proc.stdout, proc.stdout_truncated


def iter_json_lines(data: bytes) -> Iterator[dict[str, Any]]:
    for line in data.splitlines():
        line = line.strip()
        if not line or not line.startswith(b"{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            yield obj


def make_artifact(name: str, data: bytes, limit: int) -> RawArtifact:
    truncated = len(data) > limit
    body = data[:limit]
    return RawArtifact(
        name=name,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        truncated=truncated,
        data=base64.b64encode(gzip.compress(body)).decode("ascii"),
    )
