"""Execute a :class:`SensorJob` in-process. Used by the Celery sensor worker and
by the platform's inline mode (development/tests)."""

from __future__ import annotations

import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .base import ConfigurationError, ExecutionContext
from .execution import BinaryNotFound, ExecutionError
from .jobs import SensorJob, unseal_credentials
from .observations import SensorResult
from .registry import get_adapter

log = logging.getLogger(__name__)


def deployment_settings() -> dict[str, Any]:
    """Deployment-level (never user-supplied) sensor settings from the environment."""
    return {
        k: v
        for k, v in {
            "nuclei_templates_dir": os.environ.get("ASM_NUCLEI_TEMPLATES_DIR"),
            "nuclei_home": os.environ.get("ASM_NUCLEI_HOME"),
            "spiderfoot_url": os.environ.get("ASM_SPIDERFOOT_URL"),
            "crtsh_url": os.environ.get("ASM_CRTSH_URL"),
        }.items()
        if v
    }


def _failed(job: SensorJob, message: str, started: datetime) -> SensorResult:
    return SensorResult(adapter=job.adapter, status="failed", started_at=started, finished_at=datetime.now(UTC),
                        target_count=len(job.targets), errors=[message[:2000]])


async def execute_job(
    job: SensorJob, settings: dict[str, Any] | None = None, transport_key: bytes | None = None
) -> SensorResult:
    started = datetime.now(UTC)
    try:
        adapter = get_adapter(job.adapter)
    except KeyError as exc:
        return _failed(job, str(exc), started)
    credentials: dict[str, list[str]] = {}
    if job.sealed_credentials:
        credentials = unseal_credentials(job.sealed_credentials, job.job_id, transport_key)
    max_rate = int(os.environ.get("ASM_SCANNER_MAX_RATE", "2000"))
    max_out = int(os.environ.get("ASM_SCANNER_MAX_OUTPUT_MB", "64")) * 1024 * 1024
    max_raw = int(os.environ.get("ASM_RAW_OUTPUT_MAX_MB", "20")) * 1024 * 1024
    with tempfile.TemporaryDirectory(prefix="asm-sensor-") as wd:
        ctx = ExecutionContext(
            workdir=Path(wd),
            timeout_seconds=job.timeout_seconds,
            credentials=credentials,
            max_output_bytes=max_out,
            retain_raw_output=job.retain_raw_output,
            max_raw_output_bytes=max_raw,
            max_rate=max_rate,
            settings={**deployment_settings(), **(settings or {})},
        )
        try:
            return await adapter.run(list(job.targets), job.config, ctx)
        except (ConfigurationError, BinaryNotFound, ExecutionError) as exc:
            return _failed(job, f"{type(exc).__name__}: {exc}", started)
        except Exception as exc:  # noqa: BLE001 - a sensor must never crash the worker
            log.exception("sensor %s failed", job.adapter)
            return _failed(job, f"unexpected sensor error: {type(exc).__name__}", started)
