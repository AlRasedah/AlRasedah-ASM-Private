"""The job contract between the platform orchestrator and sensor workers.

The platform publishes a :class:`SensorJob` on a sensor queue; a sensor worker
executes it and returns a :class:`~asm_sensors.observations.SensorResult`.
Sensor workers have **no database access** – everything they need is in the
job, and everything they learn is in the result.
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .targets import Target

TASK_NAME = "asm.sensors.run"


class SensorJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    tenant_id: str
    scan_id: str
    stage_id: str
    adapter: str
    targets: list[Target] = Field(max_length=500_000)
    config: dict[str, Any] = Field(default_factory=dict)
    # Tenant scanner credentials, AES-GCM sealed with the transport key so they
    # never sit in the message broker in clear text.
    sealed_credentials: str | None = None
    timeout_seconds: int = Field(default=3600, ge=30, le=86_400)
    retain_raw_output: bool = False


class SealingError(ValueError):
    pass


def _transport_key(key: bytes | None = None) -> bytes:
    if key is not None:
        return key
    raw = os.environ.get("ASM_SCANNER_TRANSPORT_KEY", "")
    try:
        k = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except ValueError as exc:
        raise SealingError("ASM_SCANNER_TRANSPORT_KEY is not valid base64") from exc
    if len(k) != 32:
        raise SealingError("ASM_SCANNER_TRANSPORT_KEY must decode to 32 bytes")
    return k


def seal_credentials(credentials: dict[str, list[str]], job_id: str, key: bytes | None = None) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ct = AESGCM(_transport_key(key)).encrypt(nonce, json.dumps(credentials).encode(), job_id.encode())
    return base64.urlsafe_b64encode(nonce + ct).decode()


def unseal_credentials(token: str, job_id: str, key: bytes | None = None) -> dict[str, list[str]]:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = base64.urlsafe_b64decode(token)
    try:
        data = AESGCM(_transport_key(key)).decrypt(blob[:12], blob[12:], job_id.encode())
    except InvalidTag as exc:
        raise SealingError("credential envelope failed authentication") from exc
    obj = json.loads(data)
    return {str(k): [str(x) for x in v] for k, v in obj.items()}
