"""The job contract between the platform orchestrator and sensor workers.

The platform publishes a :class:`SensorJob` on its pool's job queue
(``scanners.<pool>``); a sensor worker executes it and submits the
:class:`~asm_sensors.observations.SensorResult` in an authenticated
:class:`ResultEnvelope` on the pool's result queue (``results.<pool>``).
Sensor workers have **no database access** – everything they need is in the
job, and everything they learn is in the result.

Trust boundary. Sensor workers are treated as untrusted by the platform:

* Each worker pool has its own key, derived from the platform's master
  transport key (:func:`pool_key`). A pool's workers hold only their pool key,
  so they can open only their own pool's credential envelopes and can
  authenticate results only as their own pool.
* A worker never publishes platform tasks. Results go to the pool's result
  queue, which is consumed by a dedicated platform process that runs nothing
  but result submission, verifies the envelope's MAC with the pool key and
  accepts it only for the stage the job was dispatched for (job id, scan,
  stage, tenant and pool must all match what the platform persisted).
* The broker enforces the same split with per-pool ACL users (docker-compose).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
from collections.abc import Callable
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .observations import SensorResult
from .targets import Target

TASK_NAME = "asm.sensors.run"
# Seconds a job may run past its own timeout before the worker kills it outright (the
# broker's hard time limit). Anything that holds a slot for a job must cover this too.
JOB_HARD_LIMIT_GRACE = 300
RESULT_TASK_NAME = "asm.results.submit"
RESULT_QUEUE_PREFIX = "results"
_POOL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62})$")


class SealingError(ValueError):
    pass


def validate_pool(pool: str) -> str:
    """Worker pool names become queue names, broker ACL users and key labels."""
    if not isinstance(pool, str) or not _POOL_RE.match(pool):
        raise ValueError(f"invalid worker pool name: {pool!r} (lowercase letters, digits and '-')")
    return pool


def job_queue(prefix: str, pool: str) -> str:
    return f"{prefix}.{validate_pool(pool)}"


def result_queue(pool: str) -> str:
    return f"{RESULT_QUEUE_PREFIX}.{validate_pool(pool)}"


class SensorJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    job_id: str
    tenant_id: str
    scan_id: str
    stage_id: str
    adapter: str
    targets: list[Target] = Field(max_length=500_000)
    config: dict[str, Any] = Field(default_factory=dict)
    # Tenant scanner credentials, AES-GCM sealed with the pool's key so they never
    # sit in the message broker in clear text (and only that pool can open them).
    sealed_credentials: str | None = None
    timeout_seconds: int = Field(default=3600, ge=30, le=86_400)
    retain_raw_output: bool = False
    # The scope's excluded IP ranges: active sensors re-check every resolved
    # destination against them just before connecting (see runner.egress_filter).
    excluded_networks: list[str] = Field(default_factory=list, max_length=10_000)
    # Latest moment the job may *start*. The platform keeps the job's execution slot until
    # this plus the job's hard time limit, so a delivery that arrives later than this is
    # refused rather than run after its slot was given to someone else.
    not_after: datetime | None = None

    @field_validator("excluded_networks")
    @classmethod
    def _networks(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(n, strict=False)) for n in v]


# ------------------------------------------------------------------------ keys
def decode_key(raw: str, name: str = "ASM_SCANNER_TRANSPORT_KEY") -> bytes:
    try:
        k = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
    except ValueError as exc:
        raise SealingError(f"{name} is not valid base64") from exc
    if len(k) != 32:
        raise SealingError(f"{name} must decode to 32 bytes")
    return k


def encode_key(key: bytes) -> str:
    return base64.urlsafe_b64encode(key).decode().rstrip("=")


def _hkdf(key: bytes, info: str) -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info.encode()).derive(key)


def pool_key(master: bytes, pool: str) -> bytes:
    """The key a worker pool holds, derived from the platform's master transport key."""
    return _hkdf(master, f"exteriq-asm/scanner-pool/v1/{validate_pool(pool)}")


def _transport_key(key: bytes | None = None) -> bytes:
    """The explicit key, or (inside a sensor worker) the pool key from the environment."""
    if key is not None:
        return key
    return decode_key(os.environ.get("ASM_SCANNER_TRANSPORT_KEY", ""))


# ----------------------------------------------------------------- credentials
def seal_credentials(credentials: dict[str, list[str]], job_id: str, key: bytes | None = None) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ct = AESGCM(_hkdf(_transport_key(key), "seal")).encrypt(nonce, json.dumps(credentials).encode(), job_id.encode())
    return base64.urlsafe_b64encode(nonce + ct).decode()


def unseal_credentials(token: str, job_id: str, key: bytes | None = None) -> dict[str, list[str]]:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    blob = base64.urlsafe_b64decode(token)
    try:
        data = AESGCM(_hkdf(_transport_key(key), "seal")).decrypt(blob[:12], blob[12:], job_id.encode())
    except InvalidTag as exc:
        raise SealingError("credential envelope failed authentication") from exc
    obj = json.loads(data)
    return {str(k): [str(x) for x in v] for k, v in obj.items()}


# --------------------------------------------------------------------- results
class ResultEnvelope(BaseModel):
    """A sensor result as submitted by a worker: bound to its job and MAC'd with the pool key."""

    model_config = ConfigDict(extra="forbid")

    job_id: str = Field(min_length=1, max_length=64)
    tenant_id: str = Field(max_length=64)
    scan_id: str = Field(max_length=64)
    stage_id: str = Field(max_length=64)
    pool: str
    result: dict[str, Any]
    mac: str = Field(max_length=128)


_SIGNED = ("job_id", "tenant_id", "scan_id", "stage_id", "pool", "result")


def _mac(key: bytes, envelope: dict[str, Any]) -> str:
    body = json.dumps({k: envelope[k] for k in _SIGNED}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(_hkdf(key, "result-mac"), body.encode(), hashlib.sha256).hexdigest()


def seal_result(job: SensorJob, result: SensorResult, pool: str, key: bytes | None = None) -> dict[str, Any]:
    envelope: dict[str, Any] = {"job_id": job.job_id, "tenant_id": job.tenant_id, "scan_id": job.scan_id,
                                "stage_id": job.stage_id, "pool": validate_pool(pool),
                                "result": result.model_dump(mode="json")}
    # Sign exactly what goes over the wire (the JSON round trip is lossless for these types).
    envelope = json.loads(json.dumps(envelope))
    envelope["mac"] = _mac(_transport_key(key), envelope)
    return envelope


class ResultRejected(ValueError):
    pass


def open_result(envelope: Any, key_for_pool: Callable[[str], bytes]) -> tuple[ResultEnvelope, SensorResult]:
    """Authenticate a submitted envelope; raises :class:`ResultRejected` if it is not genuine."""
    try:
        env = ResultEnvelope.model_validate(envelope)
        validate_pool(env.pool)
    except ValueError as exc:
        raise ResultRejected(f"malformed result envelope: {exc}") from exc
    if not hmac.compare_digest(_mac(key_for_pool(env.pool), envelope), env.mac):
        raise ResultRejected(f"result envelope for job {env.job_id} failed authentication (pool {env.pool})")
    try:
        return env, SensorResult.model_validate(env.result)
    except ValueError as exc:
        raise ResultRejected(f"invalid sensor result for job {env.job_id}: {exc}") from exc
