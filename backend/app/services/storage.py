"""Object storage abstraction.

``local`` stores files on a mounted volume; ``s3`` works with any
S3-compatible store (MinIO, OCI Object Storage S3 compatibility, Ceph, AWS) —
no provider-specific services are required, so the platform runs entirely
in-Kingdom on any infrastructure.
"""

from __future__ import annotations

import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Protocol

from app.core.config import get_settings

_KEY_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9/_.\-]{0,500}$")


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None: ...
    def get(self, key: str) -> bytes: ...
    def delete(self, key: str) -> None: ...
    def exists(self, key: str) -> bool: ...


def _check_key(key: str) -> str:
    if not _KEY_RE.match(key) or ".." in key.split("/"):
        raise ValueError("invalid object key")
    return key


class LocalObjectStore:
    def __init__(self, root: str) -> None:
        self.root = Path(root).resolve()

    def _path(self, key: str) -> Path:
        p = (self.root / _check_key(key)).resolve()
        if self.root not in p.parents:
            raise ValueError("object key escapes storage root")
        return p

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, p)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)

    def exists(self, key: str) -> bool:
        return self._path(key).exists()


class S3ObjectStore:
    def __init__(self) -> None:
        import boto3  # optional dependency: pip install exteriq-asm[s3]

        s = get_settings()
        self.bucket = s.s3_bucket
        self.client = boto3.client(
            "s3", endpoint_url=s.s3_endpoint_url, region_name=s.s3_region, aws_access_key_id=s.s3_access_key,
            aws_secret_access_key=s.s3_secret_key.get_secret_value() if s.s3_secret_key else None)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> None:
        self.client.put_object(Bucket=self.bucket, Key=_check_key(key), Body=data, ContentType=content_type)

    def get(self, key: str) -> bytes:
        return self.client.get_object(Bucket=self.bucket, Key=_check_key(key))["Body"].read()

    def delete(self, key: str) -> None:
        self.client.delete_object(Bucket=self.bucket, Key=_check_key(key))

    def exists(self, key: str) -> bool:
        try:
            self.client.head_object(Bucket=self.bucket, Key=_check_key(key))
            return True
        except Exception:  # noqa: BLE001
            return False


@lru_cache
def get_store() -> ObjectStore:
    s = get_settings()
    if s.storage_backend == "s3":
        return S3ObjectStore()
    return LocalObjectStore(s.storage_local_path)
