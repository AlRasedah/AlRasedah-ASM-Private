"""Authenticated encryption for secrets at rest (AES-256-GCM with key rotation).

Ciphertext format: ``v1:<key_id>:<base64url(nonce || ciphertext+tag)>``.
Associated data binds each ciphertext to its tenant and secret name, so a
ciphertext copied to another row or tenant fails to decrypt.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from functools import lru_cache

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import PLACEHOLDER, get_settings


class CryptoError(ValueError):
    pass


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def generate_key() -> str:
    return b64e(os.urandom(32))


@dataclass(frozen=True)
class Keyring:
    active_id: str
    keys: dict[str, bytes]

    @classmethod
    def parse(cls, spec: str) -> Keyring:
        keys: dict[str, bytes] = {}
        order: list[str] = []
        for part in [p.strip() for p in spec.split(",") if p.strip()]:
            kid, sep, material = part.partition(":")
            if not sep or not kid.isalnum():
                raise CryptoError("encryption key entries must look like 'keyid:base64key'")
            raw = b64d(material)
            if len(raw) != 32:
                raise CryptoError(f"encryption key {kid!r} must be 32 bytes")
            keys[kid] = raw
            order.append(kid)
        if not order:
            raise CryptoError("no encryption keys configured")
        return cls(active_id=order[0], keys=keys)


@lru_cache
def get_keyring() -> Keyring:
    spec = get_settings().encryption_keys.get_secret_value()
    if not spec or PLACEHOLDER in spec:
        if get_settings().env == "production":
            raise CryptoError("ASM_ENCRYPTION_KEYS is not configured")
        # Development/test fallback derived from the secret key: never used in production.
        import hashlib

        seed = hashlib.sha256(("asm-dev-" + get_settings().secret_key.get_secret_value()).encode()).digest()
        return Keyring(active_id="dev", keys={"dev": seed})
    return Keyring.parse(spec)


def encrypt(plaintext: bytes, aad: str, keyring: Keyring | None = None) -> str:
    kr = keyring or get_keyring()
    nonce = os.urandom(12)
    ct = AESGCM(kr.keys[kr.active_id]).encrypt(nonce, plaintext, aad.encode())
    return f"v1:{kr.active_id}:{b64e(nonce + ct)}"


def decrypt(token: str, aad: str, keyring: Keyring | None = None) -> bytes:
    kr = keyring or get_keyring()
    try:
        version, kid, body = token.split(":", 2)
    except ValueError as exc:
        raise CryptoError("malformed ciphertext") from exc
    if version != "v1" or kid not in kr.keys:
        raise CryptoError("unknown ciphertext version or key id")
    blob = b64d(body)
    try:
        return AESGCM(kr.keys[kid]).decrypt(blob[:12], blob[12:], aad.encode())
    except InvalidTag as exc:
        raise CryptoError("ciphertext failed authentication") from exc


def needs_rotation(token: str, keyring: Keyring | None = None) -> bool:
    kr = keyring or get_keyring()
    return token.split(":", 2)[1] != kr.active_id


def pool_transport_key(pool: str) -> bytes:
    """The key held by one worker pool's sensor workers (derived from the master transport key).

    It seals that pool's job credentials and authenticates its results; no other
    pool can derive it.
    """
    from asm_sensors.jobs import pool_key

    return pool_key(transport_key(), pool)


def transport_key() -> bytes:
    """The platform's master transport key. Never given to sensor workers."""
    raw = get_settings().scanner_transport_key.get_secret_value()
    if not raw or PLACEHOLDER in raw:
        if get_settings().env == "production":
            raise CryptoError("ASM_SCANNER_TRANSPORT_KEY is not configured")
        import hashlib

        return hashlib.sha256(("asm-dev-transport-" + get_settings().secret_key.get_secret_value()).encode()).digest()
    key = b64d(raw)
    if len(key) != 32:
        raise CryptoError("ASM_SCANNER_TRANSPORT_KEY must be 32 bytes (base64url)")
    return key
