"""Password hashing (Argon2id), token generation and JWT handling."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import get_settings

# OWASP-recommended Argon2id parameters (m=64MiB, t=3, p=4). The test suite uses
# cheaper parameters purely for speed; hashes are still Argon2id.
_hasher = (
    PasswordHasher(time_cost=1, memory_cost=8 * 1024, parallelism=1)
    if get_settings().env == "test"
    else PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=4, hash_len=32, salt_len=16)
)
# A pre-computed hash used to equalize timing when the user does not exist.
_DUMMY_HASH = _hasher.hash("timing-equalizer-" + secrets.token_hex(8))

JWT_ALGORITHM = "HS256"
ACCESS_AUDIENCE = "asm-api"
MFA_AUDIENCE = "asm-mfa"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


COMMON_PASSWORDS = {
    "password", "password123", "123456789012", "qwertyuiop12", "letmein12345", "welcome12345",
    "administrator", "changeme1234", "p@ssw0rd1234", "iloveyou1234",
}


def password_policy_errors(password: str, email: str | None = None) -> list[str]:
    s = get_settings()
    errors = []
    if len(password) < s.password_min_length:
        errors.append(f"must be at least {s.password_min_length} characters")
    if len(password) > 256:
        errors.append("must be at most 256 characters")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("is too common")
    classes = sum(bool(any(f(c) for c in password)) for f in (str.islower, str.isupper, str.isdigit))
    classes += any(not c.isalnum() for c in password)
    if classes < 3:
        errors.append("must contain at least three of: lowercase, uppercase, digits, symbols")
    if email and email.split("@")[0].lower() in password.lower() and len(email.split("@")[0]) >= 4:
        errors.append("must not contain your email name")
    return errors


def new_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def hash_token(token: str) -> str:
    """Opaque tokens (refresh, reset) are stored only as keyed hashes."""
    key = get_settings().secret_key.get_secret_value().encode()
    return hmac.new(key, token.encode(), hashlib.sha256).hexdigest()


def _secret() -> str:
    return get_settings().secret_key.get_secret_value()


def create_access_token(
    *, user_id: uuid.UUID, tenant_id: uuid.UUID | None, role: str, session_id: uuid.UUID, platform_admin: bool
) -> tuple[str, datetime]:
    now = datetime.now(UTC)
    exp = now + timedelta(minutes=get_settings().access_token_ttl_minutes)
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id) if tenant_id else None,
        "role": role,
        "sid": str(session_id),
        "pa": platform_admin,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "aud": ACCESS_AUDIENCE,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM), exp


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM], audience=ACCESS_AUDIENCE,
                      options={"require": ["exp", "sub", "sid", "aud"]})


def create_mfa_challenge(user_id: uuid.UUID, tenant_id: uuid.UUID | None) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "tid": str(tenant_id) if tenant_id else None,
        "aud": MFA_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=get_settings().mfa_challenge_ttl_minutes)).timestamp()),
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_mfa_challenge(token: str) -> dict[str, Any]:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM], audience=MFA_AUDIENCE)
