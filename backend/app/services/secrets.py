"""Secrets abstraction.

The default backend encrypts values (AES-256-GCM, see app.core.crypto) into
the ``secrets`` table. The ``SecretsBackend`` protocol is the seam for
HashiCorp Vault or a cloud KMS/secret manager: such a backend stores an
``external_ref`` instead of ciphertext. Secret values are never returned by
the API – only metadata (name, provider, last four characters).
"""

from __future__ import annotations

import json
import uuid
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.errors import NotFound
from app.models import Secret
from app.services import audit
from app.services.audit import Action


class SecretsBackend(Protocol):
    name: str

    def store(self, secret: Secret, value: str) -> None: ...
    def load(self, secret: Secret) -> str: ...


class DatabaseSecretsBackend:
    name = "database"

    @staticmethod
    def _aad(secret: Secret) -> str:
        return f"secret:{secret.tenant_id}:{secret.name}"

    def store(self, secret: Secret, value: str) -> None:
        secret.ciphertext = crypto.encrypt(value.encode(), self._aad(secret))
        secret.key_id = secret.ciphertext.split(":", 2)[1]
        secret.backend = self.name

    def load(self, secret: Secret) -> str:
        if not secret.ciphertext:
            raise NotFound("secret has no value")
        return crypto.decrypt(secret.ciphertext, self._aad(secret)).decode()


class VaultSecretsBackend:  # pragma: no cover - integration seam
    """Placeholder showing the contract for HashiCorp Vault (KV v2)."""

    name = "vault"

    def store(self, secret: Secret, value: str) -> None:
        raise NotImplementedError("Configure a Vault client and write to kv/<tenant>/<name>; set secret.external_ref")

    def load(self, secret: Secret) -> str:
        raise NotImplementedError


_BACKENDS: dict[str, SecretsBackend] = {"database": DatabaseSecretsBackend()}


def backend_for(secret: Secret) -> SecretsBackend:
    return _BACKENDS[secret.backend]


def put_secret(db: Session, *, tenant_id: uuid.UUID, name: str, value: str, kind: str = "generic",
               provider: str | None = None, user_id: uuid.UUID | None = None) -> Secret:
    secret = db.execute(select(Secret).where(Secret.tenant_id == tenant_id, Secret.name == name)).scalar_one_or_none()
    created = secret is None
    if secret is None:
        secret = Secret(tenant_id=tenant_id, name=name, kind=kind, provider=provider, created_by=user_id)
        db.add(secret)
    _BACKENDS["database"].store(secret, value)
    secret.last_four = value[-4:] if len(value) >= 8 else None
    db.flush()
    audit.record(db, Action.CREDENTIAL_CHANGED, tenant_id=tenant_id, object_type="secret", object_id=secret.id,
                 new={"name": name, "kind": kind, "provider": provider, "created": created})
    return secret


def get_secret_value(db: Session, secret_id: uuid.UUID) -> str:
    secret = db.get(Secret, secret_id)
    if secret is None:
        raise NotFound("secret not found")
    return backend_for(secret).load(secret)


def delete_secret(db: Session, secret_id: uuid.UUID) -> None:
    secret = db.get(Secret, secret_id)
    if secret is None:
        raise NotFound("secret not found")
    audit.record(db, Action.CREDENTIAL_CHANGED, tenant_id=secret.tenant_id, object_type="secret", object_id=secret.id,
                 previous={"name": secret.name}, new={"deleted": True})
    db.delete(secret)
    db.flush()


def scanner_credentials(db: Session, tenant_id: uuid.UUID, providers: tuple[str, ...]) -> dict[str, list[str]]:
    """Decrypted provider keys for a sensor job (only the providers the adapter declares)."""
    if not providers:
        return {}
    rows = db.execute(select(Secret).where(Secret.tenant_id == tenant_id, Secret.kind == "scanner_credential",
                                           Secret.provider.in_(providers))).scalars().all()
    out: dict[str, list[str]] = {}
    for s in rows:
        value = backend_for(s).load(s)
        try:
            parsed = json.loads(value)
            keys = [str(k) for k in parsed] if isinstance(parsed, list) else [value]
        except json.JSONDecodeError:
            keys = [value]
        out.setdefault(s.provider or "", []).extend(keys)
    return out
