"""Deployment settings a platform administrator manages from the web interface.

Today this is mail delivery. Values stored here take precedence over the
``ASM_SMTP_*`` environment variables, so a deployment can be configured (and
corrected) without shell access or a container restart; the environment stays
usable as a bootstrap default. The SMTP password is encrypted at rest with the
platform keyring, like every other stored secret.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import get_settings
from app.models import PlatformSetting

SMTP_AAD = "platform:smtp"
SMTP_FIELDS = ("host", "port", "username", "sender", "starttls", "ssl")


def _row(db: Session, create: bool = False) -> PlatformSetting | None:
    row = db.get(PlatformSetting, 1)
    if row is None and create:
        row = PlatformSetting(id=1, smtp={})
        db.add(row)
        db.flush()
    return row


def smtp_override(db: Session) -> dict[str, Any]:
    """The stored mail-server settings, as an override for :func:`mailer.send_email`."""
    row = _row(db)
    if row is None or not (row.smtp or {}).get("host"):
        return {}
    cfg = {k: v for k, v in (row.smtp or {}).items() if k in SMTP_FIELDS and v is not None}
    if row.smtp_password_ciphertext:
        cfg["password"] = crypto.decrypt(row.smtp_password_ciphertext, SMTP_AAD).decode()
    return cfg


def email_status(db: Session) -> dict[str, Any]:
    """What the UI shows: where mail settings come from, and whether they exist at all."""
    stored = smtp_override(db)
    env = get_settings()
    return {
        "configured": bool(stored.get("host") or env.smtp_host),
        "source": "platform_settings" if stored.get("host") else ("environment" if env.smtp_host else "none"),
        # A saved mail server replaces the environment entirely (see mailer.send_email),
        # so what is shown here is what will actually be used — including a cleared
        # password, which must not silently fall back to ASM_SMTP_PASSWORD.
        "host": stored.get("host") if stored else env.smtp_host,
        "port": stored.get("port") if stored else env.smtp_port,
        "username": stored.get("username") if stored else env.smtp_username,
        "sender": stored.get("sender") if stored else env.smtp_from,
        "starttls": stored.get("starttls") if stored else env.smtp_starttls,
        "ssl": stored.get("ssl") if stored else env.smtp_ssl,
        "has_password": bool(stored.get("password")) if stored else bool(env.smtp_password),
        "editable": True,
    }


def set_email(db: Session, values: dict[str, Any], password: str | None, *, clear_password: bool = False,
              user_id: uuid.UUID | None = None) -> None:
    """Store mail-server settings. ``password=None`` keeps the stored one."""
    row = _row(db, create=True)
    assert row is not None
    row.smtp = {**(row.smtp or {}), **{k: v for k, v in values.items() if k in SMTP_FIELDS and v is not None}}
    if clear_password:
        row.smtp_password_ciphertext = None
    elif password:
        row.smtp_password_ciphertext = crypto.encrypt(password.encode(), SMTP_AAD)
    row.updated_by = user_id
    db.flush()
