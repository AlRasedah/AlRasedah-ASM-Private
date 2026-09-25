"""First-run setup without default passwords.

The installer asks for a one-time setup token (``cli setup-token``) and shows the setup
link. Opening it lets whoever holds the link create the first platform administrator —
once. The token is stored only as a SHA-256 hash, expires (30 minutes by default), is
consumed by the first successful use, and a new token voids any older unused one. Once a
platform administrator exists, setup is closed for good: tokens are refused.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.errors import Conflict, Forbidden
from app.models import SetupToken, Tenant, TenantMembership, User
from app.models.enums import Role
from app.services import audit
from app.services.audit import Action


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def needed(db: Session) -> bool:
    return db.execute(select(User.id).where(User.is_platform_admin.is_(True)).limit(1)).first() is None


def issue(db: Session, ttl: timedelta = timedelta(minutes=30)) -> str:
    """System session. Returns the token (shown once); only its hash is stored."""
    if not needed(db):
        raise Conflict("Setup is already complete; sign in instead")
    now = datetime.now(UTC)
    db.execute(update(SetupToken).where(SetupToken.used_at.is_(None)).values(used_at=now))  # void older tokens
    token = secrets.token_urlsafe(32)
    db.add(SetupToken(token_hash=_hash(token), expires_at=now + ttl))
    db.flush()
    return token


def complete(db: Session, *, token: str, email: str, password: str, full_name: str, tenant_name: str) -> User:
    """System session. Creates the first platform administrator and its tenant, once."""
    from app.auth.service import normalize_email, set_password
    from app.tenants.service import create_tenant

    now = datetime.now(UTC)
    row = db.execute(select(SetupToken).where(SetupToken.token_hash == _hash(token)).with_for_update()).scalar_one_or_none()
    if (row is None or row.used_at is not None or row.expires_at <= now
            or not hmac.compare_digest(row.token_hash, _hash(token))):
        raise Forbidden("This setup link is invalid or has expired; ask the server administrator for a new one")
    if not needed(db):
        raise Conflict("Setup is already complete; sign in instead")
    row.used_at = now
    tenant = db.execute(select(Tenant).order_by(Tenant.created_at).limit(1)).scalar_one_or_none() \
        or create_tenant(db, tenant_name)
    user = User(email=normalize_email(email), full_name=full_name, is_platform_admin=True, default_tenant_id=tenant.id)
    db.add(user)
    db.flush()
    set_password(db, user, password)
    db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.TENANT_ADMIN))
    audit.record(db, Action.SETUP_COMPLETED, tenant_id=tenant.id, user_id=user.id, actor="setup",
                 object_type="user", object_id=user.id, new={"email": user.email, "platform_admin": True})
    db.flush()
    return user
