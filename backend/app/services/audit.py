"""Tamper-evident audit logging."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.context import get_context
from app.core.logging import redact
from app.models import AuditLog


class Action:
    LOGIN = "auth.login"
    LOGIN_FAILED = "auth.login_failed"
    LOGOUT = "auth.logout"
    TOKEN_REUSE = "auth.refresh_token_reuse"
    PASSWORD_RESET_REQUESTED = "auth.password_reset_requested"
    PASSWORD_RESET = "auth.password_reset"
    PASSWORD_CHANGED = "auth.password_changed"
    MFA_ENABLED = "auth.mfa_enabled"
    MFA_DISABLED = "auth.mfa_disabled"
    TENANT_SWITCH = "auth.tenant_switch"
    API_TOKEN_CREATED = "auth.api_token_created"
    API_TOKEN_REVOKED = "auth.api_token_revoked"
    USER_CREATED = "user.created"
    USER_UPDATED = "user.updated"
    ROLE_CHANGED = "user.role_changed"
    USER_REMOVED = "user.removed"
    TENANT_CREATED = "tenant.created"
    TENANT_UPDATED = "tenant.updated"
    ORG_CREATED = "organization.created"
    ORG_UPDATED = "organization.updated"
    ORG_DELETED = "organization.deleted"
    SCOPE_ADDED = "scope.added"
    SCOPE_UPDATED = "scope.updated"
    SCOPE_REMOVED = "scope.removed"
    SCOPE_VERIFIED = "scope.verified"
    SCAN_CREATED = "scan.created"
    SCAN_CANCELLED = "scan.cancelled"
    PROFILE_CHANGED = "scan_profile.changed"
    SCHEDULE_CHANGED = "scan_schedule.changed"
    ASSET_UPDATED = "asset.updated"
    FINDING_UPDATED = "finding.updated"
    RISK_ACCEPTED = "finding.risk_accepted"
    EVENT_ACKNOWLEDGED = "event.acknowledged"
    INTEGRATION_CHANGED = "integration.changed"
    POLICY_CHANGED = "notification_policy.changed"
    CREDENTIAL_CHANGED = "credential.changed"
    SETTINGS_CHANGED = "settings.changed"
    REPORT_GENERATED = "report.generated"
    REPORT_DOWNLOADED = "report.downloaded"
    DATA_EXPORTED = "data.exported"
    ADVISORY_CHANGED = "threat_advisory.changed"
    ADVISORY_PUBLISHED = "threat_advisory.published"
    THREAT_CHECK_CHANGED = "threat_check.changed"
    THREAT_FEED_CHANGED = "threat_feed.changed"
    THREAT_FEED_RUN = "threat_feed.run"
    THREAT_CHECK_REQUESTED = "threat_check.requested"
    THREAT_REMEDIATION_UPDATED = "threat_match.updated"
    SCREENSHOT_REQUESTED = "screenshot.requested"
    SCREENSHOT_DELETED = "screenshot.deleted"
    SCREENSHOT_POLICY_CHANGED = "screenshot_policy.changed"
    SUPPORT_BUNDLE_CREATED = "support_bundle.created"
    SUPPORT_BUNDLE_DOWNLOADED = "support_bundle.downloaded"
    SUPPORT_BUNDLE_DELETED = "support_bundle.deleted"
    SETUP_COMPLETED = "setup.completed"


def _jsonable(value: Any) -> Any:
    if value is None:
        return None
    return json.loads(json.dumps(redact(value), default=_default, sort_keys=True))


def _default(o: Any) -> Any:
    if isinstance(o, uuid.UUID | datetime):
        return str(o)
    if isinstance(o, Enum):
        return o.value
    if isinstance(o, set | frozenset):
        return sorted(o)
    return str(o)


def _digest(prev_hash: str | None, row: dict[str, Any]) -> str:
    canonical = json.dumps(row, sort_keys=True, default=_default, separators=(",", ":"))
    return hashlib.sha256(((prev_hash or "") + canonical).encode()).hexdigest()


def _row_payload(entry: AuditLog) -> dict[str, Any]:
    return {
        "tenant_id": str(entry.tenant_id) if entry.tenant_id else None,
        "user_id": str(entry.user_id) if entry.user_id else None,
        "actor": entry.actor,
        "action": entry.action,
        "object_type": entry.object_type,
        "object_id": entry.object_id,
        "previous": entry.previous,
        "new": entry.new,
        "ip": entry.ip_address,
        "success": entry.success,
        "created_at": entry.created_at.astimezone(UTC).isoformat(),
    }


def record(
    session: Session,
    action: str,
    *,
    tenant_id: uuid.UUID | None = None,
    user_id: uuid.UUID | None = None,
    actor: str | None = None,
    object_type: str | None = None,
    object_id: Any = None,
    previous: Any = None,
    new: Any = None,
    success: bool = True,
    platform: bool = False,
) -> AuditLog:
    """Append to the tenant's chain (``tenant_id`` or the request's tenant), or to the
    platform chain when ``platform`` is set — for changes to global data such as the
    Threat Center catalog, which belong to no tenant."""
    ctx = get_context()
    tenant_id = None if platform else (tenant_id if tenant_id is not None else ctx.tenant_id)
    lock_key = f"audit:{tenant_id or 'platform'}"
    session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": lock_key})
    last = session.execute(
        select(AuditLog.hash, AuditLog.chain_seq)
        .where(AuditLog.tenant_id.is_(None) if tenant_id is None else AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.id.desc()).limit(1)
    ).first()
    prev_hash, prev_seq = (last[0], last[1]) if last else (None, 0)
    entry = AuditLog(
        chain_seq=prev_seq + 1,
        tenant_id=tenant_id,
        user_id=user_id if user_id is not None else ctx.user_id,
        actor=actor or ctx.actor,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        previous=_jsonable(previous),
        new=_jsonable(new),
        ip_address=ctx.ip,
        user_agent=(ctx.user_agent or "")[:512] or None,
        request_id=ctx.request_id,
        success=success,
        created_at=datetime.now(UTC),
        prev_hash=prev_hash,
    )
    entry.hash = _digest(prev_hash, _row_payload(entry))
    session.add(entry)
    session.flush()
    return entry


@dataclass
class ChainReport:
    intact: bool
    entries: int
    first_bad_id: int | None = None
    first_bad_seq: int | None = None
    reason: str | None = None


def check_chain(session: Session, tenant_id: uuid.UUID | None) -> ChainReport:
    """Walk one chain in order and check, for every entry, that

    * ``chain_seq`` is the next number (1, 2, 3, …) — a removed or never-committed entry
      in the middle shows up as a gap;
    * ``prev_hash`` is the previous entry's hash — a removed or reordered entry breaks the link;
    * ``hash`` matches the entry's content — an edited entry no longer hashes the same.

    Removing entries from the *end* of a chain cannot be detected from the chain alone;
    anchor the latest hash externally (e.g. the SIEM export) for that.
    """
    rows = session.execute(
        select(AuditLog).where(AuditLog.tenant_id.is_(None) if tenant_id is None else AuditLog.tenant_id == tenant_id)
        .order_by(AuditLog.id)
    ).scalars()
    prev = None
    expected = 1
    for row in rows:
        reason = None
        if row.chain_seq != expected:
            reason = f"sequence gap: expected entry #{expected}, found #{row.chain_seq}"
        elif row.prev_hash != prev:
            reason = "hash link to the previous entry is broken"
        elif _digest(prev, _row_payload(row)) != row.hash:
            reason = "entry content does not match its hash"
        if reason:
            return ChainReport(False, expected - 1, row.id, row.chain_seq, reason)
        prev = row.hash
        expected += 1
    return ChainReport(True, expected - 1)


def verify_chain(session: Session, tenant_id: uuid.UUID | None) -> tuple[bool, int | None]:
    """Recompute the chain. Returns (ok, first_bad_id); see ``check_chain`` for details."""
    report = check_chain(session, tenant_id)
    return report.intact, report.first_bad_id


def diff(before: dict[str, Any], after: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return only the changed keys of two snapshots."""
    keys = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
    return {k: before.get(k) for k in keys}, {k: after.get(k) for k in keys}
