"""Notification engine: match events against tenant policies and deliver them."""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assets.queries import display_ips
from app.core.config import get_settings
from app.models import (
    Asset,
    AssetEvent,
    Finding,
    Integration,
    NotificationDelivery,
    NotificationPolicy,
    Organization,
    Tenant,
    TenantMembership,
    User,
    UserAlertPreference,
)
from app.models.enums import DeliveryStatus, Severity
from app.services.secrets import get_secret_value

from .channels import CHANNELS, ChannelError, Destination, email_message
from .mailer import MailNotConfigured, send_email

log = logging.getLogger(__name__)
_RANK = {s.value: i for i, s in enumerate(Severity)}
MAX_ATTEMPTS = 5


def event_payload(db: Session, ev: AssetEvent, tenant: Tenant | None = None) -> dict[str, Any]:
    asset = db.get(Asset, ev.asset_id) if ev.asset_id else None
    finding = db.get(Finding, ev.finding_id) if ev.finding_id else None
    org = db.get(Organization, ev.organization_id) if ev.organization_id else None
    base = get_settings().public_url.rstrip("/")
    ips = display_ips(asset) if asset else []
    return {
        "source": "exteriq-asm",
        "version": 1,
        "event_id": str(ev.id),
        "event_type": ev.event_type.value,
        "severity": ev.severity.value,
        "title": ev.title,
        "summary": ev.summary,
        "tenant": tenant.slug if tenant else None,
        "organization": org.name if org else None,
        "asset": ev.asset_value,
        "asset_type": ev.asset_type.value if ev.asset_type else None,
        "ip": ips[0] if ips else None,
        "finding": finding.title if finding else None,
        "cve": finding.cve if finding else None,
        "risk_score": asset.risk_score if asset else None,
        "previous": ev.previous_state,
        "current": ev.new_state,
        "occurred_at": ev.occurred_at.isoformat(),
        "url": f"{base}/assets/{ev.asset_id}" if ev.asset_id else f"{base}/changes",
    }


def policy_matches(policy: NotificationPolicy, ev: AssetEvent) -> bool:
    if not policy.enabled:
        return False
    if ev.is_baseline and not policy.include_baseline:
        return False
    if policy.event_types and ev.event_type.value not in policy.event_types:
        return False
    if _RANK[ev.severity.value] < _RANK[policy.min_severity.value]:
        return False
    if policy.organization_ids and ev.organization_id not in policy.organization_ids:
        return False
    return True


def _throttled(db: Session, policy: NotificationPolicy, ev: AssetEvent) -> bool:
    if not policy.throttle_minutes:
        return False
    since = datetime.now(UTC) - timedelta(minutes=policy.throttle_minutes)
    row = db.execute(select(NotificationDelivery.id).join(AssetEvent, AssetEvent.id == NotificationDelivery.event_id)
                     .where(NotificationDelivery.policy_id == policy.id, NotificationDelivery.created_at >= since,
                            NotificationDelivery.status == DeliveryStatus.SENT,
                            AssetEvent.event_type == ev.event_type, AssetEvent.asset_id == ev.asset_id).limit(1)).first()
    return row is not None


def deliver(db: Session, integration: Integration, payloads: list[dict[str, Any]]) -> None:
    channel = CHANNELS.get(integration.integration_type.value)
    if channel is None:
        raise ChannelError(f"unknown integration type {integration.integration_type}")
    secret = get_secret_value(db, integration.secret_id) if integration.secret_id else None
    # The owning tenant comes from the integration row, never from its configuration.
    channel.send(integration.config or {}, secret, payloads,
                 Destination(tenant_id=integration.tenant_id, integration_id=integration.id))


# A user who has not chosen otherwise gets high and critical changes in their inbox.
DEFAULT_ALERTS = {"enabled": True, "min_severity": Severity.HIGH, "event_types": [], "organization_ids": [],
                  "include_baseline": False}


def personal_preferences(db: Session, tenant_id: uuid.UUID) -> list[tuple[User, UserAlertPreference | None]]:
    """Active members of the tenant with their alert preferences (None = the default)."""
    rows = db.execute(select(User, TenantMembership).join(TenantMembership, TenantMembership.user_id == User.id)
                      .where(TenantMembership.tenant_id == tenant_id, TenantMembership.is_active.is_(True),
                             User.is_active.is_(True))).all()
    prefs = {p.user_id: p for p in db.execute(select(UserAlertPreference).where(
        UserAlertPreference.tenant_id == tenant_id)).scalars()}
    return [(user, prefs.get(user.id)) for user, _ in rows]


def personal_matches(pref: UserAlertPreference | None, ev: AssetEvent) -> bool:
    """Does this event belong in the user's own inbox?"""
    enabled = pref.enabled if pref else DEFAULT_ALERTS["enabled"]
    if not enabled:
        return False
    min_severity = pref.min_severity if pref else DEFAULT_ALERTS["min_severity"]
    if _RANK[ev.severity.value] < _RANK[min_severity.value]:
        return False
    include_baseline = pref.include_baseline if pref else DEFAULT_ALERTS["include_baseline"]
    if ev.is_baseline and not include_baseline:
        return False
    event_types = (pref.event_types if pref else None) or []
    if event_types and ev.event_type.value not in event_types:
        return False
    organizations = (pref.organization_ids if pref else None) or []
    return not organizations or ev.organization_id in organizations


def _deliver_personal(db: Session, tenant: Tenant | None, tenant_id: uuid.UUID, events: list[AssetEvent],
                      payloads: dict[uuid.UUID, dict[str, Any]], now: datetime, stats: dict[str, int]) -> None:
    """Email each member the changes they asked for, at their own login address.

    The address is never user-supplied: it is the account's verified login email,
    and members only ever receive their own tenant's events.
    """
    if not events:
        return
    for user, pref in personal_preferences(db, tenant_id):
        mine = [ev for ev in events if personal_matches(pref, ev)]
        if not mine:
            continue
        batch = [payloads.get(ev.id) or event_payload(db, ev, tenant) for ev in mine]
        subject, body = email_message(batch)
        # Recorded before the attempt, one row per event, exactly as an integration
        # delivery is: a failure here must be retryable and visible, not lost with the
        # event already marked notified.
        deliveries = [NotificationDelivery(tenant_id=tenant_id, event_id=ev.id, recipient_user_id=user.id,
                                           attempts=1) for ev in mine]
        db.add_all(deliveries)
        try:
            send_email([user.email], subject, body)
            for d in deliveries:
                d.status, d.sent_at = DeliveryStatus.SENT, now
            stats["personal_sent"] += len(mine)
            if pref is not None:
                pref.last_sent_at = now
        except MailNotConfigured as exc:
            # No mail server at all: nothing to retry for anyone in this tenant, and a
            # queue of doomed rows would only hide the real problem.
            for d in deliveries:
                d.status, d.last_error = DeliveryStatus.SKIPPED, str(exc)[:1000]
            stats["personal_skipped"] += len(mine)
            log.info("personal alerts for %s skipped: email delivery is not configured", tenant_id)
            return
        except Exception as exc:  # noqa: BLE001 - one bad address must not stop the rest
            for d in deliveries:
                d.status, d.last_error = DeliveryStatus.FAILED, f"{type(exc).__name__}: {exc}"[:1000]
            stats["personal_failed"] += len(mine)
            log.warning("personal alert delivery failed for a user in tenant %s: %s", tenant_id, type(exc).__name__)


def dispatch_pending(db: Session, limit: int = 1000) -> dict[str, int]:
    """Process events not yet evaluated for notification (system session)."""
    stats = {"events": 0, "sent": 0, "failed": 0, "skipped": 0,
             "personal_sent": 0, "personal_failed": 0, "personal_skipped": 0}
    events = db.execute(select(AssetEvent).where(AssetEvent.notified.is_(False)).order_by(AssetEvent.occurred_at)
                        .limit(limit).with_for_update(skip_locked=True)).scalars().all()
    if not events:
        return stats
    by_tenant: dict[uuid.UUID, list[AssetEvent]] = defaultdict(list)
    for ev in events:
        by_tenant[ev.tenant_id].append(ev)
    now = datetime.now(UTC)
    for tenant_id, evs in by_tenant.items():
        tenant = db.get(Tenant, tenant_id)
        policies = db.execute(select(NotificationPolicy).where(NotificationPolicy.tenant_id == tenant_id,
                                                               NotificationPolicy.enabled.is_(True))).scalars().all()
        integrations = {i.id: i for i in db.execute(select(Integration).where(
            Integration.tenant_id == tenant_id, Integration.enabled.is_(True))).scalars()}
        # (integration) -> [(event, policy, payload)] so each channel gets one batched delivery.
        outbox: dict[uuid.UUID, list[tuple[AssetEvent, NotificationPolicy, dict[str, Any]]]] = defaultdict(list)
        payloads: dict[uuid.UUID, dict[str, Any]] = {}
        for ev in evs:
            stats["events"] += 1
            ev.notified, ev.notified_at = True, now
            payload = None
            for policy in policies:
                if not policy_matches(policy, ev):
                    continue
                if _throttled(db, policy, ev):
                    stats["skipped"] += 1
                    continue
                payload = payload or event_payload(db, ev, tenant)
                payloads[ev.id] = payload
                for iid in policy.integration_ids or []:
                    if iid in integrations and not any(e.id == ev.id for e, _, _ in outbox[iid]):
                        outbox[iid].append((ev, policy, payload))
        for iid, items in outbox.items():
            integ = integrations[iid]
            deliveries = [NotificationDelivery(tenant_id=tenant_id, event_id=ev.id, policy_id=policy.id,
                                               integration_id=iid, attempts=1) for ev, policy, _ in items]
            db.add_all(deliveries)
            try:
                deliver(db, integ, [p for _, _, p in items])
                for d in deliveries:
                    d.status, d.sent_at = DeliveryStatus.SENT, now
                integ.last_success_at = now
                stats["sent"] += len(items)
            except (ChannelError, ValueError) as exc:
                for d in deliveries:
                    d.status, d.last_error = DeliveryStatus.FAILED, str(exc)[:1000]
                integ.last_error, integ.last_error_at = str(exc)[:1000], now
                stats["failed"] += len(items)
                log.warning("notification via integration %s failed: %s", iid, exc)
        _deliver_personal(db, tenant, tenant_id, evs, payloads, now, stats)
        db.commit()
    return stats


def retry_failed(db: Session) -> int:
    now = datetime.now(UTC)
    rows = db.execute(select(NotificationDelivery).where(NotificationDelivery.status == DeliveryStatus.FAILED,
                                                         NotificationDelivery.attempts < MAX_ATTEMPTS)
                      .limit(200)).scalars().all()
    retried = 0
    for d in rows:
        if d.created_at + timedelta(minutes=2 ** d.attempts) > now:
            continue  # exponential back-off
        ev = db.get(AssetEvent, d.event_id) if d.event_id else None
        if ev is None:
            d.status = DeliveryStatus.SKIPPED
            continue
        if d.recipient_user_id is not None:  # a personal alert
            user = db.get(User, d.recipient_user_id)
            if user is None or not user.is_active:
                d.status = DeliveryStatus.SKIPPED
                continue
            d.attempts += 1
            subject, body = email_message([event_payload(db, ev, db.get(Tenant, ev.tenant_id))])
            try:
                send_email([user.email], subject, body)
                d.status, d.sent_at, d.last_error = DeliveryStatus.SENT, now, None
                retried += 1
            except MailNotConfigured as exc:
                d.status, d.last_error = DeliveryStatus.SKIPPED, str(exc)[:1000]
            except Exception as exc:  # noqa: BLE001 - keep trying the other recipients
                d.last_error = f"{type(exc).__name__}: {exc}"[:1000]
            continue
        integ = db.get(Integration, d.integration_id) if d.integration_id else None
        if integ is None or not integ.enabled:
            d.status = DeliveryStatus.SKIPPED
            continue
        d.attempts += 1
        try:
            deliver(db, integ, [event_payload(db, ev, db.get(Tenant, ev.tenant_id))])
            d.status, d.sent_at, d.last_error = DeliveryStatus.SENT, now, None
            retried += 1
        except (ChannelError, ValueError) as exc:
            d.last_error = str(exc)[:1000]
    db.commit()
    return retried


def send_test(db: Session, integration: Integration) -> None:
    now = datetime.now(UTC)
    payload = {"source": "exteriq-asm", "version": 1, "event_id": str(uuid.uuid4()), "event_type": "test",
               "severity": "info", "title": "Exteriq ASM test notification",
               "summary": "If you can read this, the integration works.", "tenant": None, "organization": None,
               "asset": "test.example.com", "asset_type": "subdomain", "ip": "192.0.2.1", "finding": None,
               "cve": None, "risk_score": 0, "previous": None, "current": None, "occurred_at": now.isoformat(),
               "url": get_settings().public_url}
    deliver(db, integration, [payload])
    integration.last_success_at = now
