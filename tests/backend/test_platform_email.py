"""Email configured and consumed from the platform itself (no .env, no restart)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db.session import new_session, system_session
from app.integrations import notifications
from app.integrations.mailer import MailNotConfigured, send_email
from app.models import AssetEvent, PlatformSetting, UserAlertPreference
from app.models.enums import EventType, Severity
from app.services import platform_settings

PW = "Sup3r-Secret-Passw0rd!"
SMTP = {"host": "mail.example.com", "port": 2525, "username": "asm", "password": "mail-secret",
        "sender": "ASM <asm@example.com>", "starttls": True, "ssl": False}


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


def _auth(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


class _FakeSMTP:
    """Captures what the mailer would have sent."""

    sent: list = []

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.logged_in = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self, context=None):
        return None

    def login(self, username, password):  # noqa: S107 - test double for smtplib
        self.logged_in = (username, password)

    def send_message(self, msg):
        _FakeSMTP.sent.append({"host": self.host, "port": self.port, "to": msg["To"], "subject": msg["Subject"],
                               "login": self.logged_in, "body": msg.get_content()})


@pytest.fixture
def smtp():
    _FakeSMTP.sent = []
    with patch("app.integrations.mailer.smtplib.SMTP", _FakeSMTP):
        yield _FakeSMTP


class TestPlatformMailSettings:
    def test_administrator_configures_mail_from_the_interface(self, client, factory, smtp):
        tenant = factory.tenant()
        admin = factory.user(tenant.id, platform_admin=True)
        h = _auth(client, admin.email)

        before = client.get("/api/v1/settings/email", headers=h).json()
        assert before["configured"] is False and before["source"] == "none"

        saved = client.put("/api/v1/settings/email", headers=h, json=SMTP)
        assert saved.status_code == 200, saved.text
        assert saved.json()["source"] == "platform_settings" and saved.json()["has_password"] is True
        assert "password" not in saved.json() and "mail-secret" not in saved.text

        # Mail now goes through the saved server, with the stored password.
        send_email(["someone@example.org"], "hello", "body")
        assert smtp.sent[0]["host"] == "mail.example.com" and smtp.sent[0]["port"] == 2525
        assert smtp.sent[0]["login"] == ("asm", "mail-secret")

        # The password is encrypted at rest.
        with system_session() as db:
            row = db.get(PlatformSetting, 1)
            assert "mail-secret" not in (row.smtp_password_ciphertext or "")
            assert platform_settings.smtp_override(db)["password"] == "mail-secret"

    def test_test_button_reports_the_result(self, client, factory, smtp):
        tenant = factory.tenant()
        admin = factory.user(tenant.id, platform_admin=True)
        h = _auth(client, admin.email)
        failed = client.post("/api/v1/settings/email/test", headers=h)
        assert failed.status_code == 422 and "not configured" in failed.text

        client.put("/api/v1/settings/email", headers=h, json=SMTP)
        ok = client.post("/api/v1/settings/email/test", headers=h)
        assert ok.status_code == 200 and admin.email in ok.json()["message"]
        assert smtp.sent[-1]["to"] == admin.email

    def test_only_platform_administrators_may_change_it(self, client, factory):
        tenant = factory.tenant()
        tenant_admin = factory.user(tenant.id, role="tenant_admin")
        h = _auth(client, tenant_admin.email)
        assert client.get("/api/v1/settings/email", headers=h).status_code == 403
        assert client.put("/api/v1/settings/email", headers=h, json=SMTP).status_code == 403

    def test_unconfigured_mail_says_who_can_fix_it(self):
        with pytest.raises(MailNotConfigured, match="platform administrator"):
            send_email(["a@example.org"], "s", "b")


def _event(tenant_id, org_id, severity=Severity.HIGH, baseline=False):
    with new_session(tenant_id) as db:
        db.add(AssetEvent(tenant_id=tenant_id, organization_id=org_id, event_type=EventType.VULNERABILITY_DETECTED,
                          severity=severity, title=f"Test {severity.value} event", summary="something changed",
                          details={}, occurred_at=datetime.now(UTC), is_baseline=baseline))
        db.commit()


class TestPersonalAlerts:
    def test_members_get_their_own_alerts_by_default(self, client, factory, smtp):
        tenant = factory.tenant()
        org = factory.org(tenant.id)
        admin = factory.user(tenant.id, platform_admin=True)
        member = factory.user(tenant.id, role="security_analyst")
        client.put("/api/v1/settings/email", headers=_auth(client, admin.email), json=SMTP)

        prefs = client.get("/api/v1/settings/my-alerts", headers=_auth(client, member.email)).json()
        assert prefs == {**prefs, "enabled": True, "min_severity": "high", "is_default": True,
                         "email": member.email, "email_configured": True}

        _event(tenant.id, org.id, Severity.HIGH)
        _event(tenant.id, org.id, Severity.LOW)
        with system_session() as db:
            stats = notifications.dispatch_pending(db)

        assert stats["personal_sent"] == 2  # one high event, to each of the two members
        recipients = {m["to"] for m in smtp.sent}
        assert recipients == {admin.email, member.email}
        assert "Test high event" in smtp.sent[0]["body"] and "Test low event" not in smtp.sent[0]["body"]

    def test_a_user_can_change_or_switch_off_their_alerts(self, client, factory, smtp):
        tenant = factory.tenant()
        org = factory.org(tenant.id)
        admin = factory.user(tenant.id, platform_admin=True)
        member = factory.user(tenant.id, role="viewer")
        client.put("/api/v1/settings/email", headers=_auth(client, admin.email), json=SMTP)

        h = _auth(client, member.email)
        updated = client.put("/api/v1/settings/my-alerts", headers=h,
                             json={"enabled": True, "min_severity": "low", "event_types": [],
                                   "organization_ids": [], "include_baseline": False}).json()
        assert updated["min_severity"] == "low" and updated["is_default"] is False
        off = client.put("/api/v1/settings/my-alerts", headers=_auth(client, admin.email),
                         json={"enabled": False, "min_severity": "high"}).json()
        assert off["enabled"] is False

        _event(tenant.id, org.id, Severity.LOW)
        with system_session() as db:
            notifications.dispatch_pending(db)
        assert [m["to"] for m in smtp.sent] == [member.email]  # the admin switched theirs off

    def test_alerts_never_cross_tenants_and_use_the_login_address(self, client, factory, smtp):
        home, other = factory.tenant(), factory.tenant()
        admin = factory.user(home.id, platform_admin=True)
        outsider = factory.user(other.id)
        org = factory.org(home.id)
        client.put("/api/v1/settings/email", headers=_auth(client, admin.email), json=SMTP)

        _event(home.id, org.id, Severity.CRITICAL)
        with system_session() as db:
            notifications.dispatch_pending(db)
        assert [m["to"] for m in smtp.sent] == [admin.email]
        assert outsider.email not in {m["to"] for m in smtp.sent}

    def test_baseline_noise_is_excluded_unless_asked_for(self, client, factory, smtp):
        tenant = factory.tenant()
        org = factory.org(tenant.id)
        admin = factory.user(tenant.id, platform_admin=True)
        client.put("/api/v1/settings/email", headers=_auth(client, admin.email), json=SMTP)
        _event(tenant.id, org.id, Severity.CRITICAL, baseline=True)
        with system_session() as db:
            assert notifications.dispatch_pending(db)["personal_sent"] == 0
        assert smtp.sent == []

    def test_preferences_are_per_tenant(self, factory):
        tenant = factory.tenant()
        user = factory.user(tenant.id)
        with new_session(tenant.id) as db:
            db.add(UserAlertPreference(tenant_id=tenant.id, user_id=user.id, enabled=False,
                                       min_severity=Severity.CRITICAL))
            db.commit()
            row = db.scalar(select(UserAlertPreference).where(UserAlertPreference.user_id == user.id))
            assert row.tenant_id == tenant.id and row.enabled is False
        with new_session(uuid.uuid4()) as db:  # another tenant's session sees nothing (RLS)
            assert db.scalars(select(UserAlertPreference)).all() == []
