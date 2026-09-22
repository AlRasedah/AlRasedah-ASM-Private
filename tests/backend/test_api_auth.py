"""Authentication, session rotation, lockout, RBAC and API tokens over HTTP."""

from __future__ import annotations

import pyotp
import pytest
from fastapi.testclient import TestClient

PW = "Sup3r-Secret-Passw0rd!"


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


def login(client, email, password=PW):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    return r


def bearer(r):
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def csrf(client):
    return {"X-CSRF-Token": client.cookies.get("asm_csrf")}


def test_login_me_refresh_logout(client, factory):
    t = factory.tenant()
    u = factory.user(t.id, role="security_analyst")
    r = login(client, u.email.upper())  # case-insensitive email
    assert r.status_code == 200, r.text
    assert "asm_refresh" in r.headers.get("set-cookie", "") and "HttpOnly" in r.headers["set-cookie"]
    me = client.get("/api/v1/auth/me", headers=bearer(r)).json()
    assert me["user"]["email"] == u.email and me["role"] == "security_analyst"
    assert "scans:run" in me["permissions"] and "scope:write" not in me["permissions"]

    # refresh requires the CSRF double-submit header
    assert client.post("/api/v1/auth/refresh").status_code == 403
    r2 = client.post("/api/v1/auth/refresh", headers=csrf(client))
    assert r2.status_code == 200 and r2.json()["access_token"] != r.json()["access_token"]

    assert client.post("/api/v1/auth/logout", headers=bearer(r2)).status_code == 200
    # the session is revoked: its access token no longer works
    assert client.get("/api/v1/auth/me", headers=bearer(r2)).status_code == 401


def test_internal_domain_emails_are_accepted(client, factory):
    # Enterprise directories often use reserved/internal domains (corp.local, *.internal).
    t = factory.tenant()
    u = factory.user(t.id, email="admin@demo.local")
    assert login(client, "Admin@Demo.Local").status_code == 200
    h = bearer(login(client, u.email))
    r = client.post("/api/v1/users", headers=h, json={"email": "analyst@corp.internal", "role": "viewer"})
    assert r.status_code == 201 and r.json()["email"] == "analyst@corp.internal"
    assert login(client, "not-an-email").status_code == 422


def test_refresh_token_reuse_revokes_session(client, factory):
    t = factory.tenant()
    u = factory.user(t.id)
    login(client, u.email)
    old = client.cookies.get("asm_refresh")
    token = csrf(client)
    assert client.post("/api/v1/auth/refresh", headers=token).status_code == 200
    # Attacker replays the rotated (old) refresh token
    client.cookies.set("asm_refresh", old, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh", headers=csrf(client)).status_code == 401
    from app.db.session import system_session
    from app.models import AuditLog, UserSession

    with system_session() as db:
        s = db.query(UserSession).one()
        assert s.revoked_reason == "refresh_token_reuse"
        assert db.query(AuditLog).filter(AuditLog.action == "auth.refresh_token_reuse").count() == 1


def test_bad_password_lockout_and_generic_errors(client, factory):
    t = factory.tenant()
    u = factory.user(t.id)
    r = login(client, "nobody@example.org")
    assert r.status_code == 401 and r.json()["error"]["message"] == "Invalid email or password"
    for _ in range(5):
        assert login(client, u.email, "wrong-password-123").status_code == 401
    # locked: even the right password is refused, with the same generic message
    r = login(client, u.email)
    assert r.status_code in (401, 429)


def test_rate_limit_on_login(client, factory):
    t = factory.tenant()
    factory.user(t.id)
    codes = [login(client, "ratelimit@example.org", "x").status_code for _ in range(12)]
    assert 429 in codes


def test_rbac_viewer_cannot_write(client, factory):
    t = factory.tenant()
    org = factory.org(t.id)
    v = factory.user(t.id, role="viewer")
    h = bearer(login(client, v.email))
    assert client.get("/api/v1/organizations", headers=h).status_code == 200
    r = client.post("/api/v1/scopes", headers=h, json={"organization_id": str(org.id), "entry_type": "domain",
                                                        "value": "other.com"})
    assert r.status_code == 403
    assert client.post("/api/v1/organizations", headers=h, json={"name": "New"}).status_code == 403
    assert client.get("/api/v1/audit-logs", headers=h).status_code == 403


def test_cross_tenant_access_is_impossible(client, factory, tenant_db):
    a, b = factory.tenant("A"), factory.tenant("B")
    org_b = factory.org(b.id, domains=("bravo-corp.com",))
    ua = factory.user(a.id, role="tenant_admin")
    h = bearer(login(client, ua.email))
    assert client.get(f"/api/v1/organizations/{org_b.id}", headers=h).status_code == 404
    assert client.get("/api/v1/scopes", headers=h, params={"organization_id": str(org_b.id)}).json() == []
    from sqlalchemy import select

    from app.models import Asset

    with tenant_db(b.id) as db:
        asset_id = db.execute(select(Asset.id)).scalars().first()
    assert client.get(f"/api/v1/assets/{asset_id}", headers=h).status_code == 404
    assert client.patch(f"/api/v1/assets/{asset_id}", headers=h, json={"owner": "mallory"}).status_code == 404
    # cannot start scans against another tenant's organization
    profiles = client.get("/api/v1/scan-profiles", headers=h).json()
    r = client.post("/api/v1/scans", headers=h, json={"organization_id": str(org_b.id), "profile_id": profiles[0]["id"]})
    assert r.status_code == 404
    # cannot switch into a tenant without membership
    assert client.post("/api/v1/auth/switch-tenant", headers=h, json={"tenant_id": str(b.id)}).status_code == 403


def test_mfa_flow(client, factory):
    t = factory.tenant()
    u = factory.user(t.id)
    h = bearer(login(client, u.email))
    # Enrolling an authenticator requires re-entering the password.
    assert client.post("/api/v1/auth/mfa/setup", headers=h, json={"password": "wrong-password"}).status_code == 401
    setup = client.post("/api/v1/auth/mfa/setup", headers=h, json={"password": "Sup3r-Secret-Passw0rd!"}).json()
    totp = pyotp.TOTP(setup["secret"])
    assert client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": "000000"}).status_code == 422
    assert client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": totp.now()}).status_code == 200
    r = login(client, u.email)
    assert r.json()["mfa_required"] and not r.json()["access_token"]
    bad = client.post("/api/v1/auth/mfa/verify", json={"mfa_token": r.json()["mfa_token"], "code": "123456"})
    assert bad.status_code == 401
    ok = client.post("/api/v1/auth/mfa/verify", json={"mfa_token": r.json()["mfa_token"], "code": totp.now()})
    assert ok.status_code == 200 and ok.json()["access_token"]


def test_password_reset_flow(client, factory, monkeypatch):
    t = factory.tenant()
    u = factory.user(t.id)
    sent = {}

    def fake_send(email, token):
        sent["token"] = token

    monkeypatch.setattr("app.integrations.mailer.send_password_reset", fake_send)
    r1 = client.post("/api/v1/auth/password/forgot", json={"email": u.email})
    r2 = client.post("/api/v1/auth/password/forgot", json={"email": "ghost@example.org"})
    assert r1.status_code == r2.status_code == 202 and r1.json() == r2.json()  # no enumeration
    weak = client.post("/api/v1/auth/password/reset", json={"token": sent["token"], "new_password": "short"})
    assert weak.status_code == 422
    new = "An0ther-Very-Str0ng-Pass!"
    assert client.post("/api/v1/auth/password/reset", json={"token": sent["token"], "new_password": new}).status_code == 200
    assert client.post("/api/v1/auth/password/reset", json={"token": sent["token"], "new_password": new}).status_code == 422
    assert login(client, u.email, new).status_code == 200


def test_api_tokens(client, factory):
    t = factory.tenant()
    u = factory.user(t.id, role="security_analyst")
    h = bearer(login(client, u.email))
    assert client.post("/api/v1/auth/api-tokens", headers=h, json={"name": "siem", "role": "tenant_admin"}).status_code == 403
    r = client.post("/api/v1/auth/api-tokens", headers=h, json={"name": "siem", "role": "viewer"})
    assert r.status_code == 201
    raw = r.json()["token"]
    th = {"Authorization": f"Bearer {raw}"}
    assert client.get("/api/v1/organizations", headers=th).status_code == 200
    assert client.post("/api/v1/organizations", headers=th, json={"name": "x"}).status_code == 403  # viewer token
    tokens = client.get("/api/v1/auth/api-tokens", headers=h).json()
    assert tokens[0]["token_prefix"] == raw[:12] and "token" not in tokens[0]
    client.delete(f"/api/v1/auth/api-tokens/{tokens[0]['id']}", headers=h)
    assert client.get("/api/v1/organizations", headers=th).status_code == 401


class TestIdleTimeout:
    """A session must not last forever just because nobody signed out.

    The browser signs itself out on real inactivity, but an open tab polls on its own,
    so the server enforces the same window on `last_used_at`: a refresh presented after
    the idle period is refused and the session is revoked, not renewed.
    """

    @staticmethod
    def _age_session(email: str, minutes: int) -> None:
        from datetime import UTC, datetime, timedelta

        from sqlalchemy import select, update

        from app.db.session import system_session
        from app.models import User, UserSession

        with system_session() as db:
            uid = db.scalar(select(User.id).where(User.email == email))
            db.execute(update(UserSession).where(UserSession.user_id == uid)
                       .values(last_used_at=datetime.now(UTC) - timedelta(minutes=minutes)))
            db.commit()

    def test_a_refresh_after_the_idle_window_is_refused(self, client, factory, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "session_idle_ttl_minutes", 30)
        t = factory.tenant()
        u = factory.user(t.id)
        login(client, u.email)
        self._age_session(u.email, 31)

        assert client.post("/api/v1/auth/refresh", headers=csrf(client)).status_code == 401
        # and the session is gone, so the same cookie cannot be tried again
        assert client.post("/api/v1/auth/refresh", headers=csrf(client)).status_code == 401

        from sqlalchemy import select

        from app.db.session import system_session
        from app.models import User, UserSession

        with system_session() as db:
            uid = db.scalar(select(User.id).where(User.email == u.email))
            session = db.execute(select(UserSession).where(UserSession.user_id == uid)).scalar_one()
            assert session.revoked_at is not None and session.revoked_reason == "idle"

    def test_a_session_still_in_use_is_renewed(self, client, factory, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "session_idle_ttl_minutes", 30)
        t = factory.tenant()
        u = factory.user(t.id)
        login(client, u.email)
        self._age_session(u.email, 29)
        assert client.post("/api/v1/auth/refresh", headers=csrf(client)).status_code == 200

    def test_the_timeout_can_be_switched_off(self, client, factory, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "session_idle_ttl_minutes", 0)
        t = factory.tenant()
        u = factory.user(t.id)
        login(client, u.email)
        self._age_session(u.email, 60 * 24)
        assert client.post("/api/v1/auth/refresh", headers=csrf(client)).status_code == 200

    def test_the_browser_is_told_the_window(self, client, factory, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "session_idle_ttl_minutes", 30)
        t = factory.tenant()
        u = factory.user(t.id)
        r = login(client, u.email)
        assert client.get("/api/v1/auth/me", headers=bearer(r)).json()["session_idle_minutes"] == 30

    def test_api_tokens_never_idle_out(self, client, factory, monkeypatch):
        from app.core.config import get_settings

        monkeypatch.setattr(get_settings(), "session_idle_ttl_minutes", 30)
        t = factory.tenant()
        u = factory.user(t.id)
        h = bearer(login(client, u.email))
        raw = client.post("/api/v1/auth/api-tokens", headers=h,
                          json={"name": "siem", "role": "viewer"}).json()["token"]
        me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"}).json()
        assert me["session_idle_minutes"] == 0, "an unattended integration has no one to be idle"


def test_security_headers_and_errors(client):
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    for h in ("X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "X-Request-ID"):
        assert h in r.headers
    r = client.get("/api/v1/assets")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    r = client.get("/api/v1/assets", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401
