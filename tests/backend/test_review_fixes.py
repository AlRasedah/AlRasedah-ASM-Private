# ruff: noqa: F811, S106  (pytest fixtures imported by name; dummy MFA secret)
"""Regressions for the 2026-09-18 software test report and clickability audit."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, text, update

from .test_api_workflows import PW, ctx, run_scan, setup_org  # noqa: F401  (ctx is a fixture)

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _login(c, email, password=PW):
    return c.post("/api/v1/auth/login", json={"email": email, "password": password})


def _h(c, user):
    return {"Authorization": f"Bearer {_login(c, user.email).json()['access_token']}"}


# ------------------------------------------------------------------ audit chain
def test_audit_chain_seq_is_gapless_per_chain_even_when_ids_are_not(factory):
    from app.db.session import system_session
    from app.models import AuditLog
    from app.services import audit

    t1, t2 = factory.tenant("One"), factory.tenant("Two")
    with system_session() as db:
        for i in range(3):  # interleave three chains so the shared id sequence skips for each of them
            audit.record(db, "test.one", tenant_id=t1.id, actor="a", new={"i": i})
            audit.record(db, "test.platform", tenant_id=None, actor="a", new={"i": i})
            audit.record(db, "test.two", tenant_id=t2.id, actor="a", new={"i": i})
        db.commit()
        for tid in (t1.id, t2.id, None):
            rows = db.execute(select(AuditLog.id, AuditLog.chain_seq)
                              .where(AuditLog.tenant_id.is_(None) if tid is None else AuditLog.tenant_id == tid)
                              .order_by(AuditLog.id)).all()
            assert [s for _, s in rows] == list(range(1, len(rows) + 1))
            report = audit.check_chain(db, tid)
            assert report.intact and report.entries == len(rows)
        ids = [i for (i,) in db.execute(select(AuditLog.id).where(AuditLog.tenant_id == t1.id).order_by(AuditLog.id))]
        assert any(b - a > 1 for a, b in zip(ids, ids[1:], strict=False))  # ids have gaps, seq does not


def test_audit_verification_fails_on_a_sequence_gap(factory):
    """An entry missing from the middle must fail verification even if the hash links were re-forged."""
    from app.db.session import system_session
    from app.models import AuditLog
    from app.services import audit

    t = factory.tenant("Gap")
    with system_session() as db:
        audit.record(db, "test.a", tenant_id=t.id, actor="a")
        last = audit.record(db, "test.b", tenant_id=t.id, actor="a")
        forged = AuditLog(tenant_id=t.id, chain_seq=last.chain_seq + 2, action="test.forged", actor="x",
                          success=True, created_at=datetime.now(UTC), prev_hash=last.hash)
        forged.hash = audit._digest(last.hash, audit._row_payload(forged))
        db.add(forged)
        db.commit()
        report = audit.check_chain(db, t.id)
        assert not report.intact
        assert report.first_bad_seq == last.chain_seq + 2 and "sequence gap" in report.reason


def test_audit_api_shows_chain_position_and_verification(ctx):
    c, admin, *_ = ctx
    items = c.get("/api/v1/audit-logs", headers=admin).json()["items"]
    assert items and all("chain_seq" in a for a in items)
    v = c.get("/api/v1/audit-logs/verify", headers=admin).json()
    assert v["intact"] is True and v["entries"] >= len(items) and v["reason"] is None


def test_migration_backfills_chain_seq(database):
    """0002 numbers rows written before it existed, per chain, in id order."""
    from alembic.config import Config

    from alembic import command
    from app.db.session import system_session

    root = __import__("pathlib").Path(__file__).resolve().parents[2]
    cfg = Config(str(root / "backend" / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "backend" / "alembic"))
    command.downgrade(cfg, "0001")
    try:
        with system_session() as db:
            for n in range(3):
                db.execute(text("INSERT INTO audit_logs (tenant_id, action, success, created_at, hash) "
                                "VALUES (NULL, :a, true, now(), 'x')"), {"a": f"legacy.{n}"})
            db.commit()
    finally:
        command.upgrade(cfg, "head")
    with system_session() as db:
        seqs = [s for (s,) in db.execute(text(
            "SELECT chain_seq FROM audit_logs WHERE tenant_id IS NULL ORDER BY id"))]
        assert seqs == list(range(1, len(seqs) + 1)) and len(seqs) >= 3
        legacy = db.execute(text("SELECT chain_seq FROM audit_logs WHERE action LIKE 'legacy.%' ORDER BY id")).all()
        assert [s for (s,) in legacy] == seqs[-3:]


# ------------------------------------------------------------------ tenant suspension
def test_platform_admin_cannot_suspend_the_tenant_they_are_signed_in_to(ctx, factory):
    c, _admin, _analyst, t, *_ = ctx
    padmin = factory.user(t.id, platform_admin=True, password=PW)
    other = factory.tenant("Other")
    h = _h(c, padmin)
    r = c.patch(f"/api/v1/tenants/{t.id}", headers=h, json={"status": "suspended"})
    assert r.status_code == 422 and "signed in to this tenant" in r.json()["error"]["message"]
    assert c.patch(f"/api/v1/tenants/{other.id}", headers=h, json={"status": "suspended"}).status_code == 200


def test_sign_in_to_a_suspended_tenant_says_so_only_after_a_correct_password(ctx, factory):
    from app.db.session import system_session
    from app.models import Tenant
    from app.models.enums import TenantStatus

    c, *_ = ctx
    t2 = factory.tenant("Paused")
    member = factory.user(t2.id, password=PW)
    with system_session() as db:
        db.execute(update(Tenant).where(Tenant.id == t2.id).values(status=TenantStatus.SUSPENDED))
        db.commit()
    r = _login(c, member.email)
    assert r.status_code == 403 and r.json()["error"]["code"] == "tenant_suspended"
    bad = _login(c, member.email, "wrong-password-123")
    assert bad.status_code == 401 and bad.json()["error"]["message"] == "Invalid email or password"


def test_schedules_of_suspended_tenants_do_not_fire(ctx):
    from app.db.session import system_session
    from app.models import ScanSchedule, Tenant
    from app.models.enums import TenantStatus
    from app.services.maintenance import due_schedules

    c, admin, _analyst, t, *_ = ctx
    org = setup_org(c, admin)
    profile = c.get("/api/v1/scan-profiles", headers=admin).json()[0]
    r = c.post("/api/v1/schedules", headers=admin, json={"organization_id": org["id"], "profile_id": profile["id"],
                                                          "name": "Nightly", "cron": "0 2 * * *"})
    assert r.status_code == 201, r.text
    sid = uuid.UUID(r.json()["id"])
    with system_session() as db:
        db.execute(update(ScanSchedule).where(ScanSchedule.id == sid)
                   .values(next_run_at=datetime.now(UTC) - timedelta(minutes=1)))
        db.commit()
    assert (t.id, sid) in due_schedules()
    with system_session() as db:
        db.execute(update(Tenant).where(Tenant.id == t.id).values(status=TenantStatus.SUSPENDED))
        db.commit()
    assert (t.id, sid) not in due_schedules()


# ------------------------------------------------------------------ users
def _enable_mfa(user_id):
    from app.db.session import system_session
    from app.models import User

    with system_session() as db:
        db.execute(update(User).where(User.id == user_id).values(mfa_enabled=True, mfa_secret_encrypted="x"))
        db.commit()


def test_admin_can_reset_a_members_mfa(ctx):
    from app.db.session import system_session
    from app.models import User

    c, admin, analyst_h, _t, admin_u, analyst = ctx
    _enable_mfa(analyst.id)
    r = c.post(f"/api/v1/users/{analyst.id}/mfa/reset", headers=admin)
    assert r.status_code == 200, r.text
    with system_session() as db:
        u = db.get(User, analyst.id)
        assert u.mfa_enabled is False and u.mfa_secret_encrypted is None
    assert c.get("/api/v1/auth/me", headers=analyst_h).status_code == 401  # signed out
    assert c.post(f"/api/v1/users/{admin_u.id}/mfa/reset", headers=admin).status_code == 422  # not on yourself


def test_tenant_admin_cannot_reset_mfa_of_an_account_shared_with_another_tenant(ctx, factory):
    from app.db.session import system_session
    from app.models import TenantMembership
    from app.models.enums import Role

    c, admin, _analyst_h, _t, _admin_u, analyst = ctx
    other = factory.tenant("Elsewhere")
    with system_session() as db:
        db.add(TenantMembership(tenant_id=other.id, user_id=analyst.id, role=Role.VIEWER))
        db.commit()
    _enable_mfa(analyst.id)
    r = c.post(f"/api/v1/users/{analyst.id}/mfa/reset", headers=admin)
    assert r.status_code == 403 and "platform administrator" in r.json()["error"]["message"]


def test_validation_errors_are_plain_language(ctx):
    c, admin, *_ = ctx
    r = c.post("/api/v1/users", headers=admin, json={"email": "not-an-email", "role": "viewer"})
    assert r.status_code == 422
    body = r.text
    assert "^[" not in body and "should match pattern" not in body  # no regex leaks to the user
    detail = r.json()["error"]["details"][0]
    assert detail["field"] == "email" and detail["msg"] == "Enter a valid email address"


# ------------------------------------------------------------------ findings and scans
@pytest.fixture
def scanned(ctx):
    c, admin, *_ = ctx
    org = setup_org(c, admin)
    scan = run_scan(c, admin, org)
    return ctx, scan


def test_assignment_activity_shows_a_name_not_an_id(scanned):
    (c, admin, _analyst_h, _t, _admin_u, analyst), _ = scanned
    finding = c.get("/api/v1/findings", headers=admin).json()["items"][0]
    assert c.patch(f"/api/v1/findings/{finding['id']}", headers=admin,
                   json={"assigned_to": str(analyst.id)}).status_code == 200
    act = [a for a in c.get(f"/api/v1/findings/{finding['id']}/activity", headers=admin).json()
           if a["activity_type"] == "assignment"]
    assert act and act[0]["summary"] == "Assigned to Test User"
    assert str(analyst.id) not in act[0]["summary"]


def test_findings_sort_by_severity_rank_and_new_columns(scanned):
    (c, admin, *_), _ = scanned
    items = c.get("/api/v1/findings", headers=admin,
                  params={"sort": "severity", "order": "desc", "open_only": "false"}).json()["items"]
    ranks = [SEV_RANK[f["severity"]] for f in items]
    assert ranks == sorted(ranks, reverse=True) and len(set(ranks)) > 1
    for key in ("asset", "status", "detection"):
        assert c.get("/api/v1/findings", headers=admin, params={"sort": key}).status_code == 200
    for key in ("status", "owner"):
        assert c.get("/api/v1/assets", headers=admin, params={"sort": key}).status_code == 200


def test_scan_stages_report_their_time_limit(scanned):
    from app.core.config import get_settings
    from app.scans.profiles import stage_time_limit

    (c, admin, *_), scan = scanned
    stages = c.get(f"/api/v1/scans/{scan['id']}", headers=admin).json()["stages"]
    assert stages and all(isinstance(s["time_limit_seconds"], int) for s in stages)
    platform = get_settings().stage_timeout_seconds
    assert stage_time_limit("amass", {"timeout_minutes": 90}, platform) == 90 * 60 + 300
    assert stage_time_limit("naabu", {}, platform) == platform


# ------------------------------------------------------------------ product rename (Exteriq ASM)
class _Txt:
    def __init__(self, value: str) -> None:
        self.strings = [value.encode()]


class _Resolver:
    """Answers TXT queries from a dict; anything else is NXDOMAIN."""

    def __init__(self, records: dict[str, str]) -> None:
        self.records, self.lifetime = records, 0

    def resolve(self, name, _rtype):
        import dns.resolver

        if name not in self.records:
            raise dns.resolver.NXDOMAIN()
        return [_Txt(self.records[name])]


@pytest.mark.parametrize("prefix,value", [("_exteriq-asm", "exteriq-asm-verification="),
                                          ("_alrasedah-asm", "alrasedah-asm-verification=")])
def test_ownership_verification_accepts_current_and_pre_rename_records(factory, tenant_db, prefix, value):
    from app.models import ScopeEntry
    from app.models.enums import VerificationStatus
    from app.scope.service import verification_instructions, verify_entry

    t = factory.tenant("Rename")
    factory.org(t.id, domains=("rename-corp.com",))
    with tenant_db(t.id) as db:
        entry = db.execute(select(ScopeEntry).where(ScopeEntry.value == "rename-corp.com")).scalar_one()
        assert verification_instructions(entry)["name"] == "_exteriq-asm.rename-corp.com"
        resolver = _Resolver({f"{prefix}.rename-corp.com": f"{value}{entry.verification_token}"})
        assert verify_entry(db, entry.id, resolver).verification_status == VerificationStatus.VERIFIED
