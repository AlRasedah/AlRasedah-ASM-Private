"""Regression tests for the 2026-09-19 platform audit (platform side).

The audit's reproductions asserted the defective behaviour; these assert the
fixed behaviour for the same scenarios (A01, A02, A04–A09, A11).
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime
from unittest.mock import patch

import pyotp
import pytest
from asm_sensors.adapters.nuclei import NucleiAdapter
from asm_sensors.jobs import SensorJob, pool_key, seal_result
from asm_sensors.observations import SensorResult
from asm_sensors.targets import Target, TargetKind
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core import crypto
from app.core.config import Settings, get_settings
from app.db.session import new_session, system_session
from app.models import Finding, Organization, Plan, Scan, ScanProfile, ScanStage, ScopeEntry, Tenant, User
from app.models.enums import (
    OPEN_FINDING_STATES,
    ScanStatus,
    ScopeEntryType,
    StageStatus,
    TenantStatus,
    VerificationStatus,
)
from app.scans import orchestrator
from app.scope.checker import ScopeChecker, ScopeRule
from app.scope.service import add_entry, load_checker
from app.tenants.settings import tenant_settings
from app.workers import tasks
from app.workers.results import receive_result

from .sensors_fake import FIXTURES, FakeSensors

PW = "Sup3r-Secret-Passw0rd!"


def _profile(db, slug="standard-asm"):
    return db.scalar(select(ScanProfile.id).where(ScanProfile.slug == slug, ScanProfile.tenant_id.is_(None)))


def _make_scan(factory, tenant, org_name, domains=("example.com",)):
    org = factory.org(tenant.id, name=org_name, domains=domains)
    with new_session(tenant.id) as db:
        scan = orchestrator.create_scan(db, tenant_id=tenant.id, organization_id=org.id, profile_id=_profile(db))
        db.commit()
        return scan.id


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


def _login(client, email):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ------------------------------------------------------------------ A02
class TestNonPublicDestinations:
    def test_derived_private_addresses_are_never_actively_scanned(self):
        checker = ScopeChecker([ScopeRule(None, ScopeEntryType.DOMAIN, "example.com")], allow_non_public=False)
        for value in ("127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.1.1", "::1", "fd00::1"):
            d = checker.check(Target(kind=TargetKind.IP, value=value), active=True, derived_from={value: ["example.com"]})
            assert not d.allowed, value
            # Still recorded as derived inventory (an internal address in public DNS is itself worth knowing).
            assert checker.check(Target(kind=TargetKind.IP, value=value), active=False,
                                 derived_from={value: ["example.com"]}).allowed
        public = checker.check(Target(kind=TargetKind.IP, value="93.184.216.34"), active=True,
                               derived_from={"93.184.216.34": ["example.com"]})
        assert public.allowed

    def test_follows_the_deployment_setting_by_default(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "allow_non_public_scope", False)
        checker = ScopeChecker([ScopeRule(None, ScopeEntryType.DOMAIN, "example.com")])
        assert not checker.check(Target(kind=TargetKind.IP, value="10.0.0.1"), active=True,
                                 derived_from={"10.0.0.1": ["example.com"]}).allowed

    def test_explicit_private_entries_and_urls_need_the_lab_setting(self):
        rules = [ScopeRule(None, ScopeEntryType.CIDR, "10.0.0.0/24"), ScopeRule(None, ScopeEntryType.DOMAIN, "example.com")]
        strict, lab = ScopeChecker(rules, allow_non_public=False), ScopeChecker(rules, allow_non_public=True)
        for t in (Target(kind=TargetKind.IP, value="10.0.0.5"), Target(kind=TargetKind.CIDR, value="10.0.0.0/28"),
                  Target(kind=TargetKind.URL, value="http://10.0.0.5:8080/")):
            assert not strict.check(t, active=True).allowed
            assert lab.check(t, active=True).allowed

    def test_jobs_carry_excluded_ranges_to_the_sensor(self, factory):
        t = factory.tenant()
        org = factory.org(t.id, domains=("example.com",))
        with new_session(t.id) as db:
            add_entry(db, tenant_id=t.id, organization_id=org.id, entry_type=ScopeEntryType.CIDR,
                      value="203.0.113.0/24", is_exclusion=True)
            db.commit()
            scan = orchestrator.create_scan(db, tenant_id=t.id, organization_id=org.id, profile_id=_profile(db))
            assert orchestrator.try_start(db, scan)
            _stage, job = orchestrator.prepare_next_stage(db, scan)
            assert job.excluded_networks == ["203.0.113.0/24"]


# ------------------------------------------------------------------ A05
class TestOwnershipVerification:
    def test_enabling_verification_does_not_grandfather_existing_domains(self, factory, tenant_db):
        tenant = factory.tenant()
        org = factory.org(tenant.id)  # example.com added while verification was off
        with system_session() as db:
            db.get(Tenant, tenant.id).settings = {"scanning": {"require_scope_verification": True}}
            db.commit()
        with tenant_db(tenant.id) as db:
            entry = db.scalar(select(ScopeEntry).where(ScopeEntry.organization_id == org.id))
            assert entry.verification_status == VerificationStatus.NOT_REQUIRED
            checker = load_checker(db, db.get(Organization, org.id))
            target = Target(kind=TargetKind.HOSTNAME, value="example.com")
            assert not checker.check(target, active=True).allowed
            assert checker.check(target, active=False).allowed  # passive discovery still works
            entry.verification_status = VerificationStatus.VERIFIED
            db.flush()
            assert load_checker(db, db.get(Organization, org.id)).check(target, active=True).allowed

    def test_settings_change_reclassifies_scope(self, client, factory, tenant_db):
        tenant = factory.tenant()
        admin = factory.user(tenant.id)
        org = factory.org(tenant.id, ips=("93.184.216.34",))
        h = _login(client, admin.email)
        r = client.put("/api/v1/settings", headers=h, json={"scanning": {"require_scope_verification": True}})
        assert r.status_code == 200, r.text
        with tenant_db(tenant.id) as db:
            statuses = {e.value: e.verification_status for e in db.scalars(
                select(ScopeEntry).where(ScopeEntry.organization_id == org.id))}
        assert statuses == {"example.com": VerificationStatus.UNVERIFIED, "93.184.216.34": VerificationStatus.UNVERIFIED}

    def test_ip_scope_needs_platform_admin_approval(self, client, factory, tenant_db):
        tenant = factory.tenant()
        with system_session() as db:
            db.get(Tenant, tenant.id).settings = {"scanning": {"require_scope_verification": True}}
            db.commit()
        admin = factory.user(tenant.id)
        platform = factory.user(tenant.id, platform_admin=True)
        org = factory.org(tenant.id, domains=(), ips=("93.184.216.34",))
        target = Target(kind=TargetKind.IP, value="93.184.216.34")
        with tenant_db(tenant.id) as db:
            entry = db.scalar(select(ScopeEntry).where(ScopeEntry.organization_id == org.id))
            assert entry.verification_status == VerificationStatus.UNVERIFIED
            assert not load_checker(db, db.get(Organization, org.id)).check(target, active=True).allowed
        assert client.post(f"/api/v1/scopes/{entry.id}/approve", headers=_login(client, admin.email)).status_code == 403
        r = client.post(f"/api/v1/scopes/{entry.id}/approve", headers=_login(client, platform.email))
        assert r.status_code == 200 and r.json()["verification_status"] == "verified"
        with tenant_db(tenant.id) as db:
            assert load_checker(db, db.get(Organization, org.id)).check(target, active=True).allowed

    def test_platform_floor_cannot_be_weakened_by_a_tenant(self, monkeypatch):
        monkeypatch.setattr(get_settings(), "require_scope_verification", True)
        tenant = Tenant(name="x", slug="x", settings={"scanning": {"require_scope_verification": False}})
        assert tenant_settings(tenant)["scanning"]["require_scope_verification"] is True


# ------------------------------------------------------------------ A06
class TestConcurrencyLimit:
    def test_parallel_starts_respect_a_limit_of_one(self, factory):
        tenant = factory.tenant()
        first = _make_scan(factory, tenant, "First")
        second = _make_scan(factory, tenant, "Second")
        with system_session() as db:
            plan = Plan(code=f"single-{uuid.uuid4().hex[:6]}", name="Single", max_concurrent_scans=1)
            db.add(plan)
            db.flush()
            db.get(Tenant, tenant.id).plan_id = plan.id
            db.commit()

        results: dict[str, bool] = {}
        first_reserved = threading.Event()

        def start(name, sid, hold):
            with new_session(tenant.id) as db:
                if name == "second":
                    first_reserved.wait(5)
                results[name] = orchestrator.try_start(db, db.get(Scan, sid))
                if name == "first":
                    first_reserved.set()
                    time.sleep(hold)  # keep the reservation uncommitted for a while
                db.commit()

        threads = [threading.Thread(target=start, args=("first", first, 0.5)),
                   threading.Thread(target=start, args=("second", second, 0))]
        for th in threads:
            th.start()
        for th in threads:
            th.join(15)
        assert results == {"first": True, "second": False}
        with new_session(tenant.id) as db:
            statuses = {s.id: s.status for s in db.scalars(select(Scan))}
        assert statuses == {first: ScanStatus.RUNNING, second: ScanStatus.QUEUED}

    def test_redelivered_start_is_a_no_op(self, factory):
        tenant = factory.tenant()
        sid = _make_scan(factory, tenant, "Once")
        with new_session(tenant.id) as db:
            assert orchestrator.try_start(db, db.get(Scan, sid))
            db.commit()
        with new_session(tenant.id) as db:
            assert not orchestrator.try_start(db, db.get(Scan, sid))


# ------------------------------------------------------------------ A07 / A01
def _result_for(job: SensorJob, **kw) -> SensorResult:
    now = datetime.now(UTC)
    return SensorResult(adapter=kw.pop("adapter", job.adapter), status="completed", target_count=len(job.targets),
                        started_at=now, finished_at=now, **kw)


def _dispatch_first_stage(factory, on_publish=None):
    """Start a scan and run advance_scan with a stubbed broker; returns (tenant, scan_id, published job)."""
    tenant = factory.tenant()
    sid = _make_scan(factory, tenant, "Pipeline")
    with new_session(tenant.id) as db:
        assert orchestrator.try_start(db, db.get(Scan, sid))
        db.commit()
    published: list[tuple[SensorJob, str]] = []

    def publish(job, pool):
        published.append((job, pool))
        if on_publish:
            on_publish(job, pool)

    with patch.object(tasks, "publish_job", publish), patch.object(tasks.advance_scan, "delay"), \
            patch.object(tasks.dispatch_notifications, "delay"), patch.object(tasks.dispatch_queued_scans, "delay"):
        tasks.advance_scan.run(str(sid))
    assert len(published) == 1
    return tenant, sid, published[0]


class TestDispatchAndResults:
    def test_immediate_result_is_not_lost(self, factory):
        accepted = []

        def finish_immediately(job, pool):
            # A sensor worker answers before advance_scan has returned.
            env = seal_result(job, _result_for(job), pool, crypto.pool_transport_key(pool))
            accepted.append(receive_result(env))

        tenant, sid, (job, pool) = _dispatch_first_stage(factory, finish_immediately)
        assert accepted == [sid]
        with new_session(tenant.id) as db:
            stage = db.get(ScanStage, uuid.UUID(job.stage_id))
            assert stage.status == StageStatus.COMPLETED and stage.finished_at is not None
            assert stage.task_id == job.job_id and stage.worker_pool == pool == "default"

    def test_dispatched_stage_is_marked_and_duplicate_advance_is_idempotent(self, factory):
        tenant, sid, (job, _pool) = _dispatch_first_stage(factory)
        with new_session(tenant.id) as db:
            stage = db.get(ScanStage, uuid.UUID(job.stage_id))
            assert stage.status == StageStatus.RUNNING and stage.dispatched_at is not None
        published = []
        with patch.object(tasks, "publish_job", lambda j, p: published.append(j)):
            tasks.advance_scan.run(str(sid))  # a duplicate delivery
        assert published == []

    def test_publish_failure_fails_the_stage_instead_of_stranding_it(self, factory):
        def broker_down(job, pool):
            raise ConnectionError("broker unavailable")

        tenant = factory.tenant()
        sid = _make_scan(factory, tenant, "Broker down")
        with new_session(tenant.id) as db:
            assert orchestrator.try_start(db, db.get(Scan, sid))
            db.commit()
        with patch.object(tasks, "publish_job", broker_down), patch.object(tasks.advance_scan, "delay") as again:
            tasks.advance_scan.run(str(sid))
        again.assert_called_once()
        with new_session(tenant.id) as db:
            stage = db.scalars(select(ScanStage).where(ScanStage.scan_id == sid, ScanStage.position == 0)).one()
            assert stage.status in (StageStatus.FAILED, StageStatus.SKIPPED) and "dispatched" in stage.error

    def test_results_that_do_not_match_the_dispatch_are_rejected(self, factory):
        tenant, sid, (job, pool) = _dispatch_first_stage(factory)
        good = _result_for(job)
        master = crypto.transport_key()
        # 1. Another pool's worker cannot answer this pool's job (it can only sign as itself).
        other = seal_result(job, good, "rogue", pool_key(master, "rogue"))
        assert receive_result(other) is None
        # 2. A forged pool claim fails authentication.
        forged = dict(other, pool="default")
        assert receive_result(forged) is None
        # 3. A genuine pool worker cannot answer a job it was not given.
        wrong_job = job.model_copy(update={"job_id": uuid.uuid4().hex})
        assert receive_result(seal_result(wrong_job, good, pool, crypto.pool_transport_key(pool))) is None
        # 4. ... nor with another engine's output.
        assert receive_result(seal_result(job, _result_for(job, adapter="naabu"), pool,
                                          crypto.pool_transport_key(pool))) is None
        with new_session(tenant.id) as db:
            assert db.get(ScanStage, uuid.UUID(job.stage_id)).status == StageStatus.RUNNING
        # The genuine result is accepted once; a replay is stale.
        env = seal_result(job, good, pool, crypto.pool_transport_key(pool))
        assert receive_result(env) == sid
        assert receive_result(env) is None

    def test_watchdog_recovers_undispatched_stages_and_stranded_scans(self, factory):
        from datetime import timedelta

        tenant = factory.tenant()
        stranded = _make_scan(factory, tenant, "Stranded")
        with new_session(tenant.id) as db:
            assert orchestrator.try_start(db, db.get(Scan, stranded))
            db.commit()
        undispatched_scan = _make_scan(factory, tenant, "Undispatched")
        with new_session(tenant.id) as db:
            scan = db.get(Scan, undispatched_scan)
            assert orchestrator.try_start(db, scan)
            stage, _job = orchestrator.prepare_next_stage(db, scan)
            stage.started_at = datetime.now(UTC) - timedelta(minutes=30)  # crashed before publishing
            db.commit()
            stage_id = stage.id
        with system_session() as db:  # time passes
            db.get(Scan, stranded).updated_at = datetime.now(UTC) - timedelta(minutes=30)
            db.commit()
        with patch.object(tasks.stage_failed, "delay") as failed, patch.object(tasks.advance_scan, "delay") as adv:
            tasks.watchdog.run()
        failed.assert_called_once_with(str(undispatched_scan), str(stage_id), "The sensor job was never dispatched")
        adv.assert_called_once_with(str(stranded))


# ------------------------------------------------------------------ A04
class TestIncompleteRunsDoNotResolveFindings:
    def _run(self, tenant_id, org_id):
        with new_session(tenant_id) as db:
            scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=_profile(db))
            db.commit()
            orchestrator.run_inline(db, scan.id)

    def _fortinet(self, tenant_id):
        with new_session(tenant_id) as db:
            return db.scalar(select(Finding).where(Finding.title.like("Fortinet%"))).status

    @pytest.mark.parametrize("incomplete", [True, False])
    def test_partial_vulnerability_runs_keep_findings_open(self, factory, monkeypatch, incomplete):
        tenant = factory.tenant()
        org = factory.org(tenant.id, domains=("example.com",))
        fake = FakeSensors(monkeypatch)
        self._run(tenant.id, org.id)
        assert self._fortinet(tenant.id) in OPEN_FINDING_STATES

        # Later runs no longer report the Fortinet finding...
        fake.set("nuclei", (FIXTURES / "nuclei.jsonl").read_bytes().splitlines()[0] + b"\n")  # swagger only
        if incomplete:  # ...because the run did not finish (e.g. API errors / truncated output)
            fake_execute = NucleiAdapter.execute

            async def failing(self, targets, config, ctx):
                raw = await fake_execute(self, targets, config, ctx)
                raw.errors.append("simulated: rate limited by target, 40% of templates not run")
                return raw

            monkeypatch.setattr(NucleiAdapter, "execute", failing)
        for _ in range(3):  # more than the finding inactivity threshold
            self._run(tenant.id, org.id)
        status = self._fortinet(tenant.id)
        if incomplete:
            assert status in OPEN_FINDING_STATES, "an incomplete run resolved a finding it may simply have missed"
        else:
            assert status not in OPEN_FINDING_STATES  # control: complete runs do resolve it


# ------------------------------------------------------------------ A08
class TestAccountSecurityNeedsInteractiveSession:
    def test_viewer_api_token_cannot_touch_account_security(self, client, factory):
        tenant = factory.tenant()
        user = factory.user(tenant.id)
        h = _login(client, user.email)
        r = client.post("/api/v1/auth/api-tokens", headers=h, json={"name": "audit-viewer", "role": "viewer"})
        assert r.status_code == 201, r.text
        token_id, token = r.json()["id"], {"Authorization": "Bearer " + r.json()["token"]}
        assert client.get("/api/v1/auth/me", headers=token).status_code == 200  # the token works for reads
        assert client.post("/api/v1/auth/mfa/setup", headers=token, json={"password": PW}).status_code == 403
        assert client.post("/api/v1/auth/mfa/enable", headers=token, json={"code": "123456"}).status_code == 403
        assert client.post("/api/v1/auth/mfa/disable", headers=token,
                           json={"password": PW, "code": "123456"}).status_code == 403
        assert client.post("/api/v1/auth/password/change", headers=token,
                           json={"current_password": PW, "new_password": "An0ther-Passw0rd!!"}).status_code == 403
        assert client.delete(f"/api/v1/auth/api-tokens/{token_id}", headers=token).status_code == 403
        with system_session() as db:
            assert not db.get(User, user.id).mfa_enabled
        # The owner, signed in, still can (after re-entering the password).
        setup = client.post("/api/v1/auth/mfa/setup", headers=h, json={"password": PW})
        assert setup.status_code == 200
        code = pyotp.TOTP(setup.json()["secret"]).now()
        assert client.post("/api/v1/auth/mfa/enable", headers=h, json={"code": code}).status_code == 200


# ------------------------------------------------------------------ A09
class TestSuspendedTenants:
    def test_queued_scan_of_suspended_tenant_does_not_start(self, factory):
        tenant = factory.tenant()
        sid = _make_scan(factory, tenant, "Suspended")
        with system_session() as db:
            db.get(Tenant, tenant.id).status = TenantStatus.SUSPENDED
            db.commit()
        with new_session(tenant.id) as db:
            scan = db.get(Scan, sid)
            assert not orchestrator.try_start(db, scan)
            db.commit()
            assert scan.status == ScanStatus.CANCELLED and "suspended" in scan.error

    def test_running_scan_stops_at_the_next_stage(self, factory):
        tenant = factory.tenant()
        sid = _make_scan(factory, tenant, "Draining")
        with new_session(tenant.id) as db:
            assert orchestrator.try_start(db, db.get(Scan, sid))
            db.commit()
        with system_session() as db:
            db.get(Tenant, tenant.id).status = TenantStatus.SUSPENDED
            db.commit()
        with new_session(tenant.id) as db:
            scan = db.get(Scan, sid)
            assert orchestrator.prepare_next_stage(db, scan) is None
            db.commit()
            assert scan.status == ScanStatus.CANCELLED
            assert all(s.status == StageStatus.CANCELLED for s in scan.stages)

    def test_suspending_through_the_api_cancels_active_scans(self, client, factory):
        home, other = factory.tenant(), factory.tenant()
        platform = factory.user(home.id, platform_admin=True)
        queued = _make_scan(factory, other, "Queued")
        running = _make_scan(factory, other, "Running", domains=("example.org",))
        with new_session(other.id) as db:
            assert orchestrator.try_start(db, db.get(Scan, running))
            db.commit()
        with patch("app.workers.dispatch.revoke") as revoke:
            r = client.patch(f"/api/v1/tenants/{other.id}", headers=_login(client, platform.email),
                             json={"status": "suspended"})
        assert r.status_code == 200, r.text
        revoke.assert_called_once()
        with new_session(other.id) as db:
            assert {s.id: s.status for s in db.scalars(select(Scan))} == {queued: ScanStatus.CANCELLED,
                                                                           running: ScanStatus.CANCELLED}


# ------------------------------------------------------------------ A11
def test_visibility_timeout_must_cover_the_longest_job():
    with pytest.raises(ValueError, match="VISIBILITY_TIMEOUT"):
        Settings(stage_timeout_seconds=4 * 3600, broker_visibility_timeout=3600)
    assert Settings(stage_timeout_seconds=4 * 3600).broker_visibility_timeout > 4 * 3600 + 300


def test_all_apps_share_the_visibility_timeout():
    from asm_sensors import worker as sensor_worker

    from app.workers.celery_app import celery_app
    from app.workers.results import results_app

    core = celery_app.conf.broker_transport_options["visibility_timeout"]
    assert results_app.conf.broker_transport_options["visibility_timeout"] == core
    assert sensor_worker.app.conf.broker_transport_options["visibility_timeout"] == core
    # Sensor workers never write platform queues or keep results in a backend.
    assert sensor_worker.app.conf.task_ignore_result
    assert not celery_app.conf.worker_enable_remote_control and not results_app.conf.worker_enable_remote_control
    # The result consumer runs result submission and nothing else — no platform task, and
    # no Celery built-in such as celery.group that would publish message-supplied signatures.
    assert set(results_app.tasks) == {"asm.results.submit"}
    assert not any(name.startswith("asm.core.") for name in sensor_worker.app.tasks)
    assert "asm.results.submit" not in celery_app.tasks and "asm.core.ingest_stage" not in celery_app.tasks


def test_env_generator_derives_the_same_pool_key():
    import base64
    import os

    from asm_sensors.jobs import encode_key
    from generate_env import pool_key as stdlib_pool_key  # scripts/generate_env.py (no third-party deps)

    master = os.urandom(32)
    assert stdlib_pool_key(base64.urlsafe_b64encode(master).decode().rstrip("=")) == \
        encode_key(pool_key(master, "default"))


def test_sensor_job_rejects_bad_pool_names():
    from asm_sensors.jobs import job_queue

    assert job_queue("scanners", "tenant-a") == "scanners.tenant-a"
    for bad in ("", "Default", "a.b", "a*", "-x", "x" * 70):
        with pytest.raises(ValueError):
            job_queue("scanners", bad)
