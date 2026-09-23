"""Mutually untrusted tenants must not share a scanner pool (review finding F1).

A pool is a trust domain, not a queue name: its containers hold that pool's broker
credentials and transport key, so a compromised scanner can read every job in the
pool, open those tenants' sealed credentials and sign results for their pending
stages. Binding a result to tenant/scan/stage/job rejects an invented job, but all
of those ids are in the queued job the scanner can already read.

Documenting "use separate pools" is not the guarantee. The platform refuses the
dispatch.
"""

from __future__ import annotations

from sqlalchemy import select

from app.core.config import get_settings
from app.db.session import new_session, system_session
from app.models import Scan, ScanProfile, Tenant
from app.models.enums import ScanStatus
from app.scans import orchestrator

from .sensors_fake import FakeSensors


def _pools(monkeypatch, *names: str) -> None:
    monkeypatch.setattr(get_settings(), "worker_pools", list(names))


def _isolation(monkeypatch, mode: str) -> None:
    monkeypatch.setattr(get_settings(), "scanner_isolation", mode)


def _set_pool(tenant_id, pool: str) -> None:
    with system_session() as db:
        db.get(Tenant, tenant_id).worker_pool = pool
        db.commit()


def _start(tenant_id, org_id) -> Scan:
    with new_session(tenant_id) as db:
        pid = db.scalar(select(ScanProfile.id).where(ScanProfile.slug == "passive-discovery",
                                                     ScanProfile.tenant_id.is_(None)))
        scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=pid)
        db.commit()
        orchestrator.try_start(db, scan)
        db.commit()
        db.refresh(scan)
        db.expunge(scan)
        return scan


class TestSharedPoolsAreRefused:
    def test_two_tenants_on_one_pool_cannot_scan(self, db_clean, factory, monkeypatch):
        _isolation(monkeypatch, "per_tenant")
        _pools(monkeypatch, "shared")
        acme, globex = factory.tenant("Acme"), factory.tenant("Globex")
        org = factory.org(acme.id, domains=("example.com",))
        _set_pool(acme.id, "shared")
        _set_pool(globex.id, "shared")

        scan = _start(acme.id, org.id)
        assert scan.status == ScanStatus.CANCELLED
        assert "shared with another tenant" in (scan.error or "")
        assert "administrator" in (scan.error or "")

    def test_a_tenant_with_its_own_pool_scans(self, db_clean, factory, monkeypatch):
        _isolation(monkeypatch, "per_tenant")
        _pools(monkeypatch, "t-acme", "t-globex")
        acme, globex = factory.tenant("Acme"), factory.tenant("Globex")
        org = factory.org(acme.id, domains=("example.com",))
        _set_pool(acme.id, "t-acme")
        _set_pool(globex.id, "t-globex")

        scan = _start(acme.id, org.id)
        assert scan.status == ScanStatus.RUNNING

    def test_one_tenant_alone_on_the_default_pool_is_fine(self, db_clean, factory, monkeypatch):
        # A single-tenant deployment has nobody to be isolated from; enforcement must
        # not make the ordinary install unusable.
        _isolation(monkeypatch, "per_tenant")
        _pools(monkeypatch, "default")
        only = factory.tenant("Only")
        org = factory.org(only.id, domains=("example.com",))
        _set_pool(only.id, "default")
        assert _start(only.id, org.id).status == ScanStatus.RUNNING

    def test_an_unprovisioned_pool_says_what_to_run(self, db_clean, factory, monkeypatch):
        _isolation(monkeypatch, "per_tenant")
        _pools(monkeypatch, "default")
        acme = factory.tenant("Acme")
        org = factory.org(acme.id, domains=("example.com",))
        _set_pool(acme.id, "t-acme")  # named, but no scanner consumes it

        scan = _start(acme.id, org.id)
        assert scan.status == ScanStatus.CANCELLED
        assert "no scanner is running" in (scan.error or "").lower()
        assert "cli scanner-pool t-acme" in (scan.error or "")

    def test_a_deployment_may_opt_out_deliberately(self, db_clean, factory, monkeypatch):
        # In-house deployments where every tenant is the same organization.
        _isolation(monkeypatch, "shared")
        _pools(monkeypatch, "default")
        acme, globex = factory.tenant("Acme"), factory.tenant("Globex")
        org = factory.org(acme.id, domains=("example.com",))
        _set_pool(acme.id, "default")
        _set_pool(globex.id, "default")
        assert _start(acme.id, org.id).status == ScanStatus.RUNNING


class TestNewTenantsGetTheirOwnPool:
    def test_a_new_tenant_does_not_land_in_an_existing_pool(self, db_clean, monkeypatch):
        _isolation(monkeypatch, "per_tenant")
        from app.tenants.service import create_tenant

        with system_session() as db:
            first = create_tenant(db, "Acme Corp")
            second = create_tenant(db, "Globex")
            db.commit()
            assert first.worker_pool == "t-acme-corp" and second.worker_pool == "t-globex"
            assert first.worker_pool != second.worker_pool

    def test_a_shared_deployment_keeps_the_single_pool(self, db_clean, monkeypatch):
        _isolation(monkeypatch, "shared")
        from app.tenants.service import create_tenant

        with system_session() as db:
            assert create_tenant(db, "Acme Corp").worker_pool == "default"


def test_the_check_runs_before_any_target_is_touched(db_clean, factory, monkeypatch):
    """A refused tenant must not reach a sensor at all."""
    _isolation(monkeypatch, "per_tenant")
    _pools(monkeypatch, "shared")
    fake = FakeSensors(monkeypatch)
    acme, globex = factory.tenant("Acme"), factory.tenant("Globex")
    org = factory.org(acme.id, domains=("example.com",))
    _set_pool(acme.id, "shared")
    _set_pool(globex.id, "shared")

    with new_session(acme.id) as db:
        pid = db.scalar(select(ScanProfile.id).where(ScanProfile.slug == "passive-discovery",
                                                     ScanProfile.tenant_id.is_(None)))
        scan = orchestrator.create_scan(db, tenant_id=acme.id, organization_id=org.id, profile_id=pid)
        db.commit()
        finished = orchestrator.run_inline(db, scan.id)
    assert finished.status == ScanStatus.CANCELLED
    assert not fake.calls, "no engine may be handed targets for a refused tenant"
