#!/usr/bin/env python3
"""Populate a demo tenant by replaying recorded scanner output through the real pipeline.

No scanning takes place: sensor execution is replaced with the recorded tool
output in tests/sensors/fixtures (documentation IP ranges, example.com). The
rest of the platform — scope authorization, ingestion, change detection,
detection rules, risk scoring, events and metrics — runs for real.

    ASM_DATABASE_URL=... ASM_SENSOR_MODE=inline python scripts/seed_demo.py \
        --email admin@demo.local --password 'Demo-Passw0rd!'
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT)]
os.environ.setdefault("ASM_SENSOR_MODE", "inline")
os.environ.setdefault("ASM_ALLOW_NON_PUBLIC_SCOPE", "true")


class _Patch:
    """Minimal stand-in for pytest's monkeypatch used by FakeSensors."""

    def setattr(self, target, name, value):  # noqa: ANN001
        setattr(target, name, value)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--email", default="admin@demo.local")
    p.add_argument("--password", default="Demo-Passw0rd!")
    p.add_argument("--tenant", default="Demo Holding")
    a = p.parse_args()

    from sqlalchemy import select

    from app.auth.service import set_password
    from app.db.session import new_session, system_session
    from app.models import Organization, ScanProfile, Tenant, TenantMembership, User
    from app.models.enums import Role, ScopeEntryType
    from app.scans import orchestrator
    from app.scope.service import add_entry
    from app.tenants.service import bootstrap, create_tenant
    from tests.backend.sensors_fake import FakeSensors

    with system_session() as db:
        bootstrap(db)
        tenant = db.execute(select(Tenant).where(Tenant.name == a.tenant)).scalar_one_or_none() or create_tenant(db, a.tenant)
        user = db.execute(select(User).where(User.email == a.email)).scalar_one_or_none()
        if user is None:
            user = User(email=a.email, full_name="Demo Administrator", default_tenant_id=tenant.id, is_platform_admin=True)
            db.add(user)
            db.flush()
        set_password(db, user, a.password)
        if not db.execute(select(TenantMembership).where(TenantMembership.tenant_id == tenant.id,
                                                         TenantMembership.user_id == user.id)).scalar_one_or_none():
            db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.TENANT_ADMIN))
        db.commit()
        tid = tenant.id

    fake = FakeSensors(_Patch())
    with new_session(tid) as db:
        org = db.execute(select(Organization).where(Organization.name == "Example Corp")).scalar_one_or_none()
        if org is None:
            org = Organization(tenant_id=tid, name="Example Corp", industry="Financial services",
                               description="Demo organization (replayed data, documentation address ranges)", settings={})
            db.add(org)
            db.flush()
            add_entry(db, tenant_id=tid, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN, value="example.com")
            add_entry(db, tenant_id=tid, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                      value="dev-api.example.com", is_exclusion=True)
            db.commit()
        profile = db.execute(select(ScanProfile).where(ScanProfile.slug == "standard-asm")).scalar_one()
        for i in range(2):
            if i == 1:
                # Day two: a VNC service and an admin port appear on the API host.
                fake.set("naabu", b'{"ip":"198.51.100.7","port":443}\n{"ip":"198.51.100.7","port":10443}\n'
                                  b'{"ip":"192.0.2.20","port":443}\n{"ip":"192.0.2.20","port":3389}\n'
                                  b'{"ip":"192.0.2.20","port":5900}\n{"ip":"192.0.2.20","port":8443}\n')
            scan = orchestrator.create_scan(db, tenant_id=tid, organization_id=org.id, profile_id=profile.id)
            db.commit()
            scan = orchestrator.run_inline(db, scan.id)
            print(f"scan {i + 1}: {scan.status.value} {scan.stats}")
    print(f"demo ready — sign in as {a.email}")


if __name__ == "__main__":
    main()
