"""Administrative command line.

    python -m app.cli bootstrap                 # plans, built-in profiles, first admin (idempotent)
    python -m app.cli generate-keys             # print fresh secrets for .env
    python -m app.cli create-admin --email ... --tenant "Acme"
    python -m app.cli intel-import --kev kev.json --epss epss_scores-current.csv.gz
    python -m app.cli intel-refresh
    python -m app.cli run-scan --tenant <id> --organization <id> --profile standard-asm   (inline, for labs)
    python -m app.cli verify-audit --tenant <id>
    python -m app.cli demo-seed                 # create a demo tenant, admin, org and scope (customer demos)
    python -m app.cli demo-reset                # delete the demo tenant and ALL of its data
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import secrets
import sys
import uuid

from app.core.crypto import generate_key


def cmd_generate_keys(_: argparse.Namespace) -> None:
    print(f"ASM_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"ASM_ENCRYPTION_KEYS=k1:{generate_key()}")
    print(f"ASM_SCANNER_TRANSPORT_KEY={generate_key()}")


def cmd_bootstrap(_: argparse.Namespace) -> None:
    from app.db.session import system_session
    from app.tenants.service import bootstrap

    with system_session() as db:
        bootstrap(db)
    print("bootstrap complete")


def cmd_create_admin(a: argparse.Namespace) -> None:
    from sqlalchemy import select

    from app.auth.service import normalize_email, set_password
    from app.db.session import system_session
    from app.models import Tenant, TenantMembership, User
    from app.models.enums import Role
    from app.tenants.service import create_tenant

    password = a.password or os.environ.get("ASM_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    with system_session() as db:
        tenant = db.execute(select(Tenant).where(Tenant.name == a.tenant)).scalar_one_or_none() \
            or create_tenant(db, a.tenant)
        email = normalize_email(a.email)
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = User(email=email, full_name=a.name, default_tenant_id=tenant.id, is_platform_admin=a.platform_admin)
            db.add(user)
            db.flush()
        set_password(db, user, password)
        if not db.execute(select(TenantMembership).where(TenantMembership.tenant_id == tenant.id,
                                                         TenantMembership.user_id == user.id)).scalar_one_or_none():
            db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.TENANT_ADMIN))
        db.commit()
    print(f"admin {email} ready in tenant '{a.tenant}'")


def cmd_intel_import(a: argparse.Namespace) -> None:
    from app.intel.service import import_files

    print(json.dumps(import_files(a.kev, a.epss)))


def cmd_intel_refresh(_: argparse.Namespace) -> None:
    from app.intel.service import refresh_all

    print(json.dumps(refresh_all(), default=str))


def cmd_run_scan(a: argparse.Namespace) -> None:
    from sqlalchemy import or_, select

    from app.db.session import new_session
    from app.models import ScanProfile
    from app.scans import orchestrator

    tid = uuid.UUID(a.tenant)
    with new_session(tid) as db:
        profile = db.execute(select(ScanProfile).where(or_(ScanProfile.slug == a.profile,
                                                           ScanProfile.name == a.profile))).scalars().first()
        if profile is None:
            sys.exit(f"unknown profile {a.profile}")
        scan = orchestrator.create_scan(db, tenant_id=tid, organization_id=uuid.UUID(a.organization),
                                        profile_id=profile.id)
        db.commit()
        scan = orchestrator.run_inline(db, scan.id)
        print(json.dumps({"scan": str(scan.id), "status": scan.status.value, "stats": scan.stats}, default=str))


DEMO_ORG = "Example Corp"


def cmd_demo_seed(a: argparse.Namespace) -> None:
    """Create (idempotently) a demo tenant, platform admin, organization and scope.

    No scanning is performed — this sets up an empty, scoped demo ready to log
    into. Populate it by running a scan (real data in a full deployment) or, for a
    local lab with rich replayed data, use ``scripts/seed_demo.py``.
    """
    from sqlalchemy import select

    from app.auth.service import normalize_email, set_password
    from app.db.session import new_session, system_session
    from app.models import Organization, Tenant, TenantMembership, User
    from app.models.enums import Role, ScopeEntryType
    from app.scope.service import add_entry
    from app.tenants.service import bootstrap, create_tenant

    password = a.password or os.environ.get("ASM_DEMO_PASSWORD") or "Demo-Passw0rd!"
    email = normalize_email(a.email)
    with system_session() as db:
        bootstrap(db)
        tenant = db.execute(select(Tenant).where(Tenant.name == a.tenant)).scalar_one_or_none() \
            or create_tenant(db, a.tenant)
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if user is None:
            user = User(email=email, full_name="Demo Administrator", default_tenant_id=tenant.id, is_platform_admin=True)
            db.add(user)
            db.flush()
        set_password(db, user, password)
        if not db.execute(select(TenantMembership).where(TenantMembership.tenant_id == tenant.id,
                                                         TenantMembership.user_id == user.id)).scalar_one_or_none():
            db.add(TenantMembership(tenant_id=tenant.id, user_id=user.id, role=Role.TENANT_ADMIN))
        db.commit()
        tid = tenant.id

    with new_session(tid) as db:
        org = db.execute(select(Organization).where(Organization.name == a.org)).scalar_one_or_none()
        if org is None:
            org = Organization(tenant_id=tid, name=a.org, industry="Financial services",
                               description="Demo organization (documentation address ranges)", settings={})
            db.add(org)
            db.flush()
            add_entry(db, tenant_id=tid, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN, value="example.com")
            add_entry(db, tenant_id=tid, organization_id=org.id, entry_type=ScopeEntryType.DOMAIN,
                      value="dev-api.example.com", is_exclusion=True)
            db.commit()
    print(f"demo ready — tenant '{a.tenant}', organization '{a.org}'")
    print(f"  sign in as {email} / {password}")
    print("  populate it by running a scan (Scans -> New scan), or use scripts/seed_demo.py for local replayed data")
    print("  remove it later with:  python -m app.cli demo-reset --tenant " + repr(a.tenant))


def cmd_demo_reset(a: argparse.Namespace) -> None:
    """Delete a demo tenant and **all** of its data (organizations, assets, findings,
    scans, events, scope, integrations, profiles, memberships) plus any users that
    belonged only to it. Idempotent; safe to run when nothing is there."""
    from sqlalchemy import delete, func, select, text

    from app.db.session import system_session
    from app.models import Tenant, TenantMembership, User

    with system_session() as db:
        tenant = db.execute(select(Tenant).where(Tenant.name == a.tenant)).scalar_one_or_none()
        if tenant is None:
            print(f"no tenant named {a.tenant!r}; nothing to delete")
            return
        tid = tenant.id
        user_ids = {u for (u,) in db.execute(select(TenantMembership.user_id).where(TenantMembership.tenant_id == tid))}
        # Deleting the tenant cascades every tenant-scoped row (ON DELETE CASCADE) and its
        # custom profiles. The audit log is append-only and gapless per chain, so we cannot
        # let the FK SET-NULL the tenant's audit rows (that would collide on the platform
        # chain, and is blocked by the immutability trigger). Instead, delete this tenant's
        # audit rows first. That needs the immutability trigger off and FORCE row-level
        # security off (the append-only table has no UPDATE/DELETE policy, so even the owner
        # is otherwise blocked). Both toggles are transactional DDL, restored in `finally`
        # and reverted entirely on rollback. Deleting the user only SET-NULLs
        # audit_logs.user_id (not the chain key), which the FK cascade handles.
        db.execute(text("ALTER TABLE audit_logs NO FORCE ROW LEVEL SECURITY"))
        db.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_immutable"))
        removed_users = 0
        try:
            db.execute(text("DELETE FROM audit_logs WHERE tenant_id = :t"), {"t": tid})
            db.execute(delete(Tenant).where(Tenant.id == tid))
            db.flush()
            for uid in user_ids:
                if not db.scalar(select(func.count()).select_from(TenantMembership).where(TenantMembership.user_id == uid)):
                    db.execute(delete(User).where(User.id == uid))
                    removed_users += 1
        finally:
            db.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_immutable"))
            db.execute(text("ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY"))
        db.commit()
    print(f"deleted tenant {a.tenant!r} and all of its data ({removed_users} demo-only user(s) removed)")


def cmd_verify_audit(a: argparse.Namespace) -> None:
    from app.db.session import system_session
    from app.services.audit import check_chain

    with system_session() as db:
        r = check_chain(db, uuid.UUID(a.tenant) if a.tenant else None)
    print(f"audit chain intact ({r.entries} entries)" if r.intact
          else f"audit chain BROKEN at entry #{r.first_bad_seq} (id {r.first_bad_id}): {r.reason}")
    sys.exit(0 if r.intact else 1)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="asm", description="Exteriq ASM administration")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate-keys").set_defaults(fn=cmd_generate_keys)
    sub.add_parser("bootstrap").set_defaults(fn=cmd_bootstrap)
    c = sub.add_parser("create-admin")
    c.add_argument("--email", required=True)
    c.add_argument("--tenant", default="Default")
    c.add_argument("--name", default="Administrator")
    c.add_argument("--password")
    c.add_argument("--platform-admin", action="store_true")
    c.set_defaults(fn=cmd_create_admin)
    i = sub.add_parser("intel-import")
    i.add_argument("--kev")
    i.add_argument("--epss")
    i.set_defaults(fn=cmd_intel_import)
    sub.add_parser("intel-refresh").set_defaults(fn=cmd_intel_refresh)
    r = sub.add_parser("run-scan")
    r.add_argument("--tenant", required=True)
    r.add_argument("--organization", required=True)
    r.add_argument("--profile", default="standard-asm")
    r.set_defaults(fn=cmd_run_scan)
    ds = sub.add_parser("demo-seed")
    ds.add_argument("--email", default="admin@demo.local")
    ds.add_argument("--password")  # or ASM_DEMO_PASSWORD; defaults to Demo-Passw0rd!
    ds.add_argument("--tenant", default="Demo Holding")
    ds.add_argument("--org", default=DEMO_ORG)
    ds.set_defaults(fn=cmd_demo_seed)
    dr = sub.add_parser("demo-reset")
    dr.add_argument("--tenant", default="Demo Holding")
    dr.set_defaults(fn=cmd_demo_reset)
    v = sub.add_parser("verify-audit")
    v.add_argument("--tenant")
    v.set_defaults(fn=cmd_verify_audit)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
