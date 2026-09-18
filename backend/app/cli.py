"""Administrative command line.

    python -m app.cli bootstrap                 # plans, built-in profiles, first admin (idempotent)
    python -m app.cli generate-keys             # print fresh secrets for .env
    python -m app.cli create-admin --email ... --tenant "Acme"
    python -m app.cli intel-import --kev kev.json --epss epss_scores-current.csv.gz
    python -m app.cli intel-refresh
    python -m app.cli run-scan --tenant <id> --organization <id> --profile standard-asm   (inline, for labs)
    python -m app.cli verify-audit --tenant <id>
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
    v = sub.add_parser("verify-audit")
    v.add_argument("--tenant")
    v.set_defaults(fn=cmd_verify_audit)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
