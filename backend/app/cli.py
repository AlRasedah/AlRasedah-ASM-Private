"""Administrative command line.

    python -m app.cli bootstrap                 # plans, built-in profiles, first admin (idempotent)
    python -m app.cli generate-keys             # print fresh secrets for .env
    python -m app.cli scanner-pool-key <pool>   # the key a worker pool's sensor containers receive
    python -m app.cli scanner-pool <pool>       # everything to give a tenant its own scanner
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
from typing import TYPE_CHECKING

from app.core.crypto import generate_key

if TYPE_CHECKING:  # imports stay lazy at runtime: the CLI must start without loading the ORM
    from sqlalchemy.orm import Session

    from app.models import Tenant


def cmd_generate_keys(_: argparse.Namespace) -> None:
    print(f"ASM_SECRET_KEY={secrets.token_urlsafe(48)}")
    print(f"ASM_ENCRYPTION_KEYS=k1:{generate_key()}")
    print(f"ASM_SCANNER_TRANSPORT_KEY={generate_key()}")


def cmd_scanner_pool_key(a: argparse.Namespace) -> None:
    """Print a worker pool's key (the only key that pool's sensor workers receive)."""
    from asm_sensors.jobs import encode_key

    from app.core.crypto import pool_transport_key

    print(f"ASM_SCANNER_TRANSPORT_KEY={encode_key(pool_transport_key(a.pool))}   # for the '{a.pool}' sensor workers")


def cmd_scanner_pool(a: argparse.Namespace) -> None:
    """Everything needed to give a tenant its own scanner: key, broker user, ACL, service.

    A pool is a trust domain, so each tenant that must not share scanners needs its
    own workers, its own broker account and its own derived key. Printing the whole
    block keeps the three in step — a pool provisioned by hand with a mismatched key
    fails at result verification, long after the mistake.
    """
    from asm_sensors.jobs import encode_key

    from app.core.crypto import pool_transport_key

    pool = a.pool
    password = secrets.token_urlsafe(32)
    queues = [f"scanners.{pool}", f"results.{pool}"]
    print(f"# --- scanner pool '{pool}' ------------------------------------------------")
    print("# 1. .env (platform):")
    print(f"#    add '{pool}' to ASM_WORKER_POOLS, so asm-ingest consumes results.{pool}")
    print(f"ASM_SCANNER_REDIS_PASSWORD_{pool.upper().replace('-', '_')}={password}")
    print("\n# 2. docker-compose.yml — redis command, a copy of the scanner-default block:")
    print(f'              "--user", "scanner-{pool}", "on", ">{password}",')
    print('              "resetkeys", "resetchannels",')
    for q in queues:
        print(f'              "~{q}", "~_kombu.binding.{q}",')
    print(f'              "~unacked.scanners.{pool}", "~unacked_index.scanners.{pool}", '
          f'"~unacked_mutex.scanners.{pool}",')
    print(f'              "~asm.pool.{pool}.*", "&/0.asm-{pool}.pidbox", "~*.asm-{pool}.pidbox",')
    print(f'              "~_kombu.binding.asm-{pool}.pidbox",')
    print('              "+@read", "+@write", "+@connection", "+ping", "+client|setinfo", "-@dangerous",')
    print("\n# 3. docker-compose.yml — the scanner service for this pool:")
    print(f"""  asm-scanner-{pool}:
    <<: *scanner
    environment:
      <<: *scanner-env
      ASM_SENSOR_POOL: {pool}
      ASM_CELERY_BROKER_URL: redis://scanner-{pool}:{password}@redis:6379/0
      ASM_SCANNER_TRANSPORT_KEY: {encode_key(pool_transport_key(pool))}
      # Its own DAST daemon: a ZAP session is global state shared by whoever uses it.
      ASM_ZAP_URL: http://zap-{pool}:8090""")
    print("\n# 4. Point the tenant at it (Platform -> Tenants, or set tenants.worker_pool to")
    print(f"#    {pool!r} for that tenant). A tenant created after this pool exists already")
    print("#    carries its own pool name, so there is usually nothing to change.")


def cmd_bootstrap(_: argparse.Namespace) -> None:
    from app.db.session import system_session
    from app.tenants.service import bootstrap

    with system_session() as db:
        bootstrap(db)
    print("bootstrap complete")


def _resolve_tenant(db: Session, name: str, create: bool) -> Tenant:
    """The tenant named `name`, or a clear refusal.

    `--tenant` used to be a get-or-create, so a name that did not match exactly
    ("Acme" for "Acme Corp", a stray capital, a trailing space) silently built a
    second, empty tenant and put the new admin in it. They could then sign in,
    see every menu, and find no scans, no assets and nothing explaining why.
    An unknown name is now an error unless it is the first tenant of a fresh
    deployment or the caller asked for one with --create-tenant.
    """
    from sqlalchemy import func, select

    from app.models import Tenant
    from app.tenants.service import create_tenant

    tenant = db.execute(select(Tenant).where(Tenant.name == name)).scalar_one_or_none()
    if tenant is not None:
        return tenant
    existing = list(db.execute(select(Tenant.name).order_by(Tenant.name)).scalars().all())
    if create or not existing:
        return create_tenant(db, name)
    near = db.execute(select(Tenant.name).where(func.lower(func.trim(Tenant.name)) == name.strip().lower())).scalars().first()
    hint = f"\nDid you mean --tenant {near!r}?" if near else ""
    raise SystemExit(
        f"No tenant is named {name!r}.{hint}\n"
        f"Existing tenants: {', '.join(repr(n) for n in existing)}\n"
        "Use one of those names, or pass --create-tenant to start a new (empty) tenant."
    )


def cmd_create_admin(a: argparse.Namespace) -> None:
    from sqlalchemy import select

    from app.auth.service import normalize_email, set_password
    from app.db.session import system_session
    from app.models import Tenant, TenantMembership, User
    from app.models.enums import Role

    password = a.password or os.environ.get("ASM_ADMIN_PASSWORD") or getpass.getpass("Password: ")
    with system_session() as db:
        tenant = _resolve_tenant(db, a.tenant, a.create_tenant)
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
        # An existing account keeps the tenant it already defaults to, so say where this
        # sign-in will actually land — the other half of "the new admin sees nothing".
        elsewhere = user.default_tenant_id and user.default_tenant_id != tenant.id
        db.commit()
        if elsewhere:
            other = db.get(Tenant, user.default_tenant_id)
            print(f"note: {email} already signs in to tenant '{other.name if other else user.default_tenant_id}'. "
                  f"They can switch to '{tenant.name}' from the tenant selector in the top bar.")
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
                               description="Demo organization (documentation address ranges)",
                               settings={"demo_seed": True})
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
    belonged only to it. Idempotent; safe to run when nothing is there.

    Refuses (unless ``--force``) if the tenant contains any organization not created
    by ``demo-seed``, so it cannot silently wipe real data that shares the tenant."""
    from sqlalchemy import delete, func, select, text

    from app.db.session import system_session
    from app.models import Organization, Tenant, TenantMembership, User

    with system_session() as db:
        tenant = db.execute(select(Tenant).where(Tenant.name == a.tenant)).scalar_one_or_none()
        if tenant is None:
            print(f"no tenant named {a.tenant!r}; nothing to delete")
            return
        tid = tenant.id
        # Safety: show what will be deleted, and refuse if the tenant holds any
        # organization that was NOT created by demo-seed (i.e. possibly real data),
        # unless --force is given. This prevents wiping real orgs that happen to share
        # a tenant with demo data.
        orgs = db.execute(select(Organization).where(Organization.tenant_id == tid)).scalars().all()
        non_demo = [o for o in orgs if not (o.settings or {}).get("demo_seed")]
        if orgs:
            print(f"tenant {a.tenant!r} contains {len(orgs)} organization(s): "
                  + ", ".join(f"{o.name}{'' if (o.settings or {}).get('demo_seed') else ' [NOT demo-seeded]'}" for o in orgs))
        if non_demo and not getattr(a, "force", False):
            print(f"REFUSING to delete: {len(non_demo)} organization(s) were not created by demo-seed "
                  f"and may contain real data: {', '.join(o.name for o in non_demo)}")
            print("Re-run with --force if you are certain you want to delete this tenant and ALL of its data.")
            return
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
    k = sub.add_parser("scanner-pool-key")
    k.add_argument("pool", nargs="?", default="default")
    k.set_defaults(fn=cmd_scanner_pool_key)
    sp = sub.add_parser("scanner-pool", help="provision a tenant-exclusive scanner pool")
    sp.add_argument("pool")
    sp.set_defaults(fn=cmd_scanner_pool)
    c = sub.add_parser("create-admin")
    c.add_argument("--email", required=True)
    c.add_argument("--tenant", default="Default")
    c.add_argument("--create-tenant", action="store_true",
                   help="start a new, empty tenant when --tenant names one that does not exist")
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
    dr.add_argument("--force", action="store_true",
                    help="delete even if the tenant contains organizations not created by demo-seed")
    dr.set_defaults(fn=cmd_demo_reset)
    v = sub.add_parser("verify-audit")
    v.add_argument("--tenant")
    v.set_defaults(fn=cmd_verify_audit)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
