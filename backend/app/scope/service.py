"""Scope management: validation, asset synchronization, re-scoping, ownership verification."""

from __future__ import annotations

import ipaddress
import secrets
import uuid
from datetime import UTC, datetime
from typing import Any

import dns.exception
import dns.resolver
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assets.normalization import normalize_hostname, registrable_domain
from app.core.config import get_settings
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.models import Asset, Organization, ScopeEntry, Tenant
from app.models.enums import (
    HOSTNAME_TYPES,
    ApprovalStatus,
    AssetStatus,
    AssetType,
    ScopeEntryType,
    ScopeStatus,
    VerificationStatus,
)
from app.scope.checker import ScopeChecker, ScopeRule
from app.services import audit
from app.services.audit import Action
from app.tenants.settings import org_settings, tenant_settings

VERIFY_PREFIX = "_exteriq-asm"
VERIFY_VALUE = "exteriq-asm-verification="
# Records published before the product was renamed (AlRasedah ASM → Exteriq ASM) still verify.
LEGACY_VERIFY = ("_alrasedah-asm", "alrasedah-asm-verification=")
MAX_IPV4_PREFIX = 16
MAX_IPV6_PREFIX = 48


def normalize_entry(entry_type: ScopeEntryType, value: str) -> str:
    v = value.strip()
    if entry_type == ScopeEntryType.DOMAIN:
        host = normalize_hostname(v.removeprefix("*."))
        if not host:
            raise ValidationFailed(f"'{value}' is not a valid domain name")
        if registrable_domain(host) is None:
            raise ValidationFailed(f"'{value}' is a public suffix and cannot be claimed")
        return host
    if entry_type == ScopeEntryType.IP:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValidationFailed(f"'{value}' is not a valid IP address") from exc
        if not ip.is_global and not get_settings().allow_non_public_scope:
            raise ValidationFailed("Only publicly routable addresses can be in external scope")
        return str(ip)
    try:
        net = ipaddress.ip_network(v, strict=False)
    except ValueError as exc:
        raise ValidationFailed(f"'{value}' is not a valid CIDR range") from exc
    limit = MAX_IPV4_PREFIX if net.version == 4 else MAX_IPV6_PREFIX
    if net.prefixlen < limit:
        raise ValidationFailed(f"CIDR ranges larger than /{limit} are not accepted; split the range")
    if not net.is_global and not get_settings().allow_non_public_scope:
        raise ValidationFailed("Only publicly routable ranges can be in external scope")
    return str(net)


def load_checker(db: Session, organization: Organization) -> ScopeChecker:
    entries = db.execute(select(ScopeEntry).where(ScopeEntry.organization_id == organization.id)).scalars().all()
    tenant = db.get(Tenant, organization.tenant_id)
    ts = tenant_settings(tenant)
    os_ = org_settings(organization)
    return ScopeChecker(
        rules=[ScopeRule.from_entry(e) for e in entries],
        require_verification=bool(ts["scanning"].get("require_scope_verification")),
        derived_ip_scanning=bool(os_.get("derived_ip_scanning", True)),
        allow_non_public=get_settings().allow_non_public_scope,
    )


def _entry_snapshot(e: ScopeEntry) -> dict[str, Any]:
    return {"type": e.entry_type.value, "value": e.value, "include_subdomains": e.include_subdomains,
            "exclusion": e.is_exclusion, "active_scanning": e.allow_active_scanning,
            "verification": e.verification_status.value}


def add_entry(db: Session, *, tenant_id: uuid.UUID, organization_id: uuid.UUID, entry_type: ScopeEntryType, value: str,
              include_subdomains: bool = True, is_exclusion: bool = False, allow_active_scanning: bool = True,
              notes: str | None = None, user_id: uuid.UUID | None = None) -> ScopeEntry:
    org = db.get(Organization, organization_id)
    if org is None:
        raise NotFound("Organization not found")
    norm = normalize_entry(entry_type, value)
    dup = db.execute(select(ScopeEntry).where(
        ScopeEntry.organization_id == organization_id, ScopeEntry.entry_type == entry_type,
        ScopeEntry.value == norm, ScopeEntry.is_exclusion == is_exclusion)).scalar_one_or_none()
    if dup:
        raise Conflict(f"{norm} is already in scope")
    tenant = db.get(Tenant, tenant_id)
    require_verification = bool(tenant_settings(tenant)["scanning"].get("require_scope_verification"))
    entry = ScopeEntry(
        tenant_id=tenant_id, organization_id=organization_id, entry_type=entry_type, value=norm,
        include_subdomains=include_subdomains if entry_type == ScopeEntryType.DOMAIN else False,
        is_exclusion=is_exclusion, allow_active_scanning=allow_active_scanning and not is_exclusion, notes=notes,
        created_by=user_id,
        verification_status=(VerificationStatus.UNVERIFIED if require_verification and not is_exclusion
                             else VerificationStatus.NOT_REQUIRED),
        verification_token=secrets.token_urlsafe(24) if entry_type == ScopeEntryType.DOMAIN else None,
    )
    db.add(entry)
    db.flush()
    audit.record(db, Action.SCOPE_ADDED, tenant_id=tenant_id, object_type="scope_entry", object_id=entry.id,
                 new={"organization_id": str(organization_id), **_entry_snapshot(entry)})
    sync_scope_assets(db, org)
    return entry


def update_entry(db: Session, entry_id: uuid.UUID, changes: dict[str, Any]) -> ScopeEntry:
    entry = db.get(ScopeEntry, entry_id)
    if entry is None:
        raise NotFound("Scope entry not found")
    before = _entry_snapshot(entry)
    for field in ("include_subdomains", "allow_active_scanning", "notes"):
        if field in changes and changes[field] is not None:
            setattr(entry, field, changes[field])
    if entry.is_exclusion:
        entry.allow_active_scanning = False
    db.flush()
    prev, new = audit.diff(before, _entry_snapshot(entry))
    audit.record(db, Action.SCOPE_UPDATED, tenant_id=entry.tenant_id, object_type="scope_entry", object_id=entry.id,
                 previous=prev, new=new)
    org = db.get(Organization, entry.organization_id)
    if org:
        sync_scope_assets(db, org)
    return entry


def remove_entry(db: Session, entry_id: uuid.UUID) -> None:
    entry = db.get(ScopeEntry, entry_id)
    if entry is None:
        raise NotFound("Scope entry not found")
    snapshot = _entry_snapshot(entry)
    org = db.get(Organization, entry.organization_id)
    db.delete(entry)
    db.flush()
    audit.record(db, Action.SCOPE_REMOVED, tenant_id=entry.tenant_id, object_type="scope_entry", object_id=entry_id,
                 previous=snapshot)
    if org:
        sync_scope_assets(db, org)


def _upsert_scope_asset(db: Session, org: Organization, t: AssetType, value: str, now: datetime) -> None:
    asset = db.execute(select(Asset).where(Asset.organization_id == org.id, Asset.asset_type == t,
                                           Asset.normalized_value == value)).scalar_one_or_none()
    if asset is None:
        # Declared by the customer: known, approved, in scope.
        db.add(Asset(tenant_id=org.tenant_id, organization_id=org.id, asset_type=t, value=value, normalized_value=value,
                     status=AssetStatus.ACTIVE, scope_status=ScopeStatus.IN_SCOPE, first_seen=now, last_seen=now,
                     discovered_at=now, source="scope", sources=["scope"], discovery_method="scope", confidence=100,
                     approval_status=ApprovalStatus.APPROVED, meta={}, tags=[], risk_factors=[]))
    else:
        asset.scope_status = ScopeStatus.IN_SCOPE
        if asset.approval_status == ApprovalStatus.UNVERIFIED:
            asset.approval_status = ApprovalStatus.APPROVED


def sync_scope_assets(db: Session, org: Organization) -> None:
    """Materialize inclusion entries as assets and re-evaluate existing assets' scope status."""
    now = datetime.now(UTC)
    entries = db.execute(select(ScopeEntry).where(ScopeEntry.organization_id == org.id,
                                                  ScopeEntry.is_exclusion.is_(False))).scalars().all()
    for e in entries:
        if e.entry_type == ScopeEntryType.DOMAIN:
            existing_host = db.execute(select(Asset).where(
                Asset.organization_id == org.id, Asset.normalized_value == e.value,
                Asset.asset_type.in_([t.value for t in HOSTNAME_TYPES]))).scalars().first()
            if existing_host is not None and existing_host.asset_type != AssetType.ROOT_DOMAIN:
                existing_host.asset_type = AssetType.ROOT_DOMAIN  # a discovered name was later declared as a root
            _upsert_scope_asset(db, org, AssetType.ROOT_DOMAIN, e.value, now)
        elif e.entry_type == ScopeEntryType.IP:
            _upsert_scope_asset(db, org, AssetType.IP_ADDRESS, e.value, now)
        else:
            _upsert_scope_asset(db, org, AssetType.CIDR, e.value, now)
    db.flush()
    rescope_assets(db, org)


def rescope_assets(db: Session, org: Organization) -> int:
    """Recompute scope status of hostnames and IPs after scope changes. Returns #changed."""
    checker = load_checker(db, org)
    changed = 0
    rows = db.execute(select(Asset).where(
        Asset.organization_id == org.id,
        Asset.asset_type.in_([t.value for t in HOSTNAME_TYPES] + [AssetType.IP_ADDRESS.value]))).scalars().all()
    for a in rows:
        if a.asset_type == AssetType.IP_ADDRESS:
            status, _ = checker.ip_status(a.normalized_value)
            if status == ScopeStatus.OUT_OF_SCOPE and a.scope_status == ScopeStatus.DERIVED \
                    and not checker.is_excluded_ip(a.normalized_value):
                continue  # still derived from DNS; re-evaluated at next resolution
        else:
            status, _ = checker.hostname_status(a.normalized_value)
            if a.asset_type == AssetType.ROOT_DOMAIN and a.normalized_value not in checker.root_domains:
                a.asset_type = AssetType.SUBDOMAIN if registrable_domain(a.normalized_value) != a.normalized_value \
                    else AssetType.DOMAIN
        if status != a.scope_status:
            a.scope_status = status
            changed += 1
    db.flush()
    return changed


# ------------------------------------------------------------ verification
def apply_verification_policy(db: Session, tenant_id: uuid.UUID) -> int:
    """Re-classify inclusion entries after verification became mandatory.

    Entries recorded as ``not_required`` while verification was off were never
    proven; they become ``unverified`` so the UI asks for proof. (The checker
    already treats only ``verified`` as proof; this keeps the displayed state
    honest.) Returns the number of entries changed.
    """
    tenant = db.get(Tenant, tenant_id)
    if not tenant_settings(tenant)["scanning"].get("require_scope_verification"):
        return 0
    rows = db.execute(select(ScopeEntry).where(
        ScopeEntry.tenant_id == tenant_id, ScopeEntry.is_exclusion.is_(False),
        ScopeEntry.verification_status == VerificationStatus.NOT_REQUIRED)).scalars().all()
    for e in rows:
        e.verification_status = VerificationStatus.UNVERIFIED
    db.flush()
    return len(rows)


def approve_entry(db: Session, entry_id: uuid.UUID) -> ScopeEntry:
    """Platform-administrator approval of an IP/CIDR inclusion (they have no DNS proof)."""
    entry = db.get(ScopeEntry, entry_id)
    if entry is None:
        raise NotFound("Scope entry not found")
    if entry.entry_type == ScopeEntryType.DOMAIN:
        raise ValidationFailed("Domains are verified with a DNS TXT record, not by approval")
    if entry.is_exclusion:
        raise ValidationFailed("Exclusions do not need approval")
    entry.verification_status = VerificationStatus.VERIFIED
    entry.verified_at = datetime.now(UTC)
    audit.record(db, Action.SCOPE_VERIFIED, tenant_id=entry.tenant_id, object_type="scope_entry", object_id=entry.id,
                 new={"value": entry.value, "method": "platform_admin_approval"})
    db.flush()
    return entry


def verification_instructions(entry: ScopeEntry) -> dict[str, str]:
    return {"record_type": "TXT", "name": f"{VERIFY_PREFIX}.{entry.value}",
            "value": f"{VERIFY_VALUE}{entry.verification_token}"}


def verify_entry(db: Session, entry_id: uuid.UUID, resolver: dns.resolver.Resolver | None = None) -> ScopeEntry:
    entry = db.get(ScopeEntry, entry_id)
    if entry is None:
        raise NotFound("Scope entry not found")
    if entry.entry_type != ScopeEntryType.DOMAIN or not entry.verification_token:
        raise ValidationFailed("Only domain entries support DNS verification")
    r = resolver or dns.resolver.Resolver()
    r.lifetime = 10
    verified = False
    for prefix, value in ((VERIFY_PREFIX, VERIFY_VALUE), LEGACY_VERIFY):
        try:
            answers = r.resolve(f"{prefix}.{entry.value}", "TXT")
            values = {b"".join(a.strings).decode("utf-8", "replace") for a in answers}  # type: ignore[attr-defined]
        except dns.exception.DNSException:
            values = set()
        if f"{value}{entry.verification_token}" in values:
            verified = True
            break
    if verified:
        entry.verification_status = VerificationStatus.VERIFIED
        entry.verified_at = datetime.now(UTC)
        audit.record(db, Action.SCOPE_VERIFIED, tenant_id=entry.tenant_id, object_type="scope_entry",
                     object_id=entry.id, new={"value": entry.value})
    else:
        entry.verification_status = VerificationStatus.PENDING
    db.flush()
    return entry
