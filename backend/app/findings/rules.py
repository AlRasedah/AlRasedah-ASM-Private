"""Built-in detection rules evaluated by the platform on normalized state.

Rules produce ordinary finding observations with source ``asm-rules`` plus a
finding coverage over the evaluated assets, and are ingested through the same
engine as any sensor. That gives them de-duplication, history, automatic
resolution and events for free.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from asm_sensors.observations import (
    AssetRef,
    FindingCategory,
    FindingCoverage,
    FindingObservation,
    SensorResult,
    Severity,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assets.normalization import observed_type_for, parse_port_value
from app.changes.knowledge import API_DOC_TECH, RISKY_PORTS, looks_like_login, management_interface
from app.models import Asset, AssetRelationship
from app.models.enums import AssetStatus, AssetType, RelationType, ScopeStatus

SOURCE = "asm-rules"
REMOTE_ACCESS = {"FortiGate", "Fortinet", "Pulse Secure", "Ivanti", "GlobalProtect", "Citrix", "Citrix NetScaler",
                 "SonicWall", "Cisco ASA", "F5 BIG-IP", "Palo Alto", "Check Point"}

_SERVICE_REMEDIATION = ("Restrict {label} to trusted networks (VPN, allow-listing or a bastion host). Database, "
                        "remote-administration and cluster-management services should never be reachable from the "
                        "public internet.")


def _ref(asset: Asset) -> AssetRef:
    return AssetRef(type=observed_type_for(asset.asset_type), value=asset.normalized_value)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    except ValueError:
        return None


def _host_matches(host: str, names: Iterable[str]) -> bool:
    for n in names:
        n = (n or "").lower().rstrip(".")
        if n == host or (n.startswith("*.") and host.endswith(n[1:]) and host.count(".") == n.count(".")):
            return True
    return False


def evaluate_port(asset: Asset, cfg: dict[str, Any]) -> list[FindingObservation]:
    if not cfg.get("risky_ports"):
        return []
    parsed = parse_port_value(asset.normalized_value)
    if not parsed or parsed[1] not in RISKY_PORTS:
        return []
    label, sev = RISKY_PORTS[parsed[1]]
    return [FindingObservation(
        asset=_ref(asset), rule_id=f"exposed-service:{parsed[1]}/{parsed[2]}",
        title=f"{label} exposed to the internet", severity=sev, category=FindingCategory.SERVICE_EXPOSURE,
        description=f"{label} ({parsed[1]}/{parsed[2]}) is reachable from the public internet on {parsed[0]}.",
        remediation=_SERVICE_REMEDIATION.format(label=label),
        evidence={"ip": parsed[0], "port": parsed[1], "protocol": parsed[2]}, tags=["exposed-service"],
        confidence=85)]


def evaluate_endpoint(asset: Asset, cert: Asset | None, cfg: dict[str, Any], now: datetime) -> list[FindingObservation]:
    out: list[FindingObservation] = []
    meta = asset.meta or {}
    ref = _ref(asset)
    host = (meta.get("host") or "").lower()
    techs = " ".join(meta.get("technologies") or [])

    if cfg.get("management_interfaces"):
        mgmt = management_interface(meta.get("title"), techs)
        if mgmt:
            remote = mgmt in REMOTE_ACCESS
            out.append(FindingObservation(
                asset=ref, rule_id=f"management-interface:{mgmt.lower().replace(' ', '-')}",
                title=f"{'Remote-access gateway' if remote else 'Administrative interface'} exposed: {mgmt}",
                severity=Severity.MEDIUM if remote else Severity.HIGH, category=FindingCategory.EXPOSURE,
                description=f"The {mgmt} {'login portal' if remote else 'administration interface'} is reachable "
                            f"from the internet at {asset.normalized_value}.",
                remediation="Restrict access to administrative interfaces with network controls, require MFA and "
                            "keep the product patched; remote-access gateways are frequent initial-access targets.",
                evidence={"title": meta.get("title"), "technologies": meta.get("technologies")},
                tags=["panel", "management"], confidence=75))

    if cfg.get("api_documentation") and {t.lower() for t in (meta.get("technologies") or [])} & API_DOC_TECH:
        out.append(FindingObservation(
            asset=ref, rule_id="api-documentation-exposed", title="API documentation publicly exposed",
            severity=Severity.LOW, category=FindingCategory.EXPOSURE,
            description="Interactive API documentation reveals endpoints and parameters to attackers.",
            remediation="Remove public API documentation from production or require authentication.",
            evidence={"technologies": meta.get("technologies")}, tags=["exposure", "api"], confidence=80))

    if cfg.get("weak_tls") and str(meta.get("tls_version") or "").lower() in ("tls10", "tls11", "ssl30", "ssl3"):
        out.append(FindingObservation(
            asset=ref, rule_id="weak-tls-protocol", title=f"Deprecated TLS protocol negotiated ({meta['tls_version']})",
            severity=Severity.MEDIUM, category=FindingCategory.CERTIFICATE,
            description="The service negotiates a deprecated TLS version (TLS 1.0/1.1 or SSL).",
            remediation="Disable TLS 1.0/1.1 and SSL; support TLS 1.2 and 1.3 only.",
            evidence={"tls_version": meta.get("tls_version"), "cipher": meta.get("tls_cipher")},
            tags=["tls"], confidence=90))

    if meta.get("scheme") == "http" and looks_like_login(meta.get("title")) and int(meta.get("status_code") or 0) < 300:
        out.append(FindingObservation(
            asset=ref, rule_id="cleartext-login", title="Login page served over unencrypted HTTP",
            severity=Severity.MEDIUM, category=FindingCategory.MISCONFIGURATION,
            description="Credentials submitted to this page may be intercepted.",
            remediation="Serve the application exclusively over HTTPS and redirect HTTP to HTTPS (with HSTS).",
            evidence={"title": meta.get("title")}, tags=["auth"], confidence=70))

    if cfg.get("certificates") and cert is not None:
        cm = cert.meta or {}
        not_after = _parse_dt(cm.get("not_after"))
        subject = cm.get("subject_cn") or cert.normalized_value[:16]
        if not_after is not None:
            days = (not_after - now).days
            if days < 0:
                out.append(FindingObservation(
                    asset=ref, rule_id="certificate-expired", title=f"Expired TLS certificate ({subject})",
                    severity=Severity.HIGH, category=FindingCategory.CERTIFICATE,
                    description=f"The certificate expired on {not_after.date().isoformat()}.",
                    remediation="Renew the certificate and automate renewal (e.g. ACME).",
                    evidence={"not_after": cm.get("not_after"), "fingerprint": cert.normalized_value},
                    tags=["certificate"], confidence=95))
            elif days <= int(cfg.get("certificate_expiry_days", 30)):
                out.append(FindingObservation(
                    asset=ref, rule_id="certificate-expiring", title=f"TLS certificate expires in {days} day(s)",
                    severity=Severity.MEDIUM if days <= 7 else Severity.LOW, category=FindingCategory.CERTIFICATE,
                    description=f"The certificate for {subject} expires on {not_after.date().isoformat()}.",
                    remediation="Renew the certificate before expiry and automate renewal.",
                    evidence={"not_after": cm.get("not_after"), "days_left": days}, tags=["certificate"],
                    confidence=95))
        if cm.get("self_signed"):
            out.append(FindingObservation(
                asset=ref, rule_id="certificate-self-signed", title="Self-signed TLS certificate",
                severity=Severity.MEDIUM, category=FindingCategory.CERTIFICATE,
                description="Clients cannot authenticate this service; users are trained to click through warnings.",
                remediation="Install a certificate issued by a publicly trusted CA.",
                evidence={"issuer": cm.get("issuer_cn"), "subject": subject}, tags=["certificate"], confidence=90))
        names = list(cm.get("sans") or []) + ([cm["subject_cn"]] if cm.get("subject_cn") else [])
        if host and names and not host.replace(".", "").isdigit() and not _host_matches(host, names):
            out.append(FindingObservation(
                asset=ref, rule_id="certificate-hostname-mismatch", title="TLS certificate does not match hostname",
                severity=Severity.MEDIUM, category=FindingCategory.CERTIFICATE,
                description=f"The certificate presented by {host} is valid for {', '.join(names[:5])}.",
                remediation="Serve a certificate whose subject alternative names include this hostname.",
                evidence={"host": host, "names": names[:20]}, tags=["certificate"], confidence=80))
    return out


def evaluate(db: Session, asset_ids: Iterable[uuid.UUID], cfg: dict[str, Any]) -> SensorResult:
    now = datetime.now(UTC)
    ids = list(set(asset_ids))
    assets: list[Asset] = []
    for i in range(0, len(ids), 1000):
        # Inactive assets are included for coverage (their rule findings resolve) but produce no findings.
        assets += db.execute(select(Asset).where(
            Asset.id.in_(ids[i:i + 1000]), Asset.scope_status != ScopeStatus.OUT_OF_SCOPE,
            Asset.asset_type.in_([AssetType.PORT.value, AssetType.HTTP_ENDPOINT.value]))).scalars().all()

    endpoint_ids = [a.id for a in assets if a.asset_type == AssetType.HTTP_ENDPOINT]
    certs: dict[uuid.UUID, Asset] = {}
    if endpoint_ids:
        rows = db.execute(select(AssetRelationship.source_asset_id, Asset).join(
            Asset, Asset.id == AssetRelationship.target_asset_id).where(
            AssetRelationship.source_asset_id.in_(endpoint_ids),
            AssetRelationship.relation_type == RelationType.PRESENTS_CERTIFICATE,
            AssetRelationship.active.is_(True))).all()
        for src, cert in rows:
            certs[src] = cert

    observations: list[FindingObservation] = []
    for a in assets:
        if a.status != AssetStatus.ACTIVE:
            continue
        if a.asset_type == AssetType.PORT:
            observations += evaluate_port(a, cfg)
        else:
            observations += evaluate_endpoint(a, certs.get(a.id), cfg, now)

    coverage = [FindingCoverage(assets=[_ref(a) for a in assets])] if assets else []
    return SensorResult(adapter=SOURCE, started_at=now, finished_at=now, target_count=len(assets),
                        observations=observations, coverage=coverage)
