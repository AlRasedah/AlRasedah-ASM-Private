"""Change detection: compare previous state with a new observation and describe
the security-relevant difference as event drafts.

Pure functions (no database access) so every rule is unit-testable. The
ingestion engine decides *when* to call them and persists the drafts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.enums import ApprovalStatus, AssetType, EventType, Severity

from .knowledge import API_DOC_TECH, management_interface, port_exposure_severity, service_label


@dataclass
class EventDraft:
    event_type: EventType
    severity: Severity
    title: str
    summary: str | None = None
    previous: dict[str, Any] | None = None
    new: dict[str, Any] | None = None
    details: dict[str, Any] = field(default_factory=dict)


def _port_parts(value: str) -> tuple[str, int, str]:
    hostpart, _, rest = value.rpartition(":")
    port, _, proto = rest.partition("/")
    return hostpart.strip("[]"), int(port), proto or "tcp"


# ------------------------------------------------------------------ new asset
def new_asset(asset_type: AssetType, value: str, attrs: dict[str, Any],
              approval: ApprovalStatus = ApprovalStatus.UNVERIFIED) -> EventDraft | None:
    unverified = approval in (ApprovalStatus.UNVERIFIED, ApprovalStatus.UNKNOWN)
    if asset_type == AssetType.SUBDOMAIN:
        return EventDraft(EventType.NEW_SUBDOMAIN, Severity.MEDIUM if unverified else Severity.LOW,
                          f"New subdomain discovered: {value}",
                          "A previously unknown subdomain was discovered. Ownership is unverified until reviewed."
                          if unverified else None, new={"value": value})
    if asset_type == AssetType.DOMAIN:
        return EventDraft(EventType.NEW_ASSET, Severity.MEDIUM, f"New related domain: {value}", new={"value": value})
    if asset_type == AssetType.IP_ADDRESS:
        return EventDraft(EventType.NEW_ASSET, Severity.LOW, f"New IP address: {value}", new={"value": value})
    if asset_type == AssetType.PORT:
        ip, port, proto = _port_parts(value)
        label = service_label(port)
        return EventDraft(EventType.PORT_OPENED, port_exposure_severity(port),
                          f"New externally exposed service: {port}/{proto} on {ip}" + (f" ({label})" if label else ""),
                          new={"ip": ip, "port": port, "protocol": proto, "service": label})
    if asset_type == AssetType.SERVICE:
        ip, port, proto = _port_parts(value)
        product = " ".join(x for x in (attrs.get("product"), attrs.get("version")) if x)
        return EventDraft(EventType.SERVICE_DETECTED, Severity.LOW,
                          f"Service identified on {ip}:{port}/{proto}: {attrs.get('name') or 'unknown'}"
                          + (f" ({product})" if product else ""),
                          new={k: attrs.get(k) for k in ("name", "product", "version") if attrs.get(k)})
    if asset_type == AssetType.HTTP_ENDPOINT:
        mgmt = management_interface(attrs.get("title"), " ".join(attrs.get("technologies") or []))
        sev = Severity.HIGH if mgmt else Severity.MEDIUM
        return EventDraft(EventType.ASSET_EXPOSED, sev,
                          f"New web service exposed: {value}" + (f" ({mgmt})" if mgmt else ""),
                          new={k: attrs.get(k) for k in ("status_code", "title", "webserver") if attrs.get(k) is not None},
                          details={"management_interface": mgmt} if mgmt else {})
    if asset_type == AssetType.CERTIFICATE:
        return EventDraft(EventType.NEW_ASSET, Severity.INFO,
                          f"New TLS certificate observed: {attrs.get('subject_cn') or value[:16]}",
                          new={k: attrs.get(k) for k in ("subject_cn", "issuer_cn", "not_after") if attrs.get(k)})
    if asset_type == AssetType.CLOUD_RESOURCE:
        return EventDraft(EventType.NEW_ASSET, Severity.MEDIUM, f"New cloud resource: {value}", new={"value": value})
    if asset_type in (AssetType.ASN, AssetType.CIDR):
        return EventDraft(EventType.NEW_ASSET, Severity.INFO, f"New network: {value}", new={"value": value})
    return None


# ---------------------------------------------------------- attribute changes
def _ips(dns: dict[str, list[str]] | None) -> list[str]:
    dns = dns or {}
    return sorted(set(dns.get("a", [])) | set(dns.get("aaaa", [])))


def attribute_changes(asset_type: AssetType, value: str, old: dict[str, Any], new: dict[str, Any]) -> list[EventDraft]:
    out: list[EventDraft] = []
    if asset_type in (AssetType.ROOT_DOMAIN, AssetType.DOMAIN, AssetType.SUBDOMAIN):
        old_dns, new_dns = old.get("dns"), new.get("dns")
        if old_dns is not None and new_dns is not None:
            old_ips, new_ips = _ips(old_dns), _ips(new_dns)
            if old_ips != new_ips:
                out.append(EventDraft(
                    EventType.IP_CHANGED, Severity.MEDIUM, f"IP address changed for {value}",
                    f"{', '.join(old_ips) or 'none'} → {', '.join(new_ips) or 'none'}",
                    previous={"ips": old_ips}, new={"ips": new_ips},
                    details={"added": sorted(set(new_ips) - set(old_ips)), "removed": sorted(set(old_ips) - set(new_ips))}))
            changed = {}
            for rtype in sorted((set(old_dns) | set(new_dns)) - {"a", "aaaa"}):
                before, after = sorted(old_dns.get(rtype, [])), sorted(new_dns.get(rtype, []))
                if before != after:
                    changed[rtype] = {"previous": before, "current": after}
            if changed:
                out.append(EventDraft(
                    EventType.DNS_CHANGED, Severity.LOW, f"DNS records changed for {value}",
                    ", ".join(f"{k.upper()} record" for k in changed) + " changed",
                    previous={k: v["previous"] for k, v in changed.items()},
                    new={k: v["current"] for k, v in changed.items()}))
    elif asset_type == AssetType.SERVICE:
        before = (old.get("product"), old.get("version"))
        after = (new.get("product"), new.get("version"))
        if old.get("product") and new.get("product") and before != after:
            same_product = before[0] == after[0]
            out.append(EventDraft(
                EventType.SERVICE_CHANGED, Severity.MEDIUM,
                (f"Service version changed on {value}: {before[0]} {before[1] or '?'} → {after[1] or '?'}"
                 if same_product else f"Service changed on {value}: {before[0]} → {after[0]}"),
                previous={"product": before[0], "version": before[1]},
                new={"product": after[0], "version": after[1]}))
    elif asset_type == AssetType.IP_ADDRESS:
        if old.get("asn") and new.get("asn") and old["asn"] != new["asn"]:
            out.append(EventDraft(
                EventType.HOSTING_CHANGED, Severity.MEDIUM, f"{value} moved to a different network",
                f"{old['asn']} ({old.get('as_name') or '?'}) → {new['asn']} ({new.get('as_name') or '?'})",
                previous={"asn": old["asn"], "as_name": old.get("as_name")},
                new={"asn": new["asn"], "as_name": new.get("as_name")}))
    elif asset_type == AssetType.HTTP_ENDPOINT:
        if old.get("tls_version") and new.get("tls_version") and old["tls_version"] != new["tls_version"]:
            out.append(EventDraft(
                EventType.SERVICE_CHANGED, Severity.LOW, f"TLS protocol changed on {value}",
                previous={"tls_version": old["tls_version"]}, new={"tls_version": new["tls_version"]}))
    return out


# ------------------------------------------------------- disappear/reappear
def disappeared(asset_type: AssetType, value: str, meta: dict[str, Any]) -> EventDraft:
    if asset_type == AssetType.PORT:
        ip, port, proto = _port_parts(value)
        return EventDraft(EventType.PORT_CLOSED, Severity.LOW, f"Port closed: {port}/{proto} on {ip}",
                          previous={"state": "open"}, new={"state": "closed"})
    if asset_type in (AssetType.SUBDOMAIN, AssetType.ROOT_DOMAIN, AssetType.DOMAIN):
        return EventDraft(EventType.ASSET_DISAPPEARED, Severity.LOW, f"{value} no longer resolves",
                          previous={"dns": meta.get("dns")}, new={"resolves": False})
    if asset_type == AssetType.HTTP_ENDPOINT:
        return EventDraft(EventType.ASSET_DISAPPEARED, Severity.LOW, f"Web service no longer reachable: {value}",
                          previous={"status_code": meta.get("status_code")}, new={"reachable": False})
    return EventDraft(EventType.ASSET_DISAPPEARED, Severity.INFO, f"{asset_type.value.replace('_', ' ').capitalize()} "
                      f"no longer observed: {value}")


def reappeared(asset_type: AssetType, value: str) -> EventDraft:
    if asset_type == AssetType.PORT:
        ip, port, proto = _port_parts(value)
        return EventDraft(EventType.PORT_OPENED, port_exposure_severity(port),
                          f"Port re-opened: {port}/{proto} on {ip}", previous={"state": "closed"}, new={"state": "open"})
    return EventDraft(EventType.ASSET_REAPPEARED, Severity.LOW, f"Asset observed again: {value}")


# ------------------------------------------------------------- relationships
def technology_added(endpoint: str, tech_name: str, version: str | None) -> EventDraft:
    mgmt = management_interface(tech_name)
    api_docs = tech_name.lower() in API_DOC_TECH
    sev = Severity.MEDIUM if (mgmt or api_docs) else Severity.LOW
    label = f"{tech_name} {version}" if version else tech_name
    return EventDraft(EventType.TECHNOLOGY_DETECTED, sev, f"Technology detected on {endpoint}: {label}",
                      new={"technology": tech_name, "version": version},
                      details={"management_interface": mgmt} if mgmt else {})


def technology_version_changed(endpoint: str, tech_name: str, old: str | None, new: str | None) -> EventDraft:
    return EventDraft(EventType.TECHNOLOGY_CHANGED, Severity.LOW,
                      f"{tech_name} version changed on {endpoint}: {old or '?'} → {new or '?'}",
                      previous={"version": old}, new={"version": new})


def technology_removed(endpoint: str, tech_name: str) -> EventDraft:
    return EventDraft(EventType.TECHNOLOGY_REMOVED, Severity.INFO, f"Technology no longer detected on {endpoint}: {tech_name}",
                      previous={"technology": tech_name})


def certificate_changed(endpoint: str, old_cert: dict[str, Any], new_cert: dict[str, Any]) -> EventDraft:
    keys = ("fingerprint", "subject_cn", "issuer_cn", "not_after")
    issuer_changed = old_cert.get("issuer_cn") != new_cert.get("issuer_cn")
    return EventDraft(EventType.CERTIFICATE_CHANGED, Severity.MEDIUM if issuer_changed else Severity.LOW,
                      f"TLS certificate changed on {endpoint}",
                      "Issuer changed" if issuer_changed else "Certificate renewed or replaced",
                      previous={k: old_cert.get(k) for k in keys}, new={k: new_cert.get(k) for k in keys})


# --------------------------------------------------------------------- risk
RISK_EVENT_DELTA = 10
_LEVELS = ["info", "low", "medium", "high", "critical"]


def risk_changed(value: str, old_score: int, new_score: int, old_level: str, new_level: str,
                 factors: list[dict[str, Any]]) -> EventDraft | None:
    up = new_score - old_score
    level_up = _LEVELS.index(new_level) > _LEVELS.index(old_level)
    level_down = _LEVELS.index(new_level) < _LEVELS.index(old_level)
    if up >= RISK_EVENT_DELTA or level_up:
        sev = Severity.HIGH if new_level in ("high", "critical") else Severity.MEDIUM
        top = sorted(factors, key=lambda f: -abs(f.get("points", 0)))[:3]
        return EventDraft(EventType.RISK_INCREASED, sev, f"Risk score increased for {value}: {old_score} → {new_score}",
                          ", ".join(f["label"] for f in top) if top else None,
                          previous={"score": old_score, "level": old_level}, new={"score": new_score, "level": new_level})
    if level_down:
        return EventDraft(EventType.RISK_DECREASED, Severity.INFO, f"Risk score decreased for {value}: {old_score} → {new_score}",
                          previous={"score": old_score, "level": old_level}, new={"score": new_score, "level": new_level})
    return None


# ------------------------------------------------------------ certificates
EXPIRY_THRESHOLDS = (30, 14, 7, 1)


def certificate_expiry(value: str, subject: str | None, days_left: int, already: list[int]) -> tuple[EventDraft, int] | None:
    """Return (event, threshold) for the tightest newly crossed threshold."""
    if days_left < 0:
        if -1 in already:
            return None
        return EventDraft(EventType.CERTIFICATE_EXPIRED, Severity.HIGH, f"TLS certificate expired: {subject or value[:16]}",
                          new={"days_left": days_left}), -1
    crossed = [t for t in EXPIRY_THRESHOLDS if days_left <= t and t not in already]
    if not crossed:
        return None
    t = min(crossed)
    sev = Severity.HIGH if t <= 7 else Severity.MEDIUM
    return EventDraft(EventType.CERTIFICATE_EXPIRING, sev,
                      f"TLS certificate for {subject or value[:16]} expires in {days_left} day(s)",
                      new={"days_left": days_left}), t
