"""Build each pipeline stage's targets from the current inventory.

Stages feed each other through the database rather than through the previous
sensor's raw output: DNS resolution re-checks *every* known in-scope
hostname (not just new ones), port discovery covers every in-scope/derived IP,
and so on. That is what makes disappearance detection possible.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from asm_sensors.targets import InvalidTarget, Target, TargetKind, format_host_port, split_host_port
from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, aliased

from app.assets.normalization import parse_port_value
from app.models import Asset, AssetRelationship, Organization, Scan, ScopeEntry
from app.models.enums import (
    HOSTNAME_TYPES,
    AssetStatus,
    AssetType,
    RelationType,
    ScopeEntryType,
    ScopeStatus,
    StageType,
)
from app.tenants.settings import org_settings

# Non-HTTP services that are pointless to probe with an HTTP fingerprinter.
NON_HTTP_PORTS = {21, 22, 23, 25, 53, 110, 111, 135, 139, 143, 389, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049,
                  3306, 3389, 5432, 5900, 5901, 6379, 9042, 11211, 27017, 27018}
REVISIT_INACTIVE_DAYS = 30


@dataclass
class StageTargets:
    targets: list[Target] = field(default_factory=list)
    # ip -> hostnames resolving to it (for derived-scope authorization)
    derived_from: dict[str, set[str]] = field(default_factory=dict)
    invalid: list[str] = field(default_factory=list)


def _t(kind: TargetKind, value: str, out: StageTargets) -> None:
    try:
        out.targets.append(Target(kind=kind, value=value))
    except (InvalidTarget, ValidationError, ValueError):
        out.invalid.append(value)


def _hostnames(db: Session, org: Organization, include_recent_inactive: bool = True) -> list[Asset]:
    q = select(Asset).where(Asset.organization_id == org.id,
                            Asset.asset_type.in_([t.value for t in HOSTNAME_TYPES]),
                            Asset.scope_status == ScopeStatus.IN_SCOPE)
    rows = db.execute(q).scalars().all()
    cutoff = datetime.now(UTC) - timedelta(days=REVISIT_INACTIVE_DAYS)
    return [a for a in rows if a.status == AssetStatus.ACTIVE or (include_recent_inactive and a.last_seen >= cutoff)]


def _resolution_map(db: Session, org: Organization) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """(ip -> in-scope hostnames, hostname -> ips) from active resolves_to relations."""
    src, dst = aliased(Asset), aliased(Asset)
    rows = db.execute(
        select(src.normalized_value, dst.normalized_value)
        .select_from(AssetRelationship)
        .join(src, src.id == AssetRelationship.source_asset_id)
        .join(dst, dst.id == AssetRelationship.target_asset_id)
        .where(AssetRelationship.organization_id == org.id, AssetRelationship.active.is_(True),
               AssetRelationship.relation_type == RelationType.RESOLVES_TO,
               src.scope_status == ScopeStatus.IN_SCOPE, dst.status == AssetStatus.ACTIVE)).all()
    ip_to_hosts: dict[str, set[str]] = defaultdict(set)
    host_to_ips: dict[str, set[str]] = defaultdict(set)
    for host, ip in rows:
        ip_to_hosts[ip].add(host)
        host_to_ips[host].add(ip)
    return ip_to_hosts, host_to_ips


def _open_ports(db: Session, org: Organization) -> dict[str, set[int]]:
    ports: dict[str, set[int]] = defaultdict(set)
    for (value,) in db.execute(select(Asset.normalized_value).where(
            Asset.organization_id == org.id, Asset.asset_type == AssetType.PORT,
            Asset.status == AssetStatus.ACTIVE)):
        p = parse_port_value(value)
        if p and p[2] == "tcp":
            ports[p[0]].add(p[1])
    return ports


def _override(scan: Scan) -> tuple[set[str], dict[str, set[int]]]:
    """The hosts a scan was limited to, and any ports named with them.

    "Limit to specific targets" takes `example.com`, `192.0.2.1`, `example.com:8580`
    or a URL. Stages select by host, so a `host:port` entry contributes its host to
    the filter *and* records the port, which the HTTP stages then use instead of
    whatever the port sweep happened to find.
    """
    hosts: set[str] = set()
    ports: dict[str, set[int]] = defaultdict(set)
    for raw in scan.target_override or []:
        if "://" in raw:
            u = urlsplit(raw)
            if u.hostname:
                hosts.add(u.hostname)
                ports[u.hostname].add(u.port or (443 if u.scheme == "https" else 80))
            continue
        try:
            host, port = split_host_port(raw)
        except InvalidTarget:
            hosts.add(raw)
            continue
        hosts.add(host)
        ports[host].add(port)
    return hosts, dict(ports)


def build_targets(db: Session, org: Organization, scan: Scan, stage_type: StageType, limit: int,
                  *, crawled_pages: bool = False) -> StageTargets:
    out = StageTargets()
    override, override_ports = _override(scan)
    entries = db.execute(select(ScopeEntry).where(ScopeEntry.organization_id == org.id,
                                                  ScopeEntry.is_exclusion.is_(False))).scalars().all()
    settings = org_settings(org)

    if stage_type in (StageType.SUBDOMAIN_DISCOVERY, StageType.OSINT_ENRICHMENT):
        for e in entries:
            if e.entry_type == ScopeEntryType.DOMAIN and (not override or e.value in override):
                _t(TargetKind.DOMAIN, e.value, out)

    elif stage_type == StageType.DNS_RESOLUTION:
        names = {a.normalized_value for a in _hostnames(db, org)}
        names |= {e.value for e in entries if e.entry_type == ScopeEntryType.DOMAIN}
        if override:
            names = {n for n in names if n in override or any(n.endswith("." + o) for o in override)}
        for n in sorted(names):
            _t(TargetKind.HOSTNAME, n, out)

    elif stage_type == StageType.IP_ENRICHMENT:
        out.derived_from, _ = _resolution_map(db, org)
        for (ip,) in db.execute(select(Asset.normalized_value).where(
                Asset.organization_id == org.id, Asset.asset_type == AssetType.IP_ADDRESS,
                Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE)):
            _t(TargetKind.IP, ip, out)

    elif stage_type == StageType.PORT_DISCOVERY:
        ip_to_hosts, _ = _resolution_map(db, org)
        out.derived_from = ip_to_hosts
        for e in entries:
            if e.entry_type == ScopeEntryType.IP:
                _t(TargetKind.IP, e.value, out)
            elif e.entry_type == ScopeEntryType.CIDR:
                _t(TargetKind.CIDR, e.value, out)
        seen = {t.value for t in out.targets}
        rows = db.execute(select(Asset).where(
            Asset.organization_id == org.id, Asset.asset_type == AssetType.IP_ADDRESS,
            Asset.status == AssetStatus.ACTIVE, Asset.scope_status == ScopeStatus.DERIVED)).scalars().all()
        for a in rows:
            if a.normalized_value in seen:
                continue
            if settings.get("skip_cdn_ips", True) and (a.meta or {}).get("cdn"):
                continue
            if override and a.normalized_value not in override and not (ip_to_hosts.get(a.normalized_value, set()) & override):
                continue
            _t(TargetKind.IP, a.normalized_value, out)

    elif stage_type == StageType.HTTP_DISCOVERY:
        ip_to_hosts, host_to_ips = _resolution_map(db, org)
        out.derived_from = ip_to_hosts
        ports = _open_ports(db, org)
        values: set[tuple[TargetKind, str]] = set()
        # A port the user named is probed as given: the sweep may not cover it (the DAST
        # profile scans the "web" set only), and the host may not be in inventory yet.
        for host, named in override_ports.items():
            values |= {(TargetKind.HOST_PORT, format_host_port(host, p)) for p in named}
        for a in _hostnames(db, org, include_recent_inactive=False):
            host = a.normalized_value
            if override and host not in override:
                continue
            if host in override_ports:  # already added exactly as asked for
                continue
            host_ports = set().union(*(ports.get(ip, set()) for ip in host_to_ips.get(host, set()))) \
                if host_to_ips.get(host) else set()
            web = sorted(p for p in host_ports if p not in NON_HTTP_PORTS)
            if web:
                values |= {(TargetKind.HOST_PORT, format_host_port(host, p)) for p in web}
            else:
                values.add((TargetKind.HOSTNAME, host))
        # IPs in scope (or derived) that expose ports but have no in-scope name.
        for ip, ip_ports in ports.items():
            if ip in ip_to_hosts:
                continue
            for p in sorted(ip_ports - NON_HTTP_PORTS):
                values.add((TargetKind.HOST_PORT, format_host_port(ip, p)))
        for e in entries:
            if e.entry_type == ScopeEntryType.IP and e.value not in ports:
                values.add((TargetKind.IP, e.value))
        # Re-probe known endpoints so disappearance is detected even without port data.
        for (url,) in db.execute(select(Asset.normalized_value).where(
                Asset.organization_id == org.id, Asset.asset_type == AssetType.HTTP_ENDPOINT,
                Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE)):
            u = urlsplit(url)
            if u.hostname and (not override or u.hostname in override):
                port = u.port or (443 if u.scheme == "https" else 80)
                if u.hostname in override_ports and port not in override_ports[u.hostname]:
                    continue  # the user named a port on this host; leave its other ports alone
                values.add((TargetKind.HOST_PORT, format_host_port(u.hostname, port)))
        for kind, v in sorted(values):
            _t(kind, v, out)

    elif stage_type in (StageType.WEB_CRAWL, StageType.VULNERABILITY_DETECTION):
        # Both crawl and active vulnerability detection operate on the known web
        # endpoints (in-scope or derived, active); disappearance is handled by the
        # http_discovery stage re-probing them.
        ip_to_hosts, _ = _resolution_map(db, org)
        out.derived_from = ip_to_hosts
        for asset in db.execute(select(Asset).where(
                Asset.organization_id == org.id, Asset.asset_type == AssetType.HTTP_ENDPOINT,
                Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE)).scalars():
            url = asset.normalized_value
            u = urlsplit(url)
            if override and u.hostname not in override:
                continue
            named = override_ports.get(u.hostname or "")
            if named and (u.port or (443 if u.scheme == "https" else 80)) not in named:
                continue  # crawl and attack only the port the user asked for
            _t(TargetKind.URL, url, out)
            # A scanner that tests request parameters needs the pages a crawl found, not
            # just this origin; they are recorded on the endpoint by the web_crawl stage.
            if crawled_pages:
                for page in (asset.meta or {}).get("crawled_pages") or []:
                    if len(out.targets) >= limit:
                        break
                    _t(TargetKind.URL, url + str(page), out)

    if len(out.targets) > limit:
        out.targets = out.targets[:limit]
    return out
