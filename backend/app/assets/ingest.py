"""Ingestion engine: apply a :class:`SensorResult` to the inventory.

For one sensor run this module

1. normalizes every observation to a canonical ``(asset_type, value)``;
2. decides each asset's scope status (in scope / derived / out of scope) and
   drops unrelated third-party noise;
3. creates or updates assets, preserving ``first_seen`` and history;
4. upserts relationships and de-duplicated findings;
5. applies *coverage* to detect what disappeared (ports closed, hosts gone,
   technologies removed, vulnerabilities resolved);
6. records change events via :mod:`app.changes.detector`.

Everything happens in the caller's transaction, serialized per organization
with an advisory lock so concurrent scans of one organization never race.
"""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from asm_sensors.observations import (
    AssetObservation,
    FindingCoverage,
    FindingObservation,
    LivenessCoverage,
    ObservedType,
    RelationCoverage,
    RelationObservation,
    RelationType,
    SensorResult,
)
from asm_sensors.ports import port_in_spec
from asm_sensors.targets import Target, TargetKind
from sqlalchemy import select, text, tuple_
from sqlalchemy.orm import Session

from app.assets import cloud
from app.assets.normalization import (
    HOSTNAME_ASSET_TYPES,
    asset_type_for,
    normalize_value,
    parent_domain,
    parse_port_value,
)
from app.changes import detector
from app.changes.detector import EventDraft
from app.findings import service as findings_service
from app.models import Asset, AssetEvent, AssetRelationship, Organization
from app.models import AssetObservation as AssetObservationRow
from app.models.enums import ApprovalStatus, AssetStatus, AssetType, ScopeStatus
from app.scope.checker import ScopeChecker
from app.tenants.settings import inactivity_threshold

log = logging.getLogger(__name__)

AKey = tuple[AssetType, str]
OKey = tuple[ObservedType, str]

CONTEXT_TYPES = {AssetType.TECHNOLOGY, AssetType.CERTIFICATE, AssetType.ASN, AssetType.CIDR,
                 AssetType.CLOUD_RESOURCE, AssetType.DNS_RECORD, AssetType.WEB_APPLICATION}
APPROVED_BY_DEFAULT = {AssetType.TECHNOLOGY, AssetType.CERTIFICATE, AssetType.ASN, AssetType.DNS_RECORD}
# Children whose existence depends on their parent (cascade deactivation).
OWNED_CHILDREN: dict[AssetType, list[tuple[RelationType, AssetType]]] = {
    AssetType.SUBDOMAIN: [(RelationType.SERVES, AssetType.HTTP_ENDPOINT)],
    AssetType.ROOT_DOMAIN: [(RelationType.SERVES, AssetType.HTTP_ENDPOINT)],
    AssetType.DOMAIN: [(RelationType.SERVES, AssetType.HTTP_ENDPOINT)],
    AssetType.IP_ADDRESS: [(RelationType.HAS_PORT, AssetType.PORT), (RelationType.SERVES, AssetType.HTTP_ENDPOINT)],
    AssetType.PORT: [(RelationType.RUNS_SERVICE, AssetType.SERVICE)],
}
LIVENESS_TYPES = {AssetType.PORT, AssetType.SERVICE, AssetType.HTTP_ENDPOINT}
_RANK = {ScopeStatus.OUT_OF_SCOPE: 0, ScopeStatus.DERIVED: 1, ScopeStatus.IN_SCOPE: 2}


@dataclass
class IngestContext:
    tenant_id: uuid.UUID
    organization: Organization
    source: str
    checker: ScopeChecker
    now: datetime
    settings: dict[str, Any]
    discovery_method: str | None = None
    scan_id: uuid.UUID | None = None
    stage_id: uuid.UUID | None = None
    baseline: bool = False
    # The source reports what it last saw (e.g. Shodan), not a live check: new
    # knowledge is recorded, but liveness (last_seen, reactivation, miss counters)
    # is never refreshed from it, and its findings are kept unverified.
    historical: bool = False


@dataclass
class IngestResult:
    stats: Counter = field(default_factory=Counter)
    touched: set[uuid.UUID] = field(default_factory=set)
    events: list[AssetEvent] = field(default_factory=list)


def _threshold_key(t: AssetType) -> str:
    return t.value


class Ingestor:
    def __init__(self, db: Session, ctx: IngestContext) -> None:
        self.db = db
        self.ctx = ctx
        self.roots = ctx.checker.root_domains
        self.result = IngestResult()
        self.assets: dict[AKey, Asset] = {}
        self.observed: set[AKey] = set()
        self.new_keys: set[AKey] = set()
        self.status: dict[AKey, ScopeStatus | None] = {}
        self.observed_rels: set[tuple[uuid.UUID, uuid.UUID, RelationType]] = set()
        self.deactivated: set[uuid.UUID] = set()

    # ------------------------------------------------------------ utilities
    def _akey(self, t: ObservedType, value: str) -> AKey | None:
        norm = normalize_value(t, value)
        if norm is None:
            return None
        return asset_type_for(t, norm, self.roots), norm

    def _event(self, asset: Asset | None, draft: EventDraft, finding_id: uuid.UUID | None = None) -> None:
        if asset is not None and asset.scope_status == ScopeStatus.OUT_OF_SCOPE:
            return
        ev = AssetEvent(
            tenant_id=self.ctx.tenant_id, organization_id=self.ctx.organization.id,
            asset_id=asset.id if asset else None, asset_type=asset.asset_type if asset else None,
            asset_value=asset.value if asset else None, finding_id=finding_id, scan_id=self.ctx.scan_id,
            event_type=draft.event_type, severity=draft.severity, title=draft.title[:512], summary=draft.summary,
            previous_state=draft.previous, new_state=draft.new, details=draft.details,
            occurred_at=self.ctx.now, is_baseline=self.ctx.baseline,
        )
        self.db.add(ev)
        self.result.events.append(ev)
        self.result.stats["events"] += 1

    def _load(self, keys: set[AKey]) -> None:
        missing = [k for k in keys if k not in self.assets]
        for i in range(0, len(missing), 500):
            chunk = missing[i:i + 500]
            rows = self.db.execute(select(Asset).where(
                Asset.organization_id == self.ctx.organization.id,
                tuple_(Asset.asset_type, Asset.normalized_value).in_([(t.value, v) for t, v in chunk]),
            )).scalars().all()
            for a in rows:
                self.assets[(a.asset_type, a.normalized_value)] = a

    def _find_hostname(self, value: str) -> Asset | None:
        for t in HOSTNAME_ASSET_TYPES:
            a = self.assets.get((t, value))
            if a:
                return a
        a = self.db.execute(select(Asset).where(
            Asset.organization_id == self.ctx.organization.id, Asset.normalized_value == value,
            Asset.asset_type.in_([t.value for t in HOSTNAME_ASSET_TYPES]))).scalars().first()
        if a:
            self.assets[(a.asset_type, a.normalized_value)] = a
        return a

    def _existing_status(self, key: AKey) -> ScopeStatus | None:
        a = self.assets.get(key)
        return a.scope_status if a else None

    # -------------------------------------------------------- scope status
    def _ip_status(self, ip: str) -> ScopeStatus:
        key = (AssetType.IP_ADDRESS, ip)
        if key in self.status and self.status[key] is not None:
            return self.status[key]  # type: ignore[return-value]
        s, _ = self.ctx.checker.ip_status(ip)
        if s == ScopeStatus.OUT_OF_SCOPE and not self.ctx.checker.is_excluded_ip(ip):
            existing = self._existing_status(key)
            if existing and existing != ScopeStatus.OUT_OF_SCOPE:
                s = existing
        return s

    def _host_status(self, host: str) -> ScopeStatus:
        if normalize_value(ObservedType.IP_ADDRESS, host):
            return self._ip_status(host)
        return self.ctx.checker.hostname_status(host)[0]

    def _endpoint_host(self, url: str) -> str | None:
        from urllib.parse import urlsplit

        try:
            return urlsplit(url).hostname
        except ValueError:
            return None

    def _compute_statuses(self, keys: set[AKey], rels: list[tuple[AKey, RelationType, AKey, dict]]) -> None:
        for key in keys:
            t, v = key
            if t in HOSTNAME_ASSET_TYPES:
                self.status[key] = self.ctx.checker.hostname_status(v)[0]
            elif t == AssetType.IP_ADDRESS:
                self.status[key] = self._ip_status(v)
            elif t == AssetType.CIDR:
                try:
                    d = self.ctx.checker.check(Target(kind=TargetKind.CIDR, value=v), active=False)
                    self.status[key] = ScopeStatus.IN_SCOPE if d.allowed else None
                except ValueError:  # e.g. a very large announced prefix: context only
                    self.status[key] = None
            else:
                self.status[key] = None
        # IPs resolved from / hosting in-scope names are derived.
        for src, rel, dst, _ in rels:
            if dst[0] == AssetType.IP_ADDRESS and self.status.get(dst) == ScopeStatus.OUT_OF_SCOPE \
                    and not self.ctx.checker.is_excluded_ip(dst[1]):
                if rel == RelationType.RESOLVES_TO and self.status.get(src) == ScopeStatus.IN_SCOPE:
                    self.status[dst] = ScopeStatus.DERIVED
                elif rel == RelationType.HOSTED_ON and src[0] == AssetType.HTTP_ENDPOINT:
                    host = self._endpoint_host(src[1])
                    if host and self._host_status(host) == ScopeStatus.IN_SCOPE:
                        self.status[dst] = ScopeStatus.DERIVED
        # Dependent types inherit from their host.
        for key in keys:
            t, v = key
            if t in (AssetType.PORT, AssetType.SERVICE):
                parsed = parse_port_value(v)
                self.status[key] = self._ip_status(parsed[0]) if parsed else None
            elif t == AssetType.HTTP_ENDPOINT:
                host = self._endpoint_host(v)
                self.status[key] = self._host_status(host) if host else None
        # Context types and out-of-scope neighbours are kept only when attached to our assets.
        adjacency: dict[AKey, set[AKey]] = {}
        for src, _, dst, _ in rels:
            adjacency.setdefault(src, set()).add(dst)
            adjacency.setdefault(dst, set()).add(src)

        def anchored(k: AKey) -> bool:
            return self.status.get(k) in (ScopeStatus.IN_SCOPE, ScopeStatus.DERIVED)

        for _ in range(3):
            changed = False
            for key in keys:
                if anchored(key):
                    continue
                neighbours = adjacency.get(key, set())
                if key[0] in CONTEXT_TYPES:
                    existing = self._existing_status(key)
                    if any(anchored(n) for n in neighbours) or (existing and existing != ScopeStatus.OUT_OF_SCOPE):
                        self.status[key] = ScopeStatus.DERIVED
                        changed = True
            if not changed:
                break
        for key in keys:
            if self.status.get(key) == ScopeStatus.OUT_OF_SCOPE:
                if not any(anchored(n) for n in adjacency.get(key, set())):
                    self.status[key] = None  # unrelated third-party noise: drop

    # --------------------------------------------------------------- assets
    def _default_approval(self, t: AssetType, v: str, status: ScopeStatus) -> ApprovalStatus:
        if status == ScopeStatus.OUT_OF_SCOPE:
            return ApprovalStatus.THIRD_PARTY
        if t in APPROVED_BY_DEFAULT:
            return ApprovalStatus.APPROVED
        if t == AssetType.ROOT_DOMAIN:
            return ApprovalStatus.APPROVED
        if t in (AssetType.IP_ADDRESS, AssetType.CIDR) and status == ScopeStatus.IN_SCOPE:
            return ApprovalStatus.APPROVED
        return ApprovalStatus.UNVERIFIED

    def _apply_asset(self, key: AKey, attrs: dict[str, Any], confidence: int, observed: bool) -> Asset | None:
        status = self.status.get(key)
        if status is None:
            return None
        t, v = key
        now = self.ctx.now
        asset = self.assets.get(key)
        attrs = self._enrich(t, attrs)
        if asset is None:
            asset = Asset(
                tenant_id=self.ctx.tenant_id, organization_id=self.ctx.organization.id, asset_type=t, value=v,
                normalized_value=v, status=AssetStatus.ACTIVE, scope_status=status, first_seen=now, last_seen=now,
                discovered_at=now, last_scanned_at=now, source=self.ctx.source, sources=[self.ctx.source],
                discovery_method=self.ctx.discovery_method, confidence=confidence,
                approval_status=self._default_approval(t, v, status), meta=dict(attrs), tags=[], risk_factors=[],
            )
            self.db.add(asset)
            self.db.flush()
            self.assets[key] = asset
            self.new_keys.add(key)
            self.result.stats["new_assets"] += 1
            draft = detector.new_asset(t, v, attrs, asset.approval_status)
            if draft:
                self._event(asset, draft)
        else:
            if observed:
                old_meta = dict(asset.meta or {})
                if asset.status == AssetStatus.ACTIVE and attrs:
                    for draft in detector.attribute_changes(t, v, old_meta, attrs):
                        self._event(asset, draft)
                if attrs:
                    merged = dict(old_meta)
                    merged.update(attrs)
                    asset.meta = merged
                if self.ctx.source not in (asset.sources or []):
                    asset.sources = [*(asset.sources or []), self.ctx.source][-20:]
                if self.ctx.historical:
                    # Third-party sighting of unknown age: enrich, but never claim
                    # the asset is alive now or bring an inactive one back.
                    self.result.stats["updated_assets"] += 1
                else:
                    asset.last_seen = now
                    asset.missed_count = 0
                    asset.confidence = max(asset.confidence, confidence)
                    if asset.status == AssetStatus.INACTIVE:
                        asset.status = AssetStatus.ACTIVE
                        asset.inactive_since = None
                        self.result.stats["reactivated"] += 1
                        self._event(asset, detector.reappeared(t, v))
                    else:
                        self.result.stats["updated_assets"] += 1
            if t in HOSTNAME_ASSET_TYPES or t == AssetType.IP_ADDRESS:
                if asset.scope_status != status and not (t == AssetType.IP_ADDRESS and status == ScopeStatus.OUT_OF_SCOPE
                                                         and asset.scope_status == ScopeStatus.DERIVED):
                    asset.scope_status = status
            elif _RANK[status] > _RANK[asset.scope_status]:
                asset.scope_status = status
        if not self.ctx.historical:
            asset.last_scanned_at = now
        self.result.touched.add(asset.id)
        if observed:
            self.observed.add(key)
        return asset

    def _enrich(self, t: AssetType, attrs: dict[str, Any]) -> dict[str, Any]:
        if t == AssetType.IP_ADDRESS and attrs.get("asn"):
            p = cloud.provider_for_asn(attrs["asn"])
            if p:
                attrs = {**attrs, "hosting_provider": p[0], "hosting_kind": p[1]}
                if p[0] in cloud.CDN_PROVIDERS:
                    attrs["cdn"] = True
        return attrs

    # ------------------------------------------------------------ relations
    def _upsert_relations(self, rels: list[tuple[AKey, RelationType, AKey, dict]]) -> None:
        pairs = [(self.assets.get(s), r, self.assets.get(d), a) for s, r, d, a in rels]
        pairs = [(s, r, d, a) for s, r, d, a in pairs if s is not None and d is not None and s.id != d.id]
        if not pairs:
            return
        src_ids = {s.id for s, _, _, _ in pairs}
        existing: dict[tuple[uuid.UUID, uuid.UUID, RelationType], AssetRelationship] = {}
        ids = list(src_ids)
        for i in range(0, len(ids), 1000):
            for r in self.db.execute(select(AssetRelationship).where(
                    AssetRelationship.source_asset_id.in_(ids[i:i + 1000]))).scalars():
                existing[(r.source_asset_id, r.target_asset_id, r.relation_type)] = r
        by_source_rel: dict[tuple[uuid.UUID, RelationType], list[AssetRelationship]] = {}
        for r in existing.values():
            by_source_rel.setdefault((r.source_asset_id, r.relation_type), []).append(r)

        now = self.ctx.now
        for src, rel, dst, attrs in pairs:
            key = (src.id, dst.id, rel)
            if key in self.observed_rels:
                continue
            self.observed_rels.add(key)
            r = existing.get(key)
            if r is not None:
                if rel == RelationType.USES_TECHNOLOGY:
                    old_v, new_v = (r.attributes or {}).get("version"), attrs.get("version")
                    if old_v and new_v and old_v != new_v:
                        self._event(src, detector.technology_version_changed(
                            src.value, dst.meta.get("name") or dst.value, old_v, new_v))
                if not r.active:
                    r.active = True
                    if rel == RelationType.USES_TECHNOLOGY:
                        self._event(src, detector.technology_added(src.value, dst.meta.get("name") or dst.value,
                                                                   attrs.get("version")))
                if not self.ctx.historical:  # see IngestContext.historical
                    r.last_seen = now
                    r.missed_count = 0
                if attrs:
                    r.attributes = {**(r.attributes or {}), **attrs}
                continue
            r = AssetRelationship(tenant_id=self.ctx.tenant_id, organization_id=self.ctx.organization.id,
                                  source_asset_id=src.id, target_asset_id=dst.id, relation_type=rel, active=True,
                                  missed_count=0, first_seen=now, last_seen=now, source=self.ctx.source,
                                  attributes=dict(attrs))
            self.db.add(r)
            existing[key] = r
            by_source_rel.setdefault((src.id, rel), []).append(r)
            self.result.stats["new_relationships"] += 1
            if rel == RelationType.USES_TECHNOLOGY:
                self._event(src, detector.technology_added(src.value, dst.meta.get("name") or dst.value,
                                                           attrs.get("version")))
            elif rel == RelationType.PRESENTS_CERTIFICATE:
                for other in by_source_rel.get((src.id, rel), []):
                    if other is r or not other.active or \
                            (other.source_asset_id, other.target_asset_id, other.relation_type) in self.observed_rels:
                        continue
                    old_cert = self.db.get(Asset, other.target_asset_id)
                    other.active = False
                    if old_cert is not None:
                        self._event(src, detector.certificate_changed(
                            src.value, {"fingerprint": old_cert.value, **(old_cert.meta or {})},
                            {"fingerprint": dst.value, **(dst.meta or {})}))
        self.db.flush()

    def _structural_relations(self, keys: set[AKey]) -> list[tuple[AKey, RelationType, AKey, dict]]:
        """Platform-derived relations: subdomain_of parents and cloud hosting."""
        out: list[tuple[AKey, RelationType, AKey, dict]] = []
        for t, v in list(keys):
            if t == AssetType.SUBDOMAIN and self.status.get((t, v)) == ScopeStatus.IN_SCOPE:
                parent = parent_domain(v, self.roots)
                if parent:
                    pa = self._find_hostname(parent)
                    if pa is not None:
                        out.append(((t, v), RelationType.SUBDOMAIN_OF, (pa.asset_type, pa.normalized_value), {}))
        return out

    def _cloud_relations(self, rels: list[tuple[AKey, RelationType, AKey, dict]], keys: set[AKey]) -> list:
        extra: list[tuple[AKey, RelationType, AKey, dict]] = []
        candidates: list[tuple[AKey, str]] = []
        for src, rel, dst, _ in rels:
            if rel == RelationType.CNAME and dst[0] in HOSTNAME_ASSET_TYPES:
                candidates.append((src, dst[1]))
        for key in keys:
            if key[0] in HOSTNAME_ASSET_TYPES and self.status.get(key) == ScopeStatus.IN_SCOPE:
                candidates.append((key, key[1]))
        for owner, host in candidates:
            m = cloud.match_hostname(host)
            if not m or self.status.get(owner) not in (ScopeStatus.IN_SCOPE, ScopeStatus.DERIVED):
                continue
            ckey = (AssetType.CLOUD_RESOURCE, cloud.resource_value(m))
            self.status[ckey] = ScopeStatus.DERIVED
            self._load({ckey})
            self._apply_asset(ckey, {"provider": m.provider, "service": m.service, "kind": m.kind,
                                     "hostname": m.resource}, 70, observed=True)
            extra.append((owner, RelationType.HOSTED_BY, ckey, {}))
        return extra

    # -------------------------------------------------------------- coverage
    def _deactivate(self, asset: Asset, emit: bool = True) -> None:
        if asset.status == AssetStatus.INACTIVE or asset.id in self.deactivated:
            return
        self.deactivated.add(asset.id)
        asset.status = AssetStatus.INACTIVE
        asset.inactive_since = self.ctx.now
        self.result.stats["deactivated"] += 1
        self.result.touched.add(asset.id)
        if emit and asset.asset_type not in CONTEXT_TYPES:
            self._event(asset, detector.disappeared(asset.asset_type, asset.value, asset.meta or {}))
        for ch in findings_service.resolve_for_inactive_asset(self.db, asset, self.ctx.now, self.ctx.scan_id):
            self.result.stats["resolved_findings"] += 1
            if ch.event:
                self._event(asset, ch.event, ch.finding.id)
        for rel_type, child_type in OWNED_CHILDREN.get(asset.asset_type, []):
            rows = self.db.execute(
                select(AssetRelationship, Asset).join(Asset, Asset.id == AssetRelationship.target_asset_id).where(
                    AssetRelationship.source_asset_id == asset.id, AssetRelationship.relation_type == rel_type,
                    AssetRelationship.active.is_(True), Asset.asset_type == child_type,
                    Asset.status == AssetStatus.ACTIVE)).all()
            for rel, child in rows:
                rel.active = False
                if (child.asset_type, child.normalized_value) in self.observed:
                    continue
                if child.asset_type == AssetType.HTTP_ENDPOINT and self._has_other_presence(child, asset.id):
                    continue
                self._deactivate(child, emit=False)

    def _has_incoming(self, child: Asset, relation_types: tuple[RelationType, ...]) -> bool:
        return self.db.execute(select(AssetRelationship.id).where(
            AssetRelationship.target_asset_id == child.id, AssetRelationship.active.is_(True),
            AssetRelationship.relation_type.in_([r.value for r in relation_types])).limit(1)).first() is not None

    def _has_other_presence(self, child: Asset, except_parent: uuid.UUID) -> bool:
        return self.db.execute(select(AssetRelationship.id).where(
            AssetRelationship.target_asset_id == child.id, AssetRelationship.active.is_(True),
            AssetRelationship.source_asset_id != except_parent,
            AssetRelationship.relation_type == RelationType.SERVES).limit(1)).first() is not None

    def _missed(self, asset: Asset) -> None:
        key = (asset.asset_type, asset.normalized_value)
        if key in self.observed or asset.status != AssetStatus.ACTIVE:
            return
        asset.missed_count = (asset.missed_count or 0) + 1
        self.result.stats["missed"] += 1
        if asset.missed_count >= inactivity_threshold(self.ctx.settings, _threshold_key(asset.asset_type)):
            self._deactivate(asset)

    def _resolve_parents(self, parent_type: ObservedType, values: list[str], cidrs: list[str] | None = None) -> list[Asset]:
        found: list[Asset] = []
        norms = [n for n in (normalize_value(parent_type, v) for v in values) if n]
        if parent_type == ObservedType.HOSTNAME:
            types = [t.value for t in HOSTNAME_ASSET_TYPES]
        else:
            types = [parent_type.value]
        for i in range(0, len(norms), 1000):
            found += self.db.execute(select(Asset).where(
                Asset.organization_id == self.ctx.organization.id, Asset.asset_type.in_(types),
                Asset.normalized_value.in_(norms[i:i + 1000]))).scalars().all()
        if cidrs:
            import ipaddress

            nets = [ipaddress.ip_network(c, strict=False) for c in cidrs]
            ips = self.db.execute(select(Asset).where(
                Asset.organization_id == self.ctx.organization.id, Asset.asset_type == AssetType.IP_ADDRESS,
                Asset.status == AssetStatus.ACTIVE)).scalars().all()
            seen = {a.id for a in found}
            for a in ips:
                addr = ipaddress.ip_address(a.normalized_value)
                if a.id not in seen and any(addr.version == n.version and addr in n for n in nets):
                    found.append(a)
        return found

    @staticmethod
    def _child_port(child: Asset) -> int | None:
        if child.asset_type in (AssetType.PORT, AssetType.SERVICE):
            p = parse_port_value(child.normalized_value)
            return p[1] if p else None
        if child.asset_type == AssetType.HTTP_ENDPOINT:
            if (child.meta or {}).get("port"):
                return int(child.meta["port"])
            from urllib.parse import urlsplit

            u = urlsplit(child.normalized_value)
            return u.port or (443 if u.scheme == "https" else 80)
        return None

    def _apply_relation_coverage(self, cov: RelationCoverage) -> None:
        parents = self._resolve_parents(cov.parent_type, cov.parents, cov.constraints.get("parent_cidrs"))
        if not parents:
            return
        child_types = ([t.value for t in HOSTNAME_ASSET_TYPES] if cov.child_type == ObservedType.HOSTNAME
                       else [cov.child_type.value])
        spec = cov.constraints.get("port_spec")
        cdn_spec = cov.constraints.get("cdn_port_spec")
        rel_threshold = inactivity_threshold(self.ctx.settings, "relation")
        parent_by_id = {p.id: p for p in parents}
        for p in parents:
            p.last_scanned_at = self.ctx.now
        ids = list(parent_by_id)
        for i in range(0, len(ids), 1000):
            rows = self.db.execute(
                select(AssetRelationship, Asset).join(Asset, Asset.id == AssetRelationship.target_asset_id).where(
                    AssetRelationship.source_asset_id.in_(ids[i:i + 1000]),
                    AssetRelationship.relation_type == cov.relation, AssetRelationship.active.is_(True),
                    Asset.asset_type.in_(child_types))).all()
            for rel, child in rows:
                if (rel.source_asset_id, rel.target_asset_id, rel.relation_type) in self.observed_rels:
                    continue
                parent = parent_by_id[rel.source_asset_id]
                if spec:
                    port = self._child_port(child)
                    effective = cdn_spec if (cdn_spec and (parent.meta or {}).get("cdn")) else spec
                    if port is None or not port_in_spec(port, effective):
                        continue
                rel.missed_count = (rel.missed_count or 0) + 1
                if rel.missed_count >= rel_threshold:
                    rel.active = False
                    if rel.relation_type == RelationType.USES_TECHNOLOGY:
                        self._event(parent, detector.technology_removed(parent.value,
                                                                        (child.meta or {}).get("name") or child.value))
                    elif rel.relation_type == RelationType.RESOLVES_TO and child.asset_type == AssetType.IP_ADDRESS \
                            and child.scope_status == ScopeStatus.DERIVED \
                            and (child.asset_type, child.normalized_value) not in self.observed \
                            and not self._has_incoming(child, (RelationType.RESOLVES_TO, RelationType.HOSTED_ON)):
                        # No in-scope name points here any more: the address left the attack surface.
                        self._deactivate(child)
                if child.asset_type in LIVENESS_TYPES:
                    self._missed(child)

    def _apply_liveness(self, cov: LivenessCoverage) -> None:
        for asset in self._resolve_parents(cov.asset_type, cov.values):
            asset.last_scanned_at = self.ctx.now
            self._missed(asset)

    def _apply_finding_coverage(self, cov: FindingCoverage, observed_findings: dict[uuid.UUID, set[uuid.UUID]]) -> None:
        asset_ids: list[uuid.UUID] = []
        for ref in cov.assets:
            key = self._akey(ref.type, ref.value)
            if key is None:
                continue
            self._load({key})
            a = self.assets.get(key)
            if a is not None:
                asset_ids.append(a.id)
        observed_ids = set().union(*observed_findings.values()) if observed_findings else set()
        for ch in findings_service.resolve_unobserved(
                self.db, tenant_id=self.ctx.tenant_id, asset_ids=asset_ids, source=self.ctx.source, coverage=cov,
                observed_ids=observed_ids, threshold=inactivity_threshold(self.ctx.settings, "finding"),
                now=self.ctx.now, scan_id=self.ctx.scan_id):
            self.result.stats["resolved_findings"] += 1
            asset = self.db.get(Asset, ch.finding.asset_id)
            if ch.event:
                self._event(asset, ch.event, ch.finding.id)

    # ----------------------------------------------------------------- main
    def ingest(self, result: SensorResult) -> IngestResult:
        self.db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                        {"k": f"ingest:{self.ctx.organization.id}"})

        asset_obs: dict[AKey, tuple[dict[str, Any], int]] = {}
        rels: list[tuple[AKey, RelationType, AKey, dict]] = []
        finding_obs: list[tuple[AKey, FindingObservation]] = []
        all_keys: set[AKey] = set()

        for o in result.observations:
            if isinstance(o, AssetObservation):
                key = self._akey(o.type, o.value)
                if key is None:
                    self.result.stats["invalid_observations"] += 1
                    continue
                attrs, conf = asset_obs.get(key, ({}, 0))
                attrs.update({k: v for k, v in o.attributes.items() if v is not None})
                asset_obs[key] = (attrs, max(conf, o.confidence))
                all_keys.add(key)
            elif isinstance(o, RelationObservation):
                s, d = self._akey(o.source.type, o.source.value), self._akey(o.target.type, o.target.value)
                if s and d:
                    rels.append((s, o.relation, d, dict(o.attributes)))
                    all_keys |= {s, d}
            elif isinstance(o, FindingObservation):
                k = self._akey(o.asset.type, o.asset.value)
                if k:
                    finding_obs.append((k, o))
                    all_keys.add(k)

        # Load existing assets for everything referenced, plus implied hosts.
        implied: set[AKey] = set()
        for t, v in all_keys:
            if t in (AssetType.PORT, AssetType.SERVICE):
                p = parse_port_value(v)
                if p:
                    implied.add((AssetType.IP_ADDRESS, p[0]))
        self._load(all_keys | implied)
        self._compute_statuses(all_keys, rels)

        for key in sorted(all_keys, key=lambda k: list(AssetType).index(k[0])):
            attrs, conf = asset_obs.get(key, ({}, 80))
            self._apply_asset(key, attrs, conf, observed=key in asset_obs)

        rels = rels + self._structural_relations(all_keys) + self._cloud_relations(rels, all_keys)
        self._upsert_relations(rels)

        observed_findings: dict[uuid.UUID, set[uuid.UUID]] = {}
        for key, fo in finding_obs:
            asset = self.assets.get(key)
            if asset is None or asset.scope_status == ScopeStatus.OUT_OF_SCOPE:
                continue
            ch = findings_service.upsert_observation(
                self.db, tenant_id=self.ctx.tenant_id, organization_id=self.ctx.organization.id, asset=asset,
                obs=fo, source=self.ctx.source, now=self.ctx.now, scan_id=self.ctx.scan_id,
                unverified=self.ctx.historical or "unverified" in fo.tags)
            observed_findings.setdefault(asset.id, set()).add(ch.finding.id)
            self.result.stats["findings"] += 1
            if ch.event:
                if ch.event.event_type.value == "vulnerability_detected":
                    self.result.stats["new_findings"] += 1
                self._event(asset, ch.event, ch.finding.id)

        for cov in result.coverage:
            if isinstance(cov, LivenessCoverage):
                self._apply_liveness(cov)
            elif isinstance(cov, RelationCoverage):
                self._apply_relation_coverage(cov)
            elif isinstance(cov, FindingCoverage):
                self._apply_finding_coverage(cov, observed_findings)

        for key in asset_obs:
            asset = self.assets.get(key)
            if asset is not None:
                self.db.add(AssetObservationRow(
                    tenant_id=self.ctx.tenant_id, asset_id=asset.id, scan_id=self.ctx.scan_id,
                    stage_id=self.ctx.stage_id, source=self.ctx.source, observed_at=self.ctx.now,
                    data=asset_obs[key][0]))
                self.result.stats["observations"] += 1
        self.db.flush()
        return self.result
