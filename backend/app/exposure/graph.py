"""External exposure map: a bounded neighbourhood of *observed* relationships.

    Domain → IP address → Port / service → Web endpoint → Finding

This is an exposure map, not attack-path analysis. Every edge is a relationship
the platform recorded (a DNS answer, an open port, an HTTP response) or derived
from names (``subdomain_of``); nothing is inferred from shared IPs, certificates or
hosting, and no edge means "an attacker can move from here to there".

Bounds, all enforced here rather than trusted to the caller:

* one organization per request (the starting asset's), inside the caller's tenant
  session (RLS), and every relationship filtered to that organization;
* breadth-first to at most ``depth`` hops, with a visited set (cycles end there);
* at most ``per_node`` neighbours fetched per node and level (a window function in
  PostgreSQL, so a domain with 5 000 subdomains returns 25 rows plus a count), the
  rest reported as ``hidden`` for progressive expansion;
* total node and edge caps, a statement timeout and a wall-clock budget; hitting any
  of them returns a partial map that says why.
"""

from __future__ import annotations

import time
import uuid
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from asm_sensors.registry import adapter_names, get_adapter
from sqlalchemy import func, select, text, union_all
from sqlalchemy.orm import Session

from app.core.errors import NotFound, ValidationFailed
from app.models import Asset, AssetRelationship, Finding, Organization
from app.models.enums import (
    OPEN_FINDING_STATES,
    AssetStatus,
    AssetType,
    RelationType,
    ScopeStatus,
)
from app.schemas.common import source_label

EXPOSURE_RELATIONS = (RelationType.SUBDOMAIN_OF, RelationType.CNAME, RelationType.RESOLVES_TO, RelationType.HAS_PORT,
                      RelationType.RUNS_SERVICE, RelationType.SERVES, RelationType.HOSTED_ON, RelationType.REDIRECTS_TO)
CONTEXT_RELATIONS = (RelationType.USES_TECHNOLOGY, RelationType.PRESENTS_CERTIFICATE, RelationType.HOSTED_BY)
CONTEXT_TYPES = (AssetType.TECHNOLOGY, AssetType.CERTIFICATE, AssetType.CLOUD_RESOURCE, AssetType.ASN)
# Relationships the platform derives from names or patterns rather than observing on the wire.
DERIVED_RELATIONS = (RelationType.SUBDOMAIN_OF, RelationType.HOSTED_BY)

MEANING: dict[str, str] = {
    "subdomain_of": "Naming: this host name is under the domain. Derived from the names, not a network connection.",
    "cname": "DNS: this name is an alias (CNAME) of the other name.",
    "resolves_to": "DNS: this name resolved to this IP address.",
    "has_port": "Network: this port was found open on the IP address.",
    "runs_service": "Network: this service was identified on the port.",
    "serves": "Web: this host or address answered HTTP(S) at this endpoint.",
    "hosted_on": "Web: this endpoint was served from this IP address.",
    "redirects_to": "Web: this endpoint redirected to the other.",
    "uses_technology": "Fingerprint: this technology was detected on the endpoint.",
    "presents_certificate": "TLS: the endpoint presented this certificate.",
    "hosted_by": "Naming: the name matches this cloud or hosting provider's pattern.",
    "has_finding": "A finding recorded on this asset (see its detail page for evidence).",
}

LIMITS = {"depth": (1, 4), "max_nodes": (10, 300), "per_node": (5, 100)}
MAX_EDGES_FACTOR = 3  # edges ≤ 3 × nodes
TIME_BUDGET_S = 4.0
STATEMENT_TIMEOUT_MS = 3000
STALE_AFTER = timedelta(days=14)
FINDINGS_PER_ASSET = 3
MAX_ROOTS = 10


@dataclass
class MapParams:
    organization_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    expand: uuid.UUID | None = None
    depth: int = 2
    max_nodes: int = 150
    per_node: int = 25
    include_inactive: bool = False
    include_findings: bool = True
    include_unverified: bool = False
    include_context: bool = False

    def validate(self) -> MapParams:
        for name, (lo, hi) in LIMITS.items():
            v = getattr(self, name)
            if not isinstance(v, int) or not lo <= v <= hi:
                raise ValidationFailed(f"{name} must be between {lo} and {hi}")
        if not (self.organization_id or self.asset_id or self.expand):
            raise ValidationFailed("Choose an organization or a starting asset")
        return self

    def key(self) -> tuple:
        return tuple(getattr(self, f) for f in self.__dataclass_fields__)


@dataclass
class _Build:
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    edges: dict[str, dict[str, Any]] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def note(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)


def _historical_sources() -> frozenset[str]:
    return frozenset(n for n in adapter_names() if get_adapter(n).historical)


def _freshness(active: bool, last_seen: datetime | None, source: str | None, now: datetime,
               historical: frozenset[str]) -> str:
    if not active:
        return "inactive"
    if source in historical:
        return "historical"
    if last_seen is None or now - last_seen > STALE_AFTER:
        return "stale"
    return "current"


def _asset_node(a: Asset, depth: int, historical: frozenset[str]) -> dict[str, Any]:
    sources = set(a.sources or [])
    return {
        "id": str(a.id), "kind": "asset", "type": a.asset_type.value, "label": a.value[:300],
        "status": a.status.value, "scope_status": a.scope_status.value, "risk_score": a.risk_score,
        "open_findings": a.open_findings, "first_seen": a.first_seen.isoformat(), "last_seen": a.last_seen.isoformat(),
        # Known only from a third-party database's record (e.g. exposure intelligence).
        "third_party_only": bool(sources) and sources <= historical, "depth": depth, "hidden": {},
    }


def _edge(r: AssetRelationship, now: datetime, historical: frozenset[str]) -> dict[str, Any]:
    rel = r.relation_type.value
    derived = r.relation_type in DERIVED_RELATIONS
    return {
        "id": str(r.id), "source": str(r.source_asset_id), "target": str(r.target_asset_id), "relation": rel,
        "meaning": MEANING.get(rel, rel.replace("_", " ")), "active": r.active,
        "evidence": "derived" if derived else "observed",
        # Capability label only — never the engine that recorded it (ADR-022).
        "source_label": "Platform (from names)" if derived else (source_label(r.source) or "Scan"),
        "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat(),
        "age_days": max(0, (now - r.last_seen).days), "freshness": _freshness(r.active, r.last_seen, r.source, now,
                                                                              historical),
    }


def _neighbours(db: Session, org_id: uuid.UUID, frontier: list[uuid.UUID], relations: list[str], p: MapParams):
    """Up to ``per_node`` relationships per frontier node (both directions), newest active first,
    plus the total per node and relation so the caller can say what it left out."""
    conds = [AssetRelationship.organization_id == org_id, AssetRelationship.relation_type.in_(relations)]
    if not p.include_inactive:
        conds.append(AssetRelationship.active.is_(True))
    parts = []
    for anchor, other in ((AssetRelationship.source_asset_id, AssetRelationship.target_asset_id),
                          (AssetRelationship.target_asset_id, AssetRelationship.source_asset_id)):
        parts.append(select(
            AssetRelationship.id.label("rid"), anchor.label("anchor"), other.label("other"),
            AssetRelationship.relation_type.label("relation"),
            func.row_number().over(partition_by=anchor, order_by=(AssetRelationship.active.desc(),
                                                                 AssetRelationship.last_seen.desc())).label("rn"),
        ).where(anchor.in_(frontier), *conds))
    both = union_all(*parts).subquery()
    ranked = select(both.c.rid, both.c.anchor, both.c.other).where(both.c.rn <= p.per_node)
    rows = db.execute(ranked).all()
    totals = db.execute(select(both.c.anchor, both.c.relation, func.count()).group_by(both.c.anchor,
                                                                                     both.c.relation)).all()
    return rows, totals


def build(db: Session, p: MapParams, *, findings_allowed: bool) -> dict[str, Any]:
    """The map for the caller's tenant session. Raises NotFound for anything invisible to it."""
    p.validate()
    started = time.monotonic()
    now = datetime.now(UTC)
    historical = _historical_sources()
    db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))

    start_id = p.expand or p.asset_id
    start: Asset | None = db.get(Asset, start_id) if start_id else None
    if start_id and start is None:
        raise NotFound("Asset not found")
    org_id = start.organization_id if start else p.organization_id
    if p.organization_id and org_id != p.organization_id:
        raise NotFound("Asset not found")  # the organization boundary is explicit
    org = db.get(Organization, org_id)
    if org is None:
        raise NotFound("Organization not found")

    relations = [r.value for r in EXPOSURE_RELATIONS] + ([r.value for r in CONTEXT_RELATIONS]
                                                         if p.include_context else [])
    b = _Build()
    max_edges = p.max_nodes * MAX_EDGES_FACTOR
    if start is not None:
        roots = [start]
    else:
        q = select(Asset).where(Asset.organization_id == org.id, Asset.asset_type == AssetType.ROOT_DOMAIN)
        if not p.include_inactive:
            q = q.where(Asset.status == AssetStatus.ACTIVE)
        roots = list(db.execute(q.order_by(Asset.risk_score.desc(), Asset.value).limit(MAX_ROOTS + 1)).scalars())
        if not roots:  # scope without domains: start from the highest-risk in-scope assets
            roots = list(db.execute(select(Asset).where(
                Asset.organization_id == org.id, Asset.scope_status == ScopeStatus.IN_SCOPE,
                Asset.status == AssetStatus.ACTIVE, Asset.asset_type.not_in([t.value for t in CONTEXT_TYPES]))
                .order_by(Asset.risk_score.desc()).limit(MAX_ROOTS + 1)).scalars())
        if len(roots) > MAX_ROOTS:
            roots = roots[:MAX_ROOTS]
            b.note(f"only the {MAX_ROOTS} highest-risk starting points are shown; pick an asset to focus")
    for a in roots:
        b.nodes[str(a.id)] = _asset_node(a, 0, historical)

    depth_limit = 1 if p.expand else p.depth
    frontier = [a.id for a in roots]
    for depth in range(1, depth_limit + 1):
        if not frontier:
            break
        if time.monotonic() - started > TIME_BUDGET_S:
            b.note("time limit reached")
            break
        rows, totals = _neighbours(db, org.id, frontier, relations, p)
        shown: dict[tuple[str, str], int] = defaultdict(int)
        other_ids = {r.other for r in rows}
        others = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_(other_ids))).scalars()} \
            if other_ids else {}
        rels = {r.id: r for r in db.execute(select(AssetRelationship).where(
            AssetRelationship.id.in_({r.rid for r in rows}))).scalars()} if rows else {}
        next_frontier: list[uuid.UUID] = []
        for rid, anchor, other in rows:
            o = others.get(other)
            rel = rels.get(rid)
            if o is None or rel is None:
                continue
            if not p.include_context and o.asset_type in CONTEXT_TYPES:
                continue
            if not p.include_inactive and o.status != AssetStatus.ACTIVE:
                continue
            key = str(o.id)
            if key not in b.nodes:
                if len(b.nodes) >= p.max_nodes:
                    b.note("node limit reached")
                    continue
                b.nodes[key] = _asset_node(o, depth, historical)
                next_frontier.append(o.id)
            if str(rid) not in b.edges:
                if len(b.edges) >= max_edges:
                    b.note("edge limit reached")
                    continue
                b.edges[str(rid)] = _edge(rel, now, historical)
            # Shown for this anchor whether it was drawn now or from its other end earlier
            # (a cycle reaches the same edge twice); only undrawn edges count as hidden.
            shown[(str(anchor), rel.relation_type.value)] += 1
        for anchor, relation, total in totals:
            name = getattr(relation, "value", relation)
            hidden = total - shown.get((str(anchor), name), 0)
            node = b.nodes.get(str(anchor))
            if node is not None and hidden > 0:
                node["hidden"][name] = hidden
        frontier = next_frontier
    if frontier and depth_limit and not p.expand:
        # Nodes on the outer ring may have more; say so without querying further.
        for aid in frontier:
            b.nodes[str(aid)]["more_beyond_depth"] = True

    if p.include_findings and findings_allowed:
        _add_findings(db, b, p, max_edges)
    hidden = sum(sum(n["hidden"].values()) for n in b.nodes.values())
    if hidden:
        b.note(f"{hidden} more relationships are not shown (nodes marked +N); expand a node to load them")

    elapsed = round((time.monotonic() - started) * 1000)
    return {
        "organization": {"id": str(org.id), "name": org.name},
        "root_ids": [str(a.id) for a in roots], "expanded": str(p.expand) if p.expand else None,
        "nodes": list(b.nodes.values()), "edges": list(b.edges.values()),
        "truncated": bool(b.reasons), "truncation_reasons": b.reasons,
        "limits": {"depth": depth_limit, "max_nodes": p.max_nodes, "max_edges": max_edges, "per_node": p.per_node,
                   "time_budget_ms": int(TIME_BUDGET_S * 1000)},
        "elapsed_ms": elapsed,
        "notice": "Observed relationships only. A line never means one asset can be used to reach another.",
    }


def _add_findings(db: Session, b: _Build, p: MapParams, max_edges: int) -> None:
    asset_ids = [uuid.UUID(k) for k, n in b.nodes.items() if n["kind"] == "asset"]
    if not asset_ids:
        return
    conds = [Finding.asset_id.in_(asset_ids), Finding.status.in_([s.value for s in OPEN_FINDING_STATES])]
    if not p.include_unverified:
        conds.append(Finding.unverified.is_(False))
    ranked = select(Finding.id, Finding.asset_id, func.row_number().over(
        partition_by=Finding.asset_id, order_by=(Finding.risk_score.desc(), Finding.last_seen.desc())).label("rn"),
        func.count().over(partition_by=Finding.asset_id).label("total")).where(*conds).subquery()
    picked = db.execute(select(ranked.c.id, ranked.c.asset_id, ranked.c.total)
                        .where(ranked.c.rn <= FINDINGS_PER_ASSET)).all()
    findings = {f.id: f for f in db.execute(select(Finding).where(Finding.id.in_([r.id for r in picked]))).scalars()} \
        if picked else {}
    for fid, aid, total in picked:
        f = findings.get(fid)
        if f is None:
            continue
        if len(b.nodes) >= p.max_nodes:
            b.note("node limit reached")
            break
        key = f"f:{fid}"
        b.nodes[key] = {"id": key, "kind": "finding", "finding_id": str(fid), "type": "finding",
                        "label": f.title[:300], "severity": f.severity.value, "status": f.status.value,
                        "unverified": f.unverified, "risk_score": f.risk_score,
                        "first_seen": f.first_seen.isoformat(), "last_seen": f.last_seen.isoformat(),
                        "depth": b.nodes[str(aid)]["depth"] + 1, "hidden": {}}
        if len(b.edges) < max_edges:
            b.edges[f"hf:{fid}"] = {
                "id": f"hf:{fid}", "source": str(aid), "target": key, "relation": "has_finding",
                "meaning": MEANING["has_finding"], "active": True,
                "evidence": "unverified report" if f.unverified else "observed",
                "source_label": source_label(f.source) or "Scan", "first_seen": f.first_seen.isoformat(),
                "last_seen": f.last_seen.isoformat(), "age_days": max(0, (datetime.now(UTC) - f.last_seen).days),
                "freshness": "unverified" if f.unverified else "current"}
        if total > FINDINGS_PER_ASSET:
            b.nodes[str(aid)]["hidden"]["has_finding"] = total - FINDINGS_PER_ASSET


# ------------------------------------------------------------------------ cache
class _TTLCache:
    """Small in-process cache. Keys always carry the tenant and the caller's authorization
    context, so one tenant's (or role's) map can never answer another's request."""

    def __init__(self, ttl: float = 30.0, size: int = 128) -> None:
        self.ttl, self.size = ttl, size
        self._d: OrderedDict[tuple, tuple[float, dict[str, Any]]] = OrderedDict()

    def get(self, key: tuple) -> dict[str, Any] | None:
        hit = self._d.get(key)
        if hit is None or time.monotonic() - hit[0] > self.ttl:
            self._d.pop(key, None)
            return None
        self._d.move_to_end(key)
        return hit[1]

    def put(self, key: tuple, value: dict[str, Any]) -> None:
        self._d[key] = (time.monotonic(), value)
        self._d.move_to_end(key)
        while len(self._d) > self.size:
            self._d.popitem(last=False)

    def clear(self) -> None:
        self._d.clear()


cache = _TTLCache()


def cached_build(db: Session, p: MapParams, *, tenant_id: uuid.UUID, role: str, findings_allowed: bool
                 ) -> dict[str, Any]:
    key = ("exposure-map", str(tenant_id), role, findings_allowed, p.validate().key())
    hit = cache.get(key)
    if hit is not None:
        return {**hit, "cached": True}
    out = build(db, p, findings_allowed=findings_allowed)
    cache.put(key, out)
    return {**out, "cached": False}


__all__ = ["MapParams", "build", "cached_build", "cache", "MEANING"]
