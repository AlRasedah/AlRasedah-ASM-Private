"""Advisory ↔ inventory matching. Pure functions over plain data.

Input is what fingerprinting already recorded (technology names with versions
on ``uses_technology`` edges, service products/versions, web-server banners).
Output is one verdict per asset with the evidence that produced it. Nothing
here touches the network or the database.

Verdicts, strongest first when an asset has several observations:

``potentially_affected``  a product name matched and its version is inside an
                          affected range (or the advisory affects every version)
``version_unknown``       a product name matched but no usable version was seen
``not_affected_version``  a product name matched at a version outside every range

A match is never "confirmed" here. Confirmation needs a verified finding
(see ``service.assess``).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from app.models.enums import MatchStatus

from .content import AdvisoryContent, AffectedProduct, norm_name
from .versions import UnparseableVersion, Version, in_range

_RANK = {MatchStatus.POTENTIALLY_AFFECTED: 3, MatchStatus.VERSION_UNKNOWN: 2, MatchStatus.NOT_AFFECTED_VERSION: 1}
MAX_EVIDENCE = 5


@dataclass(frozen=True)
class ProductObservation:
    asset_id: uuid.UUID
    organization_id: uuid.UUID
    name: str  # as reported; normalized when compared
    version: str | None
    source: str  # "technology" | "service" | "web_server"
    observed_at: datetime | None
    # Only a third-party database has reported this (e.g. exposure intelligence), never a live probe.
    third_party: bool = False


@dataclass
class AssetVerdict:
    asset_id: uuid.UUID
    organization_id: uuid.UUID
    status: MatchStatus
    evidence: list[dict[str, Any]] = field(default_factory=list)

    @property
    def third_party_only(self) -> bool:
        return bool(self.evidence) and all(e.get("third_party") for e in self.evidence)


def names_of(content: AdvisoryContent) -> set[str]:
    return {n for p in content.affected for n in p.match_names}


def judge(product: AffectedProduct, version: str | None) -> tuple[MatchStatus, str]:
    """One observation of a matching product → verdict and a human-readable reason."""
    if not product.versions:
        return MatchStatus.POTENTIALLY_AFFECTED, "every version of this product is listed as affected"
    if not version:
        return MatchStatus.VERSION_UNKNOWN, "the product was seen but no version was reported"
    try:
        v = Version.parse(version)
    except UnparseableVersion:
        return MatchStatus.VERSION_UNKNOWN, f"the reported version {version!r} cannot be compared"
    for r in product.versions:
        if in_range(v, introduced=r.introduced, fixed=r.fixed, last_affected=r.last_affected):
            bounds = ", ".join(f"{k} {val}" for k, val in (("from", r.introduced), ("fixed in", r.fixed),
                                                           ("up to", r.last_affected)) if val)
            return MatchStatus.POTENTIALLY_AFFECTED, f"version {version} is inside the affected range ({bounds})"
    return MatchStatus.NOT_AFFECTED_VERSION, f"version {version} is outside every affected range"


def match(content: AdvisoryContent, observations: Iterable[ProductObservation]) -> dict[uuid.UUID, AssetVerdict]:
    by_name: dict[str, AffectedProduct] = {}
    for p in content.affected:
        for n in p.match_names:
            by_name.setdefault(n, p)
    out: dict[uuid.UUID, AssetVerdict] = {}
    for o in observations:
        product = by_name.get(norm_name(o.name))
        if product is None:
            continue
        status, reason = judge(product, o.version)
        ev = {"product": product.product, "vendor": product.vendor, "matched_name": norm_name(o.name),
              "version": o.version, "source": o.source, "verdict": status.value, "reason": reason,
              "observed_at": o.observed_at.isoformat() if o.observed_at else None, "third_party": o.third_party}
        cur = out.get(o.asset_id)
        if cur is None:
            out[o.asset_id] = AssetVerdict(o.asset_id, o.organization_id, status, [ev])
            continue
        if _RANK[status] > _RANK[cur.status]:
            cur.status = status
            cur.evidence.insert(0, ev)
        elif len(cur.evidence) < MAX_EVIDENCE and ev not in cur.evidence:
            cur.evidence.append(ev)
        del cur.evidence[MAX_EVIDENCE:]
    return out
