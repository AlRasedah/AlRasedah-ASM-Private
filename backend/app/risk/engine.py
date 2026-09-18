"""Risk scoring.

Risk is *not* CVSS. A finding's score combines

    technical severity + exploitability (KEV, EPSS, public exploits)
    + exposure (internet-facing, management interfaces, auth surfaces, risky ports)
    + business criticality + threat context (shadow IT, new assets, age)

scaled by detection confidence and clamped to 0–100. Every contribution is
stored as a factor so analysts can see *why* a score was assigned. Weights are
configurable per tenant (``settings.risk``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from app.changes.knowledge import RISKY_PORTS, looks_like_login, management_interface
from app.models.enums import ApprovalStatus, AssetType, RiskLevel, ScopeStatus


class FindingLike(Protocol):
    severity: Any
    cvss_score: float | None
    epss_score: float | None
    kev: bool
    exploit_available: bool
    confidence: int
    first_seen: datetime
    tags: list[str]
    category: Any


class AssetLike(Protocol):
    asset_type: AssetType
    normalized_value: str
    criticality: Any
    approval_status: ApprovalStatus
    scope_status: ScopeStatus
    first_seen: datetime
    meta: dict[str, Any]


@dataclass
class RiskResult:
    score: int
    level: RiskLevel
    factors: list[dict[str, Any]] = field(default_factory=list)


def level_for(score: int, cfg: dict[str, Any]) -> RiskLevel:
    lv = cfg["levels"]
    if score >= lv["critical"]:
        return RiskLevel.CRITICAL
    if score >= lv["high"]:
        return RiskLevel.HIGH
    if score >= lv["medium"]:
        return RiskLevel.MEDIUM
    if score >= lv["low"]:
        return RiskLevel.LOW
    return RiskLevel.INFO


def _v(x: Any) -> str:
    return getattr(x, "value", x)


def _port_of(asset: AssetLike) -> int | None:
    if asset.asset_type in (AssetType.PORT, AssetType.SERVICE):
        try:
            return int(asset.normalized_value.rsplit(":", 1)[1].split("/")[0])
        except (IndexError, ValueError):
            return None
    return None


def exposure_factors(asset: AssetLike, cfg: dict[str, Any], now: datetime) -> list[tuple[str, str, float]]:
    """Factors describing the asset's exposure and business context."""
    out: list[tuple[str, str, float]] = []
    meta = asset.meta or {}
    if asset.scope_status in (ScopeStatus.IN_SCOPE, ScopeStatus.DERIVED):
        out.append(("exposure", "Internet-facing asset", cfg["exposure_points"]))
    mgmt = meta.get("management_interface") or management_interface(meta.get("title"),
                                                                      " ".join(meta.get("technologies") or []))
    if mgmt:
        out.append(("management_interface", f"Exposed administrative interface ({mgmt})",
                    cfg["management_interface_points"]))
    elif asset.asset_type == AssetType.HTTP_ENDPOINT and looks_like_login(meta.get("title")):
        out.append(("auth_exposure", "Exposed authentication surface", cfg["auth_exposure_points"]))
    port = _port_of(asset)
    if port in RISKY_PORTS:
        out.append(("risky_port", f"High-risk service exposed ({RISKY_PORTS[port][0]})", cfg["risky_port_points"]))
    crit = _v(asset.criticality)
    pts = cfg["criticality_points"].get(crit, 0)
    if pts:
        out.append(("criticality", f"Business criticality: {crit}", pts))
    approval = _v(asset.approval_status)
    if approval == ApprovalStatus.UNAUTHORIZED.value:
        out.append(("unauthorized", "Asset marked unauthorized", cfg["unauthorized_points"]))
    elif approval in (ApprovalStatus.UNVERIFIED.value, ApprovalStatus.UNKNOWN.value):
        out.append(("shadow_it", "Unknown ownership (potential shadow IT)", cfg["shadow_it_points"]))
    if (now - asset.first_seen).days < cfg["new_asset_days"]:
        out.append(("new_asset", "Recently discovered asset", cfg["new_asset_points"]))
    return out


def score_finding(f: FindingLike, asset: AssetLike, cfg: dict[str, Any], now: datetime) -> RiskResult:
    factors: list[tuple[str, str, float]] = []
    sev = _v(f.severity)
    sev_pts = float(cfg["severity_points"].get(sev, 0))
    label = f"Technical severity: {sev}"
    if f.cvss_score is not None and f.cvss_score * 5.5 > sev_pts:
        sev_pts = f.cvss_score * 5.5
        label = f"CVSS {f.cvss_score:.1f}"
    factors.append(("severity", label, sev_pts))

    if f.kev:
        factors.append(("kev", "Known exploited in the wild (CISA KEV)", cfg["kev_points"]))
    elif f.exploit_available:
        factors.append(("exploit", "Public exploit available", cfg["exploit_points"]))
    if f.epss_score:
        pts = round(f.epss_score * cfg["epss_max_points"], 1)
        if pts >= 1:
            factors.append(("epss", f"Exploit prediction (EPSS {f.epss_score:.0%})", pts))

    factors += exposure_factors(asset, cfg, now)
    if "panel" in (f.tags or []) and not any(k == "management_interface" for k, _, _ in factors):
        factors.append(("management_interface", "Administrative panel", cfg["management_interface_points"]))

    age_days = (now - f.first_seen).days
    if age_days >= 30:
        pts = min(cfg["age_max_points"], (age_days // 30) * cfg["age_points_per_30_days"])
        factors.append(("age", f"Unresolved for {age_days} days", pts))

    total = sum(p for _, _, p in factors)
    conf = max(0, min(100, f.confidence or 100))
    if conf < 100:
        mult = 0.6 + 0.4 * conf / 100
        factors.append(("confidence", f"Detection confidence {conf}%", round(total * (mult - 1), 1)))
        total *= mult
    score = int(round(max(0, min(100, total))))
    return RiskResult(score, level_for(score, cfg), [{"key": k, "label": lbl, "points": round(p, 1)} for k, lbl, p in factors])


def score_asset(asset: AssetLike, finding_scores: list[int], child_scores: list[tuple[int, str]],
                cfg: dict[str, Any], now: datetime) -> RiskResult:
    factors: list[tuple[str, str, float]] = []
    if finding_scores:
        ordered = sorted(finding_scores, reverse=True)
        factors.append(("top_finding", "Highest-risk open finding", float(ordered[0])))
        extra = sum(ordered[1:])
        if extra:
            factors.append(("more_findings", f"{len(ordered) - 1} additional open finding(s)", min(15.0, extra * 0.15)))
    else:
        # No findings: residual exposure risk from context only, capped low-to-medium.
        ctx = exposure_factors(asset, cfg, now)
        port = _port_of(asset)
        if port in RISKY_PORTS:
            ctx.append(("exposed_service", f"{RISKY_PORTS[port][0]} reachable from the internet",
                        float(cfg["severity_points"].get(RISKY_PORTS[port][1].value, 0)) * 0.5))
        factors += ctx
        total = sum(p for _, _, p in factors)
        if total > 45:
            factors.append(("cap", "Residual exposure cap (no confirmed findings)", 45 - total))
    if child_scores:
        best, name = max(child_scores)
        own = sum(p for _, _, p in factors)
        if best > own:
            factors.append(("child", f"Inherited from {name}", float(best - own)))
    score = int(round(max(0, min(100, sum(p for _, _, p in factors)))))
    return RiskResult(score, level_for(score, cfg), [{"key": k, "label": lbl, "points": round(p, 1)} for k, lbl, p in factors])
