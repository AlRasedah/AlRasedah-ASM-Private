"""Risk scoring (pure)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from app.models.enums import ApprovalStatus, AssetType, Criticality, FindingCategory, RiskLevel, ScopeStatus, Severity
from app.risk.engine import level_for, score_asset, score_finding
from app.tenants.settings import DEFAULT_TENANT_SETTINGS

CFG = DEFAULT_TENANT_SETTINGS["risk"]
NOW = datetime(2026, 9, 18, tzinfo=UTC)


@dataclass
class A:
    asset_type: AssetType = AssetType.HTTP_ENDPOINT
    normalized_value: str = "https://app.example.com"
    criticality: Criticality = Criticality.MEDIUM
    approval_status: ApprovalStatus = ApprovalStatus.APPROVED
    scope_status: ScopeStatus = ScopeStatus.IN_SCOPE
    first_seen: datetime = NOW - timedelta(days=100)
    meta: dict = field(default_factory=dict)


@dataclass
class F:
    severity: Severity = Severity.HIGH
    cvss_score: float | None = None
    epss_score: float | None = None
    kev: bool = False
    exploit_available: bool = False
    confidence: int = 100
    first_seen: datetime = NOW
    tags: list = field(default_factory=list)
    category: FindingCategory = FindingCategory.VULNERABILITY


def keys(r):
    return {f["key"] for f in r.factors}


def test_risk_is_not_just_cvss():
    base = score_finding(F(cvss_score=9.8), A(), CFG, NOW)
    kev = score_finding(F(cvss_score=9.8, kev=True, epss_score=0.97), A(), CFG, NOW)
    assert kev.score > base.score
    assert {"kev", "epss", "severity", "exposure"} <= keys(kev)
    assert kev.level == RiskLevel.CRITICAL


def test_context_raises_score_and_factors_are_explained():
    plain = score_finding(F(severity=Severity.MEDIUM), A(), CFG, NOW)
    shadow = score_finding(F(severity=Severity.MEDIUM),
                           A(approval_status=ApprovalStatus.UNVERIFIED, criticality=Criticality.CRITICAL,
                             first_seen=NOW - timedelta(days=1), meta={"title": "Jenkins"}), CFG, NOW)
    assert shadow.score > plain.score
    assert {"shadow_it", "criticality", "new_asset", "management_interface"} <= keys(shadow)
    assert all("label" in f and "points" in f for f in shadow.factors)


def test_low_confidence_and_age():
    sure = score_finding(F(), A(), CFG, NOW)
    unsure = score_finding(F(confidence=40), A(), CFG, NOW)
    assert unsure.score < sure.score and "confidence" in keys(unsure)
    old = score_finding(F(first_seen=NOW - timedelta(days=120)), A(), CFG, NOW)
    assert old.score > sure.score and "age" in keys(old)


def test_scores_are_bounded():
    r = score_finding(F(severity=Severity.CRITICAL, cvss_score=10, kev=True, epss_score=1.0),
                      A(criticality=Criticality.CRITICAL, approval_status=ApprovalStatus.UNAUTHORIZED,
                        meta={"title": "phpMyAdmin"}, first_seen=NOW), CFG, NOW)
    assert 0 <= r.score <= 100


def test_asset_scores():
    finding_driven = score_asset(A(), [82, 40, 30], [], CFG, NOW)
    assert finding_driven.score >= 82 and "more_findings" in keys(finding_driven)
    exposure_only = score_asset(A(asset_type=AssetType.PORT, normalized_value="192.0.2.1:3389/tcp",
                                  approval_status=ApprovalStatus.UNVERIFIED), [], [], CFG, NOW)
    assert 0 < exposure_only.score <= 45 and "risky_port" in keys(exposure_only)
    parent = score_asset(A(asset_type=AssetType.SUBDOMAIN, normalized_value="x.example.com"), [], [(90, "child")], CFG, NOW)
    assert parent.score == 90 and "child" in keys(parent)


def test_levels():
    assert level_for(85, CFG) == RiskLevel.CRITICAL
    assert level_for(60, CFG) == RiskLevel.HIGH
    assert level_for(35, CFG) == RiskLevel.MEDIUM
    assert level_for(15, CFG) == RiskLevel.LOW
    assert level_for(3, CFG) == RiskLevel.INFO
