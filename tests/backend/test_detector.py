"""Change-detection rules (pure)."""

from __future__ import annotations

from app.changes import detector
from app.models.enums import ApprovalStatus, AssetType, EventType, Severity


def test_new_subdomain_unverified_is_medium():
    ev = detector.new_asset(AssetType.SUBDOMAIN, "api-dev.example.com", {}, ApprovalStatus.UNVERIFIED)
    assert ev.event_type == EventType.NEW_SUBDOMAIN and ev.severity == Severity.MEDIUM


def test_new_port_severity_by_service():
    rdp = detector.new_asset(AssetType.PORT, "192.0.2.1:3389/tcp", {})
    assert rdp.event_type == EventType.PORT_OPENED and rdp.severity == Severity.HIGH and "RDP" in rdp.title
    web = detector.new_asset(AssetType.PORT, "192.0.2.1:443/tcp", {})
    assert web.severity == Severity.LOW
    odd = detector.new_asset(AssetType.PORT, "192.0.2.1:10443/tcp", {})
    assert odd.severity == Severity.MEDIUM and "10443/tcp" in odd.title


def test_new_endpoint_with_management_interface_is_high():
    ev = detector.new_asset(AssetType.HTTP_ENDPOINT, "https://vpn.example.com:10443",
                            {"title": "Fortinet SSL VPN Login", "technologies": ["FortiGate"]})
    assert ev.event_type == EventType.ASSET_EXPOSED and ev.severity == Severity.HIGH


def test_dns_and_ip_changes():
    old = {"dns": {"a": ["192.0.2.1"], "mx": ["mx1.example.com"]}}
    new = {"dns": {"a": ["192.0.2.2"], "mx": ["mx2.example.com"]}}
    evs = detector.attribute_changes(AssetType.SUBDOMAIN, "www.example.com", old, new)
    types = {e.event_type for e in evs}
    assert types == {EventType.IP_CHANGED, EventType.DNS_CHANGED}
    ip_ev = next(e for e in evs if e.event_type == EventType.IP_CHANGED)
    assert ip_ev.previous == {"ips": ["192.0.2.1"]} and ip_ev.new == {"ips": ["192.0.2.2"]}
    # first time DNS is learned: no change event
    assert detector.attribute_changes(AssetType.SUBDOMAIN, "x", {}, new) == []
    # order-insensitive
    assert detector.attribute_changes(AssetType.SUBDOMAIN, "x", {"dns": {"a": ["1.1.1.1", "2.2.2.2"]}},
                                      {"dns": {"a": ["2.2.2.2", "1.1.1.1"]}}) == []


def test_service_version_change():
    evs = detector.attribute_changes(AssetType.SERVICE, "192.0.2.1:443/tcp",
                                     {"product": "nginx", "version": "1.24.0"},
                                     {"product": "nginx", "version": "1.25.3"})
    assert len(evs) == 1 and evs[0].event_type == EventType.SERVICE_CHANGED
    assert "1.24.0" in evs[0].title and "1.25.3" in evs[0].title


def test_hosting_change():
    evs = detector.attribute_changes(AssetType.IP_ADDRESS, "192.0.2.1", {"asn": "AS1", "as_name": "A"},
                                     {"asn": "AS2", "as_name": "B"})
    assert evs[0].event_type == EventType.HOSTING_CHANGED


def test_disappearance_and_reappearance():
    assert detector.disappeared(AssetType.PORT, "192.0.2.1:22/tcp", {}).event_type == EventType.PORT_CLOSED
    ev = detector.disappeared(AssetType.SUBDOMAIN, "old.example.com", {"dns": {"a": ["192.0.2.1"]}})
    assert ev.event_type == EventType.ASSET_DISAPPEARED and "no longer resolves" in ev.title
    assert detector.reappeared(AssetType.PORT, "192.0.2.1:3389/tcp").severity == Severity.HIGH


def test_risk_change_thresholds():
    assert detector.risk_changed("a", 34, 78, "low", "high", [{"label": "x", "points": 40}]).severity == Severity.HIGH
    assert detector.risk_changed("a", 30, 33, "low", "low", []) is None
    assert detector.risk_changed("a", 70, 20, "high", "low", []).event_type == EventType.RISK_DECREASED


def test_certificate_expiry_thresholds():
    ev, t = detector.certificate_expiry("fp", "api.example.com", 25, [])
    assert t == 30 and ev.event_type == EventType.CERTIFICATE_EXPIRING
    assert detector.certificate_expiry("fp", "x", 25, [30]) is None
    ev, t = detector.certificate_expiry("fp", "x", 5, [30])
    assert t == 7 and ev.severity == Severity.HIGH
    ev, t = detector.certificate_expiry("fp", "x", -1, [30, 14, 7, 1])
    assert ev.event_type == EventType.CERTIFICATE_EXPIRED and t == -1
