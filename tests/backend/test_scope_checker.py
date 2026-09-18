"""Authorization/scope decision tests (pure logic)."""

from __future__ import annotations

import uuid

from asm_sensors.targets import Target

from app.models.enums import ScopeEntryType, ScopeStatus
from app.scope.checker import ScopeChecker, ScopeRule


def rule(t, v, **kw):
    return ScopeRule(id=uuid.uuid4(), entry_type=ScopeEntryType(t), value=v, **kw)


def checker(**kw):
    return ScopeChecker(rules=[
        rule("domain", "example.com"),
        rule("domain", "dev.example.com", is_exclusion=True),
        rule("domain", "passive-only.org", allow_active_scanning=False),
        rule("domain", "exact.net", include_subdomains=False),
        rule("cidr", "198.51.100.0/24"),
        rule("ip", "198.51.100.66", is_exclusion=True),
        rule("ip", "203.0.113.9"),
    ], **kw)


def test_hostname_rules():
    c = checker()
    assert c.check(Target(kind="hostname", value="api.example.com"), active=True).allowed
    assert c.check(Target(kind="hostname", value="example.com"), active=True).allowed
    d = c.check(Target(kind="hostname", value="x.dev.example.com"), active=False)
    assert not d.allowed and "excluded" in d.reason  # exclusion wins
    assert not c.check(Target(kind="hostname", value="evil-example.com"), active=False).allowed
    assert not c.check(Target(kind="hostname", value="example.com.evil.net"), active=False).allowed
    assert c.check(Target(kind="hostname", value="exact.net"), active=False).allowed
    assert not c.check(Target(kind="hostname", value="www.exact.net"), active=False).allowed


def test_active_scanning_permission():
    c = checker()
    assert c.check(Target(kind="hostname", value="www.passive-only.org"), active=False).allowed
    d = c.check(Target(kind="hostname", value="www.passive-only.org"), active=True)
    assert not d.allowed and "does not permit active scanning" in d.reason


def test_ip_rules_and_exclusions():
    c = checker()
    assert c.check(Target(kind="ip", value="198.51.100.10"), active=True).allowed
    assert not c.check(Target(kind="ip", value="198.51.100.66"), active=True).allowed
    assert c.check(Target(kind="ip", value="203.0.113.9"), active=True).allowed
    assert not c.check(Target(kind="ip", value="192.0.2.1"), active=True).allowed


def test_derived_ips():
    c = checker()
    derived = {"192.0.2.44": {"api.example.com"}, "192.0.2.45": {"x.dev.example.com"}}
    d = c.check(Target(kind="ip", value="192.0.2.44"), active=True, derived_from=derived)
    assert d.allowed and d.status == ScopeStatus.DERIVED
    # resolved only from an excluded hostname -> not derived
    assert not c.check(Target(kind="ip", value="192.0.2.45"), active=True, derived_from=derived).allowed
    strict = checker(derived_ip_scanning=False)
    assert not strict.check(Target(kind="ip", value="192.0.2.44"), active=True, derived_from=derived).allowed
    assert strict.check(Target(kind="ip", value="192.0.2.44"), active=False, derived_from=derived).allowed


def test_urls_and_host_ports_use_host_part():
    c = checker()
    assert c.check(Target(kind="url", value="https://api.example.com/login"), active=True).allowed
    assert not c.check(Target(kind="url", value="https://evil.org/"), active=True).allowed
    assert c.check(Target(kind="host_port", value="198.51.100.10:8443"), active=True).allowed


def test_cidr_targets():
    c = checker()
    assert not c.check(Target(kind="cidr", value="198.51.100.0/24"), active=True).allowed  # overlaps exclusion
    ok = ScopeChecker(rules=[rule("cidr", "198.51.100.0/24")])
    assert ok.check(Target(kind="cidr", value="198.51.100.0/25"), active=True).allowed
    assert not ok.check(Target(kind="cidr", value="198.51.0.0/16"), active=True).allowed


def test_verification_requirement():
    c = ScopeChecker(rules=[rule("domain", "example.com", verified=False)], require_verification=True)
    assert c.check(Target(kind="hostname", value="a.example.com"), active=False).allowed
    d = c.check(Target(kind="hostname", value="a.example.com"), active=True)
    assert not d.allowed and "not verified" in d.reason


def test_root_domains():
    assert checker().root_domains == {"example.com", "passive-only.org", "exact.net"}
