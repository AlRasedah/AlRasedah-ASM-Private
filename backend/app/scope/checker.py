"""Authorization scope evaluation.

The single place that decides whether a target may be scanned. Rules:

1. Exclusions always win over inclusions.
2. Hostnames are in scope when they equal, or (with ``include_subdomains``) sit
   below, an included domain entry.
3. IPs are in scope when inside an included IP/CIDR entry.
4. An IP not directly in scope is *derived* when an in-scope hostname resolves
   to it. Derived IPs may be actively scanned only when the organization allows
   derived scanning (default on) — and never when excluded.
5. Active scanning additionally requires ``allow_active_scanning`` on the
   matched entry, and (if verification is required) a *verified* entry: DNS
   TXT proof for domains, platform-administrator approval for IPs/CIDRs.
   ``not_required`` (recorded while verification was off) is not proof.
6. Active scanning never targets a non-public address (loopback, RFC 1918,
   link-local/metadata, CGNAT, ...) unless the deployment allows non-public
   scope — however the address was reached (explicit entry or DNS). Sensor
   workers re-check resolved destinations just before connecting.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from asm_sensors.targets import Target, TargetKind

from app.models.enums import ScopeEntryType, ScopeStatus, VerificationStatus


@dataclass(frozen=True)
class ScopeRule:
    id: uuid.UUID | None
    entry_type: ScopeEntryType
    value: str
    include_subdomains: bool = True
    is_exclusion: bool = False
    allow_active_scanning: bool = True
    # Ownership proven (DNS TXT record, or platform-admin approval for IPs/CIDRs).
    verified: bool = True

    @classmethod
    def from_entry(cls, e) -> ScopeRule:  # type: ignore[no-untyped-def]
        return cls(id=e.id, entry_type=ScopeEntryType(e.entry_type), value=e.value,
                   include_subdomains=e.include_subdomains, is_exclusion=e.is_exclusion,
                   allow_active_scanning=e.allow_active_scanning,
                   verified=e.verification_status == VerificationStatus.VERIFIED)


def _allow_non_public_default() -> bool:
    from app.core.config import get_settings

    return get_settings().allow_non_public_scope


@dataclass
class Decision:
    allowed: bool
    reason: str
    status: ScopeStatus
    rule_id: uuid.UUID | None = None


@dataclass
class ScopeChecker:
    rules: list[ScopeRule]
    require_verification: bool = False
    derived_ip_scanning: bool = True
    allow_non_public: bool = field(default_factory=_allow_non_public_default)
    _nets: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ScopeRule]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        for r in self.rules:
            if r.entry_type in (ScopeEntryType.IP, ScopeEntryType.CIDR):
                self._nets.append((ipaddress.ip_network(r.value, strict=False), r))

    # ---------------------------------------------------------------- basics
    @property
    def root_domains(self) -> set[str]:
        return {r.value for r in self.rules if r.entry_type == ScopeEntryType.DOMAIN and not r.is_exclusion}

    def _domain_rules(self, host: str, exclusion: bool) -> list[ScopeRule]:
        out = []
        for r in self.rules:
            if r.entry_type != ScopeEntryType.DOMAIN or r.is_exclusion != exclusion:
                continue
            if host == r.value or (r.include_subdomains and host.endswith("." + r.value)):
                out.append(r)
        return sorted(out, key=lambda r: len(r.value), reverse=True)  # most specific first

    def _ip_rules(self, ip: str, exclusion: bool) -> list[ScopeRule]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []
        hits = [(net, r) for net, r in self._nets if r.is_exclusion == exclusion and addr.version == net.version
                and addr in net]
        return [r for _, r in sorted(hits, key=lambda x: x[0].prefixlen, reverse=True)]

    def hostname_status(self, host: str) -> tuple[ScopeStatus, ScopeRule | None]:
        if self._domain_rules(host, exclusion=True):
            return ScopeStatus.OUT_OF_SCOPE, None
        inc = self._domain_rules(host, exclusion=False)
        return (ScopeStatus.IN_SCOPE, inc[0]) if inc else (ScopeStatus.OUT_OF_SCOPE, None)

    def ip_status(self, ip: str) -> tuple[ScopeStatus, ScopeRule | None]:
        if self._ip_rules(ip, exclusion=True):
            return ScopeStatus.OUT_OF_SCOPE, None
        inc = self._ip_rules(ip, exclusion=False)
        return (ScopeStatus.IN_SCOPE, inc[0]) if inc else (ScopeStatus.OUT_OF_SCOPE, None)

    def is_excluded_ip(self, ip: str) -> bool:
        return bool(self._ip_rules(ip, exclusion=True))

    # ------------------------------------------------------------- decisions
    def _authorize(self, rule: ScopeRule, active: bool, what: str) -> Decision:
        if active and not rule.allow_active_scanning:
            return Decision(False, f"{what} matched scope entry {rule.value} which does not permit active scanning",
                            ScopeStatus.IN_SCOPE, rule.id)
        if active and self.require_verification and not rule.verified:
            return Decision(False, f"scope entry {rule.value} is not verified", ScopeStatus.IN_SCOPE, rule.id)
        return Decision(True, f"{what} within authorized scope entry {rule.value}", ScopeStatus.IN_SCOPE, rule.id)

    def check_host(self, host: str, *, active: bool, derived_from: Mapping[str, Iterable[str]] | None = None) -> Decision:
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
        if not is_ip:
            if self._domain_rules(host, exclusion=True):
                return Decision(False, "hostname excluded from scope", ScopeStatus.OUT_OF_SCOPE)
            inc = self._domain_rules(host, exclusion=False)
            if not inc:
                return Decision(False, "hostname is not within any authorized domain", ScopeStatus.OUT_OF_SCOPE)
            return self._authorize(inc[0], active, "hostname")

        if self._ip_rules(host, exclusion=True):
            return Decision(False, "IP address excluded from scope", ScopeStatus.OUT_OF_SCOPE)
        inc = self._ip_rules(host, exclusion=False)
        if inc:
            d = self._authorize(inc[0], active, "IP address")
            return self._public_only(host, active, d)
        # Derived: resolved from an in-scope hostname.
        parents = sorted((derived_from or {}).get(host, ()))
        for parent in parents:
            d = self.check_host(parent, active=active)
            if d.allowed:
                if active and not self.derived_ip_scanning:
                    return Decision(False, "IP is only derived from in-scope hostnames and derived scanning is disabled",
                                    ScopeStatus.DERIVED, d.rule_id)
                return self._public_only(host, active, Decision(
                    True, f"IP address resolved from in-scope hostname {parent}", ScopeStatus.DERIVED, d.rule_id))
        return Decision(False, "IP address is not within authorized scope", ScopeStatus.OUT_OF_SCOPE)

    def _public_only(self, address: str, active: bool, d: Decision) -> Decision:
        """Refuse active scanning of non-public destinations, however they were reached."""
        if not d.allowed or not active or self.allow_non_public:
            return d
        net = ipaddress.ip_network(address, strict=False)
        if net.is_global:
            return d
        return Decision(False, f"{address} is not a publicly routable address; it is never actively scanned",
                        d.status, d.rule_id)

    def check(self, target: Target, *, active: bool, derived_from: Mapping[str, Iterable[str]] | None = None) -> Decision:
        if target.kind == TargetKind.CIDR:
            net = ipaddress.ip_network(target.value, strict=False)
            for n, r in self._nets:
                if r.is_exclusion and n.overlaps(net):
                    return Decision(False, f"network overlaps excluded range {r.value}", ScopeStatus.OUT_OF_SCOPE)
            for n, r in self._nets:
                if not r.is_exclusion and n.version == net.version and net.subnet_of(n):  # type: ignore[arg-type]
                    return self._public_only(target.value, active, self._authorize(r, active, "network"))
            return Decision(False, "network is not within authorized scope", ScopeStatus.OUT_OF_SCOPE)
        return self.check_host(target.host, active=active, derived_from=derived_from)
