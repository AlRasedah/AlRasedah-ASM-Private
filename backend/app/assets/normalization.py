"""Canonical forms for asset values.

Two observations refer to the same asset iff they normalize to the same
``(asset_type, normalized_value)``. All normalization is deterministic and
offline (the public suffix list is the snapshot bundled with tldextract; no
network fetch, which matters for air-gapped/in-Kingdom deployments).
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache

import tldextract
from asm_sensors.adapters.httpx import endpoint_base
from asm_sensors.observations import ObservedType
from asm_sensors.targets import InvalidTarget, validate_hostname

from app.models.enums import AssetType

_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False)
_PORT_RE = re.compile(r"^(?P<host>\[[0-9a-f:.]+\]|[0-9.]+):(?P<port>\d{1,5})/(?P<proto>tcp|udp)$", re.IGNORECASE)
_FP_RE = re.compile(r"^[0-9a-f]{8,128}$")
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)

HOSTNAME_ASSET_TYPES = {AssetType.ROOT_DOMAIN, AssetType.DOMAIN, AssetType.SUBDOMAIN}


@lru_cache(maxsize=65536)
def registrable_domain(host: str) -> str | None:
    r = _extract(host)
    if hasattr(r, "top_domain_under_public_suffix"):
        value = r.top_domain_under_public_suffix
    else:  # tldextract < 5.2
        value = r.registered_domain
    return value or None


def normalize_hostname(value: str) -> str | None:
    try:
        return validate_hostname(value)
    except InvalidTarget:
        return None


def normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def normalize_cidr(value: str) -> str | None:
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def normalize_port(value: str) -> str | None:
    m = _PORT_RE.match(value.strip())
    if not m:
        return None
    host = m.group("host").strip("[]")
    ip = normalize_ip(host)
    port = int(m.group("port"))
    if not ip or not 1 <= port <= 65535:
        return None
    h = f"[{ip}]" if ":" in ip else ip
    return f"{h}:{port}/{m.group('proto').lower()}"


def parse_port_value(value: str) -> tuple[str, int, str] | None:
    norm = normalize_port(value)
    if not norm:
        return None
    hostpart, _, rest = norm.rpartition(":")
    port, _, proto = rest.partition("/")
    return hostpart.strip("[]"), int(port), proto


def normalize_value(t: ObservedType | AssetType, value: str) -> str | None:
    """Return the canonical value or None if the value is not valid for the type."""
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        return None
    tv = t.value
    if tv in ("hostname", "root_domain", "domain", "subdomain"):
        return normalize_hostname(value)
    if tv == "ip_address":
        return normalize_ip(value)
    if tv == "cidr":
        return normalize_cidr(value)
    if tv == "asn":
        m = _ASN_RE.match(value.strip())
        return f"AS{int(m.group(1))}" if m else None
    if tv in ("port", "service"):
        return normalize_port(value)
    if tv == "http_endpoint":
        base = endpoint_base(value.strip())
        return base[0] if base else None
    if tv == "technology":
        v = " ".join(value.strip().lower().split())
        return v[:128] if v else None
    if tv == "certificate":
        v = value.strip().lower().replace(":", "")
        return v if _FP_RE.match(v) else None
    if tv in ("cloud_resource", "web_application", "dns_record"):
        v = value.strip().lower()
        return v[:512] if v and not any(ord(c) < 32 for c in v) else None
    return None


def classify_hostname(host: str, root_domains: set[str]) -> AssetType:
    if host in root_domains:
        return AssetType.ROOT_DOMAIN
    if registrable_domain(host) == host:
        return AssetType.DOMAIN
    return AssetType.SUBDOMAIN


def parent_domain(host: str, root_domains: set[str]) -> str | None:
    """The most specific scoped root domain containing ``host`` (else its registrable domain)."""
    best = None
    for root in root_domains:
        if host != root and host.endswith("." + root) and (best is None or len(root) > len(best)):
            best = root
    if best:
        return best
    reg = registrable_domain(host)
    return reg if reg and reg != host else None


def asset_type_for(t: ObservedType, value: str, root_domains: set[str]) -> AssetType:
    if t == ObservedType.HOSTNAME:
        return classify_hostname(value, root_domains)
    return AssetType(t.value)


def observed_type_for(t: AssetType) -> ObservedType:
    if t in HOSTNAME_ASSET_TYPES:
        return ObservedType.HOSTNAME
    return ObservedType(t.value)


def is_private_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
