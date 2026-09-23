"""Helpers shared by adapters for building observations from untrusted tool output."""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from ..observations import AssetObservation, AssetRef, ObservedType, RelationObservation, RelationType
from ..targets import InvalidTarget, validate_hostname

_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)


def clean_hostname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower().rstrip(".")
    if v.startswith("*."):
        v = v[2:]
    try:
        return validate_hostname(v)
    except InvalidTarget:
        return None


def clean_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def clean_cidr(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_network(value.strip(), strict=False))
    except ValueError:
        return None


def clean_asn(value: Any) -> str | None:
    m = _ASN_RE.match(str(value).strip()) if value is not None else None
    return f"AS{int(m.group(1))}" if m else None


def asset(t: ObservedType, value: str, attributes: dict[str, Any] | None = None, **kw: Any) -> AssetObservation:
    return AssetObservation(type=t, value=value, attributes=attributes or {}, **kw)


def ref(t: ObservedType, value: str) -> AssetRef:
    return AssetRef(type=t, value=value)


def relation(
    st: ObservedType, sv: str, rel: RelationType, tt: ObservedType, tv: str, attributes: dict[str, Any] | None = None
) -> RelationObservation:
    return RelationObservation(source=ref(st, sv), target=ref(tt, tv), relation=rel, attributes=attributes or {})


def port_value(ip: str, port: int, proto: str = "tcp") -> str:
    host = f"[{ip}]" if ":" in ip else ip
    return f"{host}:{int(port)}/{proto.lower()}"


class ObservationSet:
    """Collects observations while de-duplicating assets and relations."""

    def __init__(self) -> None:
        self._assets: dict[tuple[str, str], AssetObservation] = {}
        self._relations: dict[tuple, RelationObservation] = {}
        self.findings: list = []

    def add_asset(self, obs: AssetObservation) -> None:
        key = (obs.type.value, obs.value)
        existing = self._assets.get(key)
        if existing is None:
            self._assets[key] = obs
        else:
            existing.attributes.update({k: v for k, v in obs.attributes.items() if v not in (None, [], {})})
            existing.confidence = max(existing.confidence, obs.confidence)

    def add(self, t: ObservedType, value: str, attributes: dict[str, Any] | None = None, **kw: Any) -> None:
        self.add_asset(asset(t, value, attributes, **kw))

    def link(
        self, st: ObservedType, sv: str, rel: RelationType, tt: ObservedType, tv: str, attributes: dict | None = None
    ) -> None:
        key = (st.value, sv, rel.value, tt.value, tv)
        if key in self._relations:
            if attributes:
                self._relations[key].attributes.update(attributes)
            return
        self._relations[key] = relation(st, sv, rel, tt, tv, attributes)

    def has_asset(self, t: ObservedType, value: str) -> bool:
        return (t.value, value) in self._assets

    def assets_of(self, t: ObservedType) -> list[str]:
        return [v for (tt, v) in self._assets if tt == t.value]

    def all(self) -> list:
        return [*self._assets.values(), *self._relations.values(), *self.findings]
