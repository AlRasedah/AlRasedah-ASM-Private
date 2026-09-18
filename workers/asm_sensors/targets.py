"""Strict target validation.

Targets are always re-validated inside the sensor, even though the platform
already validated and scope-checked them. Nothing that fails these checks is
ever written to a tool's input file or argument vector. In particular no
target may begin with ``-`` (argument injection) or contain whitespace, shell
metacharacters or control characters.
"""

from __future__ import annotations

import ipaddress
import re
from enum import StrEnum
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, model_validator

_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
HOSTNAME_RE = re.compile(rf"^(?=.{{1,253}}$){_LABEL}(?:\.{_LABEL})+$")
PORT_RE = re.compile(r"^[0-9]{1,5}$")


class TargetKind(StrEnum):
    DOMAIN = "domain"  # a root domain, used by discovery sensors
    HOSTNAME = "hostname"
    IP = "ip"
    CIDR = "cidr"
    HOST_PORT = "host_port"
    URL = "url"


class InvalidTarget(ValueError):
    pass


def validate_hostname(value: str) -> str:
    v = value.strip().lower().rstrip(".")
    if v.startswith("*."):
        raise InvalidTarget("wildcard hostnames are not valid scan targets")
    try:
        # Accept internationalized names but always operate on the A-label form.
        v = v.encode("idna").decode("ascii") if any(ord(c) > 127 for c in v) else v
    except UnicodeError as exc:
        raise InvalidTarget(f"invalid IDN hostname: {value!r}") from exc
    if not HOSTNAME_RE.match(v):
        raise InvalidTarget(f"invalid hostname: {value!r}")
    return v


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise InvalidTarget(f"invalid IP address: {value!r}") from exc


def validate_cidr(value: str, *, max_ipv4_prefix: int = 16, max_ipv6_prefix: int = 48) -> str:
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise InvalidTarget(f"invalid CIDR: {value!r}") from exc
    limit = max_ipv4_prefix if net.version == 4 else max_ipv6_prefix
    if net.prefixlen < limit:
        raise InvalidTarget(f"CIDR {net} is larger than the permitted /{limit}")
    return str(net)


def validate_port(value: int | str) -> int:
    s = str(value)
    if not PORT_RE.match(s) or not 1 <= int(s) <= 65535:
        raise InvalidTarget(f"invalid port: {value!r}")
    return int(s)


def split_host_port(value: str) -> tuple[str, int]:
    v = value.strip()
    if v.startswith("["):  # [ipv6]:port
        host, _, port = v[1:].partition("]:")
        return validate_ip(host), validate_port(port)
    host, sep, port = v.rpartition(":")
    if not sep:
        raise InvalidTarget(f"expected host:port, got {value!r}")
    try:
        host = validate_ip(host)
    except InvalidTarget:
        host = validate_hostname(host)
    return host, validate_port(port)


def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def validate_url(value: str) -> str:
    v = value.strip()
    parts = urlsplit(v)
    if parts.scheme not in ("http", "https"):
        raise InvalidTarget(f"only http(s) URLs are permitted: {value!r}")
    if parts.username or parts.password:
        raise InvalidTarget("URLs with embedded credentials are not permitted")
    host = parts.hostname or ""
    try:
        host = validate_ip(host)
    except InvalidTarget:
        host = validate_hostname(host)
    if any(c.isspace() for c in v) or any(ord(c) < 32 for c in v):
        raise InvalidTarget("URL contains whitespace or control characters")
    port = parts.port  # raises ValueError on garbage
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc += f":{port}"
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme}://{netloc}{path}{query}"


_VALIDATORS = {
    TargetKind.DOMAIN: validate_hostname,
    TargetKind.HOSTNAME: validate_hostname,
    TargetKind.IP: validate_ip,
    TargetKind.CIDR: validate_cidr,
    TargetKind.URL: validate_url,
    TargetKind.HOST_PORT: lambda v: format_host_port(*split_host_port(v)),
}


class Target(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: TargetKind
    value: str

    @model_validator(mode="before")
    @classmethod
    def _validate(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        kind = TargetKind(data.get("kind"))
        raw = data.get("value")
        if not isinstance(raw, str):
            raise InvalidTarget("target value must be a string")
        normalized = _VALIDATORS[kind](raw)
        if normalized.startswith("-"):
            raise InvalidTarget("targets may not start with '-'")
        return {**data, "kind": kind, "value": normalized}

    @property
    def host(self) -> str:
        """The host part of the target (hostname or IP)."""
        if self.kind in (TargetKind.DOMAIN, TargetKind.HOSTNAME, TargetKind.IP, TargetKind.CIDR):
            return self.value
        if self.kind == TargetKind.HOST_PORT:
            return split_host_port(self.value)[0]
        return urlsplit(self.value).hostname or ""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
