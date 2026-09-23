"""Explicit port sets.

The platform always passes explicit port lists to port scanners (never an
opaque "top N" list whose contents vary between tool versions). This makes
coverage exact: a previously open port is only considered closed if it was
inside the port set that was actually probed.
"""

from __future__ import annotations

import re
from functools import lru_cache

PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

WEB = "80,443,3000,5000,8000,8008,8080,8081,8443,8888,9443"

COMMON = (
    "21,22,23,25,53,80,81,110,111,135,139,143,389,443,445,465,500,587,636,873,993,995,1080,1194,"
    "1433,1434,1521,1723,1883,2049,2082,2083,2086,2087,2181,2222,2375,2376,2379,3000,3128,3268,3306,"
    "3389,4443,4444,4786,5000,5001,5060,5061,5432,5601,5672,5900,5901,5984,5985,5986,6379,6443,7001,"
    "7002,7443,8000,8008,8009,8080,8081,8088,8089,8161,8443,8500,8834,8880,8888,9000,9001,9042,9090,"
    "9091,9200,9300,9418,9443,10000,10250,10443,11211,15672,27017,27018,50000,50070"
)

EXTENDED = "1-1024," + COMMON + ",1025-1100,2000-2100,3000-3100,4000-4100,5000-5100,7000-7100,8000-8100,8400-8500,9000-9100"

FULL = "1-65535"

PORT_SETS = {"web": WEB, "common": COMMON, "extended": EXTENDED, "full": FULL}


def validate_port_spec(spec: str) -> str:
    s = spec.replace(" ", "")
    if not PORT_SPEC_RE.match(s):
        raise ValueError(f"invalid port specification: {spec!r}")
    for lo, hi in _ranges(s):
        if not (1 <= lo <= hi <= 65535):
            raise ValueError(f"invalid port range {lo}-{hi}")
    return s


def _ranges(spec: str) -> list[tuple[int, int]]:
    out = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-", 1)
            out.append((int(a), int(b)))
        else:
            out.append((int(part), int(part)))
    return out


@lru_cache(maxsize=64)
def compile_spec(spec: str) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(_ranges(validate_port_spec(spec))):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return tuple(merged)


def port_in_spec(port: int, spec: str) -> bool:
    return any(lo <= port <= hi for lo, hi in compile_spec(spec))


def normalize_spec(spec: str) -> str:
    return ",".join(f"{lo}" if lo == hi else f"{lo}-{hi}" for lo, hi in compile_spec(spec))


def count_ports(spec: str) -> int:
    return sum(hi - lo + 1 for lo, hi in compile_spec(spec))
