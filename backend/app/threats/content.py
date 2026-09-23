"""What an advisory may contain.

An advisory is *data*: names, versions, CVE ids, prose and reference links.
There is no field for a command, a detection template, a script or a download
location, and ``extra="forbid"`` refuses anything else. The only way an
advisory can cause a scan is by naming a check from the platform's approved
list (``check_keys``), which platform administrators manage separately and
which is resolved against that list when the advisory is saved *and* again when
a check runs.
"""

from __future__ import annotations

import re
from datetime import datetime
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from app.models.enums import Severity
from app.schemas.common import Input

from .versions import UnparseableVersion, Version

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
KEY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9 ._+/-]{0,79}$")


def norm_name(value: str) -> str:
    """How product names are compared everywhere: lower case, single spaces, '_' as space."""
    return re.sub(r"[\s_]+", " ", value.strip().lower())


class VersionRange(Input):
    introduced: str | None = Field(default=None, max_length=64)
    fixed: str | None = Field(default=None, max_length=64)
    last_affected: str | None = Field(default=None, max_length=64)

    @model_validator(mode="after")
    def _parseable(self) -> VersionRange:
        bounds = [v for v in (self.introduced, self.fixed, self.last_affected) if v]
        if not bounds:
            raise ValueError("a version range needs at least one bound (introduced, fixed or last affected)")
        if self.fixed and self.last_affected:
            raise ValueError("give either 'fixed' or 'last affected', not both")
        for b in bounds:
            try:
                Version.parse(b)
            except UnparseableVersion as exc:
                raise ValueError(f"version {b!r} must start with a number") from exc
        return self


class AffectedProduct(Input):
    vendor: str | None = Field(default=None, max_length=120)
    product: str = Field(min_length=1, max_length=120)
    # Names compared (exactly, after normalization) with what fingerprinting reports:
    # technology names, service products and web-server products.
    match_names: list[str] = Field(min_length=1, max_length=10)
    # Empty = every version of the product is affected.
    versions: list[VersionRange] = Field(default_factory=list, max_length=20)

    @field_validator("match_names")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        out = []
        for n in v:
            n = norm_name(n)
            if not _NAME_RE.match(n):
                raise ValueError(f"invalid product name {n!r}: letters, digits, spaces and . _ + / - only")
            out.append(n)
        return sorted(set(out))


class AdvisoryContent(Input):
    title: str = Field(min_length=3, max_length=300)
    summary: str = Field(default="", max_length=4000)
    severity: Severity = Severity.HIGH
    cves: list[str] = Field(default_factory=list, max_length=50)
    references: list[str] = Field(default_factory=list, max_length=20)
    affected: list[AffectedProduct] = Field(default_factory=list, max_length=20)
    remediation: str = Field(default="", max_length=8000)
    check_keys: list[str] = Field(default_factory=list, max_length=5)
    source_published_at: datetime | None = None
    source_updated_at: datetime | None = None

    @field_validator("cves")
    @classmethod
    def _cves(cls, v: list[str]) -> list[str]:
        out = []
        for c in v:
            c = c.strip().upper()
            if not CVE_RE.match(c):
                raise ValueError(f"{c!r} is not a CVE identifier (CVE-YYYY-NNNN)")
            out.append(c)
        return sorted(set(out))

    @field_validator("references")
    @classmethod
    def _references(cls, v: list[str]) -> list[str]:
        """Links shown to people. Never fetched by the platform, never downloaded."""
        out = []
        for r in v:
            r = r.strip()
            try:
                p = urlsplit(r)
            except ValueError as exc:
                raise ValueError(f"invalid reference link {r!r}") from exc
            if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password or len(r) > 1000:
                raise ValueError(f"reference {r!r} must be an http(s) link without credentials")
            out.append(r)
        return out

    @field_validator("check_keys")
    @classmethod
    def _keys(cls, v: list[str]) -> list[str]:
        for k in v:
            if not KEY_RE.match(k):
                raise ValueError(f"invalid check identifier {k!r}")
        return sorted(set(v))

    @model_validator(mode="after")
    def _something_to_match(self) -> AdvisoryContent:
        if not self.affected and not self.cves:
            raise ValueError("an advisory needs affected products or CVE identifiers to match anything")
        return self
