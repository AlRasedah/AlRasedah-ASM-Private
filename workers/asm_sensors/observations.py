"""Scanner-independent observation schema.

Every adapter translates its tool's native output into these models. The
platform ingests *only* these models, so the database schema is never coupled
to a particular scanner's output format.

Three kinds of statements are produced:

* :class:`AssetObservation`    – "I saw this asset (with these attributes)".
* :class:`RelationObservation` – "asset A is related to asset B".
* :class:`FindingObservation`  – "this asset exhibits this security issue".

In addition, a sensor run declares *coverage* – which parts of the existing
state it was authoritative for. Coverage is what lets the platform tell the
difference between "not observed because it is gone" and "not observed because
this sensor never looked". Without it, change detection (port closed, asset
disappeared, vulnerability resolved) would be guesswork.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ObservedType(StrEnum):
    """Asset types a sensor may report.

    ``hostname`` is deliberately generic: sensors do not know the customer's
    scope, so the platform classifies hostnames into root domains, domains and
    subdomains during normalization.
    """

    HOSTNAME = "hostname"
    IP_ADDRESS = "ip_address"
    CIDR = "cidr"
    ASN = "asn"
    DNS_RECORD = "dns_record"
    CERTIFICATE = "certificate"
    PORT = "port"
    SERVICE = "service"
    HTTP_ENDPOINT = "http_endpoint"
    WEB_APPLICATION = "web_application"
    TECHNOLOGY = "technology"
    CLOUD_RESOURCE = "cloud_resource"


class RelationType(StrEnum):
    RESOLVES_TO = "resolves_to"  # hostname -> ip_address
    CNAME = "cname"  # hostname -> hostname
    NS_RECORD = "ns_record"  # hostname -> hostname
    MX_RECORD = "mx_record"  # hostname -> hostname
    PTR = "ptr"  # ip_address -> hostname
    SUBDOMAIN_OF = "subdomain_of"  # subdomain -> root/registrable domain
    CONTAINS = "contains"  # cidr -> ip_address
    ANNOUNCES = "announces"  # asn -> cidr
    BELONGS_TO_ASN = "belongs_to_asn"  # ip_address -> asn
    HAS_PORT = "has_port"  # ip_address -> port
    RUNS_SERVICE = "runs_service"  # port -> service
    SERVES = "serves"  # hostname / ip_address -> http_endpoint
    HOSTED_ON = "hosted_on"  # http_endpoint -> ip_address
    USES_TECHNOLOGY = "uses_technology"  # http_endpoint / service -> technology
    PRESENTS_CERTIFICATE = "presents_certificate"  # http_endpoint / service -> certificate
    CERTIFICATE_FOR = "certificate_for"  # certificate -> hostname (SAN)
    HOSTED_BY = "hosted_by"  # hostname / ip -> cloud_resource
    REDIRECTS_TO = "redirects_to"  # http_endpoint -> http_endpoint
    RELATED_TO = "related_to"  # generic


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, value: str | None, default: Severity | None = None) -> Severity:
        if value is None:
            return default or cls.INFO
        v = str(value).strip().lower()
        aliases = {"informational": "info", "information": "info", "none": "info", "unknown": "info", "moderate": "medium"}
        v = aliases.get(v, v)
        try:
            return cls(v)
        except ValueError:
            return default or cls.INFO


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    EXPOSURE = "exposure"
    MISCONFIGURATION = "misconfiguration"
    CERTIFICATE = "certificate"
    SERVICE_EXPOSURE = "service_exposure"
    INFORMATION = "information"
    CREDENTIAL_LEAK = "credential_leak"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=False)


class AssetRef(_Model):
    type: ObservedType
    value: str = Field(min_length=1, max_length=2048)

    def key(self) -> tuple[str, str]:
        return (self.type.value, self.value)


class AssetObservation(_Model):
    kind: Literal["asset"] = "asset"
    type: ObservedType
    value: str = Field(min_length=1, max_length=2048)
    attributes: dict[str, Any] = Field(default_factory=dict)
    confidence: int = Field(default=80, ge=0, le=100)
    # Upstream origin inside the sensor, e.g. a passive data source name.
    origin: str | None = None

    def ref(self) -> AssetRef:
        return AssetRef(type=self.type, value=self.value)


class RelationObservation(_Model):
    kind: Literal["relation"] = "relation"
    source: AssetRef
    target: AssetRef
    relation: RelationType
    attributes: dict[str, Any] = Field(default_factory=dict)


class FindingObservation(_Model):
    kind: Literal["finding"] = "finding"
    asset: AssetRef
    # Stable identifier of the detection logic (e.g. a template or rule id).
    rule_id: str = Field(min_length=1, max_length=512)
    title: str = Field(min_length=1, max_length=512)
    description: str | None = None
    severity: Severity = Severity.INFO
    category: FindingCategory = FindingCategory.VULNERABILITY
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    epss_score: float | None = Field(default=None, ge=0, le=1)
    references: list[str] = Field(default_factory=list)
    remediation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    # Where exactly the issue was observed; part of the de-duplication key.
    location: str | None = None
    confidence: int = Field(default=90, ge=0, le=100)


Observation = Annotated[
    AssetObservation | RelationObservation | FindingObservation,
    Field(discriminator="kind"),
]


class LivenessCoverage(_Model):
    """The sensor checked whether these assets still exist.

    Any listed asset that is not re-observed in the same run is counted as
    *missed*; the platform deactivates it after a configurable number of
    consecutive misses.
    """

    kind: Literal["liveness"] = "liveness"
    asset_type: ObservedType
    values: list[str]


class RelationCoverage(_Model):
    """The sensor enumerated *all* ``relation`` children of these parents.

    Existing relationships from a listed parent to a child of ``child_type``
    that were not re-observed are counted as missed. ``constraints`` narrows
    the enumerated space, e.g. ``{"ports": [80, 443]}`` means only those ports
    were probed on the parents, so previously-open port 8443 is *not* covered.
    """

    kind: Literal["relation"] = "relation"
    parent_type: ObservedType
    parents: list[str]
    relation: RelationType
    child_type: ObservedType
    constraints: dict[str, Any] = Field(default_factory=dict)


class FindingCoverage(_Model):
    """The sensor tested these assets for this class of findings.

    Open findings from ``source`` on these assets that match the filter and
    were not re-observed are candidates for automatic resolution.
    """

    kind: Literal["finding"] = "finding"
    assets: list[AssetRef]
    severities: list[Severity] | None = None
    include_tags: list[str] | None = None
    exclude_tags: list[str] | None = None
    rule_ids: list[str] | None = None


Coverage = Annotated[
    LivenessCoverage | RelationCoverage | FindingCoverage,
    Field(discriminator="kind"),
]


class NormalizedOutput(_Model):
    observations: list[Observation] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)


class RawArtifact(_Model):
    """Optionally retained raw tool output (gzip + base64), for troubleshooting."""

    name: str
    content_type: str = "application/octet-stream"
    encoding: Literal["gzip+base64"] = "gzip+base64"
    size: int
    sha256: str
    truncated: bool = False
    data: str


# A capture travels base64-encoded inside the result envelope, so the broker message
# is bounded by this (the platform's configured image limit is lower still).
SCREENSHOT_MAX_BYTES = 5 * 1024 * 1024


class ScreenshotImage(_Model):
    """One website capture (the ``screenshot`` adapter). Never evidence of a vulnerability."""

    url: str = Field(max_length=2048)
    # Where the page ended up, without query string or fragment (they can carry tokens).
    final_url: str | None = Field(default=None, max_length=2048)
    redirects: list[str] = Field(default_factory=list, max_length=10)
    status_code: int | None = None
    title: str | None = Field(default=None, max_length=300)
    content_type: Literal["image/png"] = "image/png"
    width: int = Field(ge=1, le=4096)
    height: int = Field(ge=1, le=4096)
    size: int = Field(ge=1, le=SCREENSHOT_MAX_BYTES)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    data: str = Field(max_length=(SCREENSHOT_MAX_BYTES * 4) // 3 + 8)  # base64
    captured_at: datetime


class SensorResult(_Model):
    adapter: str
    adapter_version: str | None = None
    tool_version: str | None = None
    status: Literal["completed", "failed", "partial"] = "completed"
    # True when the observations describe what a third-party database last saw
    # rather than a live check: the platform adds new assets from them but never
    # refreshes "last seen", revives inactive assets or closes anything.
    historical: bool = False
    started_at: datetime
    finished_at: datetime
    target_count: int = 0
    observations: list[Observation] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[RawArtifact] = Field(default_factory=list)
    # At most one capture per result: a screenshot job covers exactly one endpoint.
    screenshots: list[ScreenshotImage] = Field(default_factory=list, max_length=1)
