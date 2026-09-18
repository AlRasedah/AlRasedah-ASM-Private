"""Platform enumerations. Stored as VARCHAR (see ``enum_column``)."""

from __future__ import annotations

from enum import StrEnum

from asm_sensors.base import StageType
from asm_sensors.observations import FindingCategory, RelationType, Severity

__all__ = [
    "Severity", "FindingCategory", "RelationType", "StageType",
    "Role", "TenantStatus", "AssetType", "AssetStatus", "ScopeStatus", "ApprovalStatus", "Criticality",
    "FindingStatus", "ScanStatus", "StageStatus", "ScanTrigger", "EventType", "ScopeEntryType",
    "VerificationStatus", "DecisionResult", "IntegrationType", "DeliveryStatus", "ReportType",
    "ReportFormat", "JobStatus", "RiskLevel",
]


class Role(StrEnum):
    PLATFORM_ADMIN = "platform_admin"
    TENANT_ADMIN = "tenant_admin"
    SECURITY_ANALYST = "security_analyst"
    VIEWER = "viewer"


class TenantStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class AssetType(StrEnum):
    ROOT_DOMAIN = "root_domain"
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
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


HOSTNAME_TYPES = (AssetType.ROOT_DOMAIN, AssetType.DOMAIN, AssetType.SUBDOMAIN)
# Types shown in the default inventory view / counted in dashboard totals.
PRIMARY_TYPES = (
    AssetType.ROOT_DOMAIN, AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP_ADDRESS, AssetType.CIDR,
    AssetType.PORT, AssetType.HTTP_ENDPOINT, AssetType.CERTIFICATE, AssetType.CLOUD_RESOURCE,
    AssetType.WEB_APPLICATION,
)


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"


class ScopeStatus(StrEnum):
    IN_SCOPE = "in_scope"  # explicitly authorized
    DERIVED = "derived"  # linked to an in-scope asset (e.g. resolved IP, technology)
    OUT_OF_SCOPE = "out_of_scope"  # related third-party infrastructure; never actively scanned


class ApprovalStatus(StrEnum):
    UNVERIFIED = "unverified"
    APPROVED = "approved"
    EXPECTED = "expected"
    THIRD_PARTY = "third_party"
    UNKNOWN = "unknown"
    UNAUTHORIZED = "unauthorized"
    DECOMMISSIONED = "decommissioned"


SHADOW_IT_STATES = (ApprovalStatus.UNVERIFIED, ApprovalStatus.UNKNOWN, ApprovalStatus.UNAUTHORIZED)


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskLevel(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    ACCEPTED_RISK = "accepted_risk"
    FALSE_POSITIVE = "false_positive"
    REMEDIATED = "remediated"
    REOPENED = "reopened"


OPEN_FINDING_STATES = (FindingStatus.NEW, FindingStatus.INVESTIGATING, FindingStatus.REOPENED)


class ScanStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


ACTIVE_SCAN_STATES = (ScanStatus.PENDING, ScanStatus.QUEUED, ScanStatus.RUNNING)


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class ScanTrigger(StrEnum):
    MANUAL = "manual"
    SCHEDULED = "scheduled"
    API = "api"


class EventType(StrEnum):
    NEW_ASSET = "new_asset"
    NEW_SUBDOMAIN = "new_subdomain"
    ASSET_DISAPPEARED = "asset_disappeared"
    ASSET_REAPPEARED = "asset_reappeared"
    DNS_CHANGED = "dns_changed"
    IP_CHANGED = "ip_changed"
    PORT_OPENED = "port_opened"
    PORT_CLOSED = "port_closed"
    SERVICE_DETECTED = "service_detected"
    SERVICE_CHANGED = "service_changed"
    CERTIFICATE_CHANGED = "certificate_changed"
    CERTIFICATE_EXPIRING = "certificate_expiring"
    CERTIFICATE_EXPIRED = "certificate_expired"
    TECHNOLOGY_DETECTED = "technology_detected"
    TECHNOLOGY_CHANGED = "technology_changed"
    TECHNOLOGY_REMOVED = "technology_removed"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    VULNERABILITY_RESOLVED = "vulnerability_resolved"
    VULNERABILITY_REOPENED = "vulnerability_reopened"
    RISK_INCREASED = "risk_increased"
    RISK_DECREASED = "risk_decreased"
    ASSET_EXPOSED = "asset_exposed"
    OWNERSHIP_CHANGED = "ownership_changed"
    APPROVAL_CHANGED = "approval_changed"
    HOSTING_CHANGED = "hosting_changed"
    SHADOW_IT_DISCOVERED = "shadow_it_discovered"
    SCAN_FAILED = "scan_failed"
    SCAN_COMPLETED = "scan_completed"


class ScopeEntryType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"


class VerificationStatus(StrEnum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    NOT_REQUIRED = "not_required"


class DecisionResult(StrEnum):
    ALLOWED = "allowed"
    REJECTED = "rejected"


class IntegrationType(StrEnum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    WAZUH = "wazuh"
    SLACK = "slack"
    TEAMS = "teams"
    JIRA = "jira"
    SERVICENOW = "servicenow"


class DeliveryStatus(StrEnum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    SKIPPED = "skipped"


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL = "technical"
    ASSET_INVENTORY = "asset_inventory"
    VULNERABILITY = "vulnerability"
    CHANGES = "changes"
    RISK_TREND = "risk_trend"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"


class JobStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
