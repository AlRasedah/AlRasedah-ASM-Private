"""SQLAlchemy models. Importing this package registers every table on ``Base.metadata``."""

from app.db.base import Base

from .assets import Asset, AssetObservation, AssetRelationship
from .audit import AuditLog
from .auth import ApiToken, PasswordResetToken, TenantMembership, User, UserSession
from .events import AssetEvent
from .findings import Finding, FindingActivity
from .integrations import Integration, NotificationDelivery, NotificationPolicy
from .intel import IntelFeedState, VulnIntel
from .reports import Report
from .scans import Scan, ScanArtifact, ScanProfile, ScanSchedule, ScanStage, ScopeDecision
from .scope import ScopeEntry, Secret
from .tenancy import MetricSnapshot, Organization, Plan, Tenant, UsageRecord

__all__ = [
    "Base", "Asset", "AssetObservation", "AssetRelationship", "AuditLog", "ApiToken", "PasswordResetToken",
    "TenantMembership", "User", "UserSession", "AssetEvent", "Finding", "FindingActivity", "Integration",
    "NotificationDelivery", "NotificationPolicy", "IntelFeedState", "VulnIntel", "Report", "Scan",
    "ScanArtifact", "ScanProfile", "ScanSchedule", "ScanStage", "ScopeDecision", "ScopeEntry", "Secret",
    "MetricSnapshot", "Organization", "Plan", "Tenant", "UsageRecord",
]

# Tables protected by the standard tenant-isolation RLS policy.
TENANT_TABLES = [
    "organizations", "usage_records", "metric_snapshots", "tenant_memberships", "api_tokens",
    "scope_entries", "secrets", "assets", "asset_relationships", "asset_observations", "asset_events",
    "scans", "scan_stages", "scope_decisions", "scan_schedules", "scan_artifacts", "findings",
    "finding_activities", "integrations", "notification_policies", "notification_deliveries", "reports",
]
