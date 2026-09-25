"""SQLAlchemy models. Importing this package registers every table on ``Base.metadata``."""

from app.db.base import Base

from .assets import Asset, AssetObservation, AssetRelationship
from .audit import AuditLog
from .auth import ApiToken, PasswordResetToken, TenantMembership, User, UserSession
from .events import AssetEvent
from .findings import Finding, FindingActivity
from .integrations import Integration, NotificationDelivery, NotificationPolicy
from .intel import IntelFeedState, VulnIntel
from .platform import PlatformSetting, UserAlertPreference
from .reports import Report
from .observability import EventExportState, OpsEvent, SetupToken, SupportBundle
from .scans import Scan, ScanArtifact, ScanProfile, ScanSchedule, ScanStage, ScanStageOutput, ScopeDecision
from .scope import ScopeEntry, Secret
from .screenshots import ScreenshotCapture, ScreenshotUsage, StorageDeletion
from .tenancy import MetricSnapshot, Organization, Plan, Tenant, UsageRecord
from .threats import (
    ThreatAdvisory,
    ThreatAdvisoryVersion,
    ThreatCampaign,
    ThreatCheck,
    ThreatCheckRun,
    ThreatFeedItem,
    ThreatMatch,
)

__all__ = [
    "Base", "Asset", "AssetObservation", "AssetRelationship", "AuditLog", "ApiToken", "PasswordResetToken",
    "TenantMembership", "User", "UserSession", "AssetEvent", "Finding", "FindingActivity", "Integration",
    "NotificationDelivery", "NotificationPolicy", "IntelFeedState", "VulnIntel", "PlatformSetting",
    "UserAlertPreference", "Report", "Scan",
    "ScanArtifact", "ScanProfile", "ScanSchedule", "ScanStage", "ScanStageOutput", "ScopeDecision", "ScopeEntry", "Secret",
    "MetricSnapshot", "Organization", "Plan", "Tenant", "UsageRecord", "ThreatAdvisory", "ThreatAdvisoryVersion",
    "ThreatCampaign", "ThreatCheck", "ThreatCheckRun", "ThreatMatch", "ScreenshotCapture",
    "ScreenshotUsage", "StorageDeletion", "ThreatFeedItem", "OpsEvent", "EventExportState", "SupportBundle",
    "SetupToken",
]

# Tables protected by the standard tenant-isolation RLS policy.
TENANT_TABLES = [
    "organizations", "usage_records", "metric_snapshots", "tenant_memberships", "api_tokens",
    "scope_entries", "secrets", "assets", "asset_relationships", "asset_observations", "asset_events",
    "scans", "scan_stages", "scope_decisions", "scan_schedules", "scan_artifacts", "findings",
    "finding_activities", "integrations", "notification_policies", "notification_deliveries", "reports",
    "threat_campaigns", "threat_matches", "threat_check_runs", "screenshot_captures",
]

# Global catalog tables: tenant sessions may read only what is published; only system
# sessions (platform administrators) may write.
CATALOG_TABLES = ["threat_advisories", "threat_advisory_versions", "threat_checks"]
