// Types mirroring the REST API schemas (see /api/docs).

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type RiskLevel = Severity;

export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface TenantRef {
  id: string;
  name: string;
  slug: string;
}

export interface Me {
  user: { id: string; email: string; full_name: string | null; is_platform_admin: boolean; mfa_enabled: boolean };
  tenant: TenantRef | null;
  role: string;
  permissions: string[];
  memberships: { tenant: TenantRef; role: string }[];
  /** Idle minutes before the session signs itself out; 0 = no idle timeout. */
  session_idle_minutes: number;
}

export interface Organization {
  id: string;
  name: string;
  description: string | null;
  industry: string | null;
  settings: Record<string, unknown>;
  is_active: boolean;
  baseline_completed_at: string | null;
  created_at: string;
  scope_entries?: number;
  assets?: number;
  open_findings?: number;
  risk_score?: number;
  last_scan_at?: string | null;
}

export interface ScopeEntry {
  id: string;
  organization_id: string;
  entry_type: "domain" | "ip" | "cidr";
  value: string;
  include_subdomains: boolean;
  is_exclusion: boolean;
  allow_active_scanning: boolean;
  verification_status: string;
  verified_at: string | null;
  notes: string | null;
  created_at: string;
}

export interface AssetRef {
  id: string;
  asset_type: string;
  value: string;
  status: string;
  risk_score: number;
  scope_status: string;
}

export interface Asset {
  id: string;
  organization_id: string;
  asset_type: string;
  value: string;
  status: "active" | "inactive";
  scope_status: string;
  approval_status: string;
  owner: string | null;
  business_unit: string | null;
  criticality: string;
  tags: string[];
  first_seen: string;
  last_seen: string;
  risk_score: number;
  risk_level: RiskLevel;
  open_findings: number;
  confidence: number;
  ips: string[];
  source_label: string | null;
  title: string | null;
}

export interface RelatedAsset {
  relation: string;
  direction: "in" | "out";
  active: boolean;
  first_seen: string;
  last_seen: string;
  attributes: Record<string, unknown>;
  asset: AssetRef;
}

export interface RiskFactor {
  key: string;
  label: string;
  points: number;
}

export interface AssetDetail extends Asset {
  normalized_value: string;
  meta: Record<string, any>;
  notes: string | null;
  risk_factors: RiskFactor[];
  discovered_at: string;
  last_scanned_at: string | null;
  inactive_since: string | null;
  missed_count: number;
  discovery_method: string | null;
  sources: string[];
  relationships: RelatedAsset[];
}

export interface AssetEvent {
  id: string;
  organization_id: string | null;
  asset_id: string | null;
  asset_type: string | null;
  asset_value: string | null;
  finding_id: string | null;
  scan_id: string | null;
  event_type: string;
  severity: Severity;
  title: string;
  summary: string | null;
  previous_state: Record<string, unknown> | null;
  new_state: Record<string, unknown> | null;
  details: Record<string, unknown>;
  occurred_at: string;
  is_baseline: boolean;
  acknowledged: boolean;
  acknowledged_at: string | null;
  notified: boolean;
}

export interface Observation {
  id: number;
  scan_id: string | null;
  source_label: string | null;
  observed_at: string;
  data: Record<string, unknown>;
}

export interface Finding {
  id: string;
  organization_id: string;
  asset_id: string;
  title: string;
  category: string;
  severity: Severity;
  status: string;
  cve: string[];
  cvss_score: number | null;
  epss_score: number | null;
  kev: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  assigned_to: string | null;
  tags: string[];
  false_positive: boolean;
  location: string | null;
  source_label: string | null;
  /** Confirmed by active web application testing. */
  dast: boolean;
  /** Reported by an external database and not verified against the live service. */
  unverified: boolean;
  asset: AssetRef | null;
}

export interface WebApp {
  id: string;
  url: string;
  host: string | null;
  title: string | null;
  webserver: string | null;
  technologies: string[];
  status_code: number | null;
  risk_score: number;
  risk_level: RiskLevel;
  approval_status: string;
  open_findings: number;
  by_severity: Record<string, number>;
  dast_verified: number;
  crawled: boolean;
  first_seen: string;
  last_seen: string;
  last_scanned_at: string | null;
}

export interface FindingDetail extends Finding {
  description: string | null;
  remediation: string | null;
  references: string[];
  evidence: Record<string, unknown>;
  cwe: string[];
  cvss_vector: string | null;
  epss_percentile: number | null;
  kev_due_date: string | null;
  exploit_available: boolean;
  confidence: number;
  occurrence_count: number;
  notes: string | null;
  accepted_until: string | null;
  risk_factors: RiskFactor[];
  source_finding_id: string;
}

export interface Activity {
  id: string;
  user_id: string | null;
  user_email: string | null;
  activity_type: string;
  summary?: string | null;
  previous: Record<string, unknown> | null;
  new: Record<string, unknown> | null;
  comment: string | null;
  scan_id: string | null;
  created_at: string;
}

export interface Stage {
  id: string;
  position: number;
  stage_type: string;
  /** Capability label; the engine behind it is not exposed by the API. */
  label: string;
  status: string;
  is_active: boolean;
  target_count: number;
  rejected_count: number;
  observation_count: number;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  stats: Record<string, any>;
  time_limit_seconds?: number | null;
}

export interface Scan {
  id: string;
  organization_id: string;
  profile_id: string | null;
  profile_name: string;
  status: string;
  trigger: string;
  is_baseline: boolean;
  target_override: string[] | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  stats: Record<string, number>;
  error: string | null;
  stages?: Stage[];
}

export interface ScopeDecision {
  id: number;
  stage_id: string | null;
  target: string;
  decision: "allowed" | "rejected";
  reason: string;
  active: boolean;
  created_at: string;
}

export interface ProfileStage {
  stage: string;
  /** Opaque capability token (deployment-specific), round-tripped when editing a profile. */
  engine: string;
  config: Record<string, unknown>;
  enabled: boolean;
  optional: boolean;
  active: boolean;
  label: string | null;
  /** This stage can use a sign-in cookie/token supplied when starting a scan. */
  accepts_login?: boolean;
}

export interface ScanProfile {
  id: string;
  slug: string;
  name: string;
  description: string | null;
  stages: ProfileStage[];
  is_builtin: boolean;
  is_active_scanning: boolean;
  retain_raw_output: boolean;
  tenant_id: string | null;
}

export interface Schedule {
  id: string;
  organization_id: string;
  profile_id: string;
  name: string;
  cron: string;
  /** The cron expression in words, e.g. "Every Sunday at 09:00". */
  description: string;
  recurrence: { frequency: string; hour: number; minute: number; weekday: number | null; day: number | null } | null;
  timezone: string;
  enabled: boolean;
  next_run_at: string | null;
  last_run_at: string | null;
  last_scan_id: string | null;
}

export interface DashboardSummary {
  totals: {
    total_assets: number;
    active_assets: number;
    new_assets_7d: number;
    unknown_assets: number;
    critical_findings: number;
    high_findings: number;
    kev_findings: number;
    changes_24h: number;
    risk_score: number;
  };
  findings_by_severity: Record<Severity, number>;
  asset_types: Record<string, number>;
  most_exposed_assets: DashAsset[];
  top_vulnerable_assets: DashAsset[];
  recent_changes: DashEvent[];
  recently_opened_services: DashEvent[];
  expiring_certificates: { id: string; subject: string; issuer: string | null; not_after: string; days_left: number }[];
  technologies: { name: string; count: number }[];
  asn_distribution: { asn: string; name: string | null; count: number }[];
  hosting_distribution: { provider: string; count: number }[];
}

export interface DashAsset {
  id: string;
  asset_type: string;
  value: string;
  risk_score: number;
  risk_level: RiskLevel;
  open_findings: number;
  status: string;
  approval_status: string;
  first_seen: string;
}

export interface DashEvent {
  id: string;
  event_type: string;
  severity: Severity;
  title: string;
  asset_id: string | null;
  asset_value: string | null;
  occurred_at: string;
  acknowledged: boolean;
}

export interface TrendPoint {
  day: string;
  total_assets: number;
  active_assets: number;
  new_assets: number;
  unknown_assets: number;
  risk_score: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Report {
  id: string;
  organization_id: string | null;
  report_type: string;
  report_format: "html" | "pdf" | "csv";
  title: string;
  status: string;
  size: number | null;
  error: string | null;
  parameters: Record<string, unknown>;
  created_at: string;
  completed_at: string | null;
}

export interface Integration {
  id: string;
  name: string;
  integration_type: string;
  config: Record<string, any>;
  has_secret: boolean;
  enabled: boolean;
  last_success_at: string | null;
  last_error: string | null;
  last_error_at: string | null;
  created_at: string;
}

export interface Policy {
  id: string;
  name: string;
  enabled: boolean;
  event_types: string[];
  min_severity: Severity;
  organization_ids: string[] | null;
  integration_ids: string[];
  include_baseline: boolean;
  throttle_minutes: number;
}

export interface Member {
  user_id: string;
  email: string;
  full_name: string | null;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface AuditEntry {
  id: number;
  chain_seq: number;
  user_id: string | null;
  actor: string | null;
  action: string;
  object_type: string | null;
  object_id: string | null;
  previous: Record<string, unknown> | null;
  new: Record<string, unknown> | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  success: boolean;
  created_at: string;
}

export interface AuditVerification {
  intact: boolean;
  entries: number;
  first_tampered_id: number | null;
  first_tampered_seq: number | null;
  reason: string | null;
}

export interface Facets {
  asset_types: { value: string; count: number }[];
  statuses: { value: string; count: number }[];
  approval: { value: string; count: number }[];
  technologies: { value: string; count: number }[];
  asns: { value: string; count: number }[];
  owners: { value: string; count: number }[];
  business_units: { value: string; count: number }[];
  tags: { value: string; count: number }[];
}
