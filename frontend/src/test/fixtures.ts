// Representative API responses for UI smoke tests.
const now = "2026-09-18T09:42:00Z";
const earlier = "2026-09-17T09:42:00Z";

export const me = {
  user: { id: "u1", email: "analyst@example.com", full_name: "Sara Analyst", is_platform_admin: true, mfa_enabled: false },
  tenant: { id: "t1", name: "Acme", slug: "acme" },
  role: "platform_admin",
  permissions: [
    "assets:read", "assets:write", "findings:read", "findings:write", "findings:accept_risk", "events:read", "events:ack",
    "scans:read", "scans:run", "profiles:write", "schedules:write", "scope:read", "scope:write", "orgs:read", "orgs:write",
    "reports:read", "reports:create", "integrations:read", "integrations:write", "credentials:write", "users:read",
    "users:write", "settings:write", "audit:read", "tenants:admin", "intel:admin",
    "diagnostics:read", "support:bundles", "platform:diagnostics",
  ],
  memberships: [{ tenant: { id: "t1", name: "Acme", slug: "acme" }, role: "tenant_admin" }],
  session_idle_minutes: 30,
};

export const org = {
  id: "o1", name: "Example Corp", description: "Demo", industry: "Finance", settings: { derived_ip_scanning: true },
  is_active: true, baseline_completed_at: earlier, created_at: earlier, scope_entries: 2, assets: 40, open_findings: 9,
  risk_score: 88, last_scan_at: now,
};

const asset = {
  id: "a1", organization_id: "o1", asset_type: "subdomain", value: "vpn.example.com", status: "active",
  scope_status: "in_scope", approval_status: "unverified", owner: null, business_unit: null, criticality: "medium",
  tags: ["edge"], first_seen: earlier, last_seen: now, risk_score: 88, risk_level: "critical", open_findings: 3,
  confidence: 95, ips: ["198.51.100.7"], source_label: "Asset discovery", title: null,
};

const ref = (id: string, type: string, value: string) => ({ id, asset_type: type, value, status: "active", risk_score: 40, scope_status: "derived" });

export const assetDetail = {
  ...asset, normalized_value: asset.value,
  meta: { dns: { a: ["198.51.100.7"], aaaa: ["2001:db8::7"] }, resolves: true, discovery_sources: ["crtsh"] },
  notes: null, risk_factors: [{ key: "child", label: "Inherited from https://vpn.example.com:10443", points: 88 }],
  discovered_at: earlier, last_scanned_at: now, inactive_since: null, missed_count: 0, discovery_method: "subdomain_discovery",
  sources: ["Asset discovery", "DNS resolution"],
  relationships: [
    { relation: "resolves_to", direction: "out", active: true, first_seen: earlier, last_seen: now, attributes: {}, asset: ref("a2", "ip_address", "198.51.100.7") },
    { relation: "serves", direction: "out", active: true, first_seen: earlier, last_seen: now, attributes: {}, asset: ref("a3", "http_endpoint", "https://vpn.example.com:10443") },
    { relation: "subdomain_of", direction: "out", active: true, first_seen: earlier, last_seen: now, attributes: {}, asset: ref("a4", "root_domain", "example.com") },
  ],
};

const event = {
  id: "e1", organization_id: "o1", asset_id: "a1", asset_type: "port", asset_value: "198.51.100.7:10443/tcp",
  finding_id: null, scan_id: "s1", event_type: "port_opened", severity: "medium",
  title: "New externally exposed service: 10443/tcp on 198.51.100.7", summary: null,
  previous_state: null, new_state: { port: 10443 }, details: {}, occurred_at: now, is_baseline: false,
  acknowledged: false, acknowledged_at: null, notified: true,
};

const finding = {
  id: "f1", organization_id: "o1", asset_id: "a3", title: "Fortinet FortiOS - Path Traversal", category: "vulnerability",
  severity: "critical", status: "new", cve: ["CVE-2018-13379"], cvss_score: 9.8, epss_score: 0.97, kev: true,
  risk_score: 95, risk_level: "critical", first_seen: earlier, last_seen: now, resolved_at: null, assigned_to: null,
  tags: ["cve"], false_positive: false, location: "https://vpn.example.com:10443/remote/x",
  source_label: "Vulnerability detection", dast: false, unverified: false,
  asset: ref("a3", "http_endpoint", "https://vpn.example.com:10443"),
};

// A web vulnerability confirmed dynamically against the running application (DAST).
const dastFinding = {
  id: "f2", organization_id: "o1", asset_id: "a3", title: "SQL Injection", category: "vulnerability",
  severity: "high", status: "new", cve: [], cvss_score: null, epss_score: null, kev: false,
  risk_score: 72, risk_level: "high", first_seen: earlier, last_seen: now, resolved_at: null, assigned_to: null,
  tags: ["zap"], false_positive: false, location: "https://vpn.example.com:10443/search [q]",
  source_label: "Active web scanning", dast: true, unverified: false,
  asset: ref("a3", "http_endpoint", "https://vpn.example.com:10443"),
};

const scan = {
  id: "s1", organization_id: "o1", profile_id: "p1", profile_name: "Standard ASM", status: "completed", trigger: "manual",
  is_baseline: false, target_override: null, started_at: earlier, finished_at: now, created_at: earlier,
  stats: { new_assets: 2, events: 5, new_findings: 1 }, error: null,
  stages: [{ id: "st1", position: 0, stage_type: "dns_resolution", label: "DNS resolution", status: "completed",
    is_active: false, target_count: 6, rejected_count: 1, observation_count: 18, started_at: earlier, finished_at: now,
    error: null, stats: { duration_seconds: 3.2 } }],
};

export const stageOutput = {
  head: [[0, "info", "Stage started with 6 target(s)"], [1.2, "warning", "engine: 2 resolvers answered slowly"]],
  tail: [[3.2, "info", "Stage finished: completed, 18 observation(s) in 3 s"]],
  total: 5003, omitted: 5000, final: true, running: false, updated_at: now,
};

const profile = {
  id: "p1", slug: "standard-asm", name: "Standard ASM", description: "Recommended", is_builtin: true,
  is_active_scanning: true, retain_raw_output: false, tenant_id: null,
  stages: [{ stage: "dns_resolution", engine: "eng_0123456789abcdef", config: {}, enabled: true, optional: false,
    active: false, label: "DNS resolution", accepts_login: false }],
};

const page = <T,>(items: T[]) => ({ items, total: items.length, page: 1, page_size: 50 });

export const dashboard = {
  totals: { total_assets: 40, active_assets: 38, new_assets_7d: 2, unknown_assets: 9, critical_findings: 1, high_findings: 4,
            kev_findings: 1, changes_24h: 5, risk_score: 88 },
  findings_by_severity: { critical: 1, high: 4, medium: 3, low: 1, info: 0 },
  asset_types: { subdomain: 8, ip_address: 6, port: 7, http_endpoint: 4, certificate: 2 },
  most_exposed_assets: [{ ...asset }], top_vulnerable_assets: [{ ...asset }],
  recent_changes: [event], recently_opened_services: [event],
  expiring_certificates: [{ id: "c1", subject: "vpn.example.com", issuer: "vpn.example.com", not_after: now, days_left: 2 }],
  technologies: [{ name: "nginx", count: 1 }], asn_distribution: [{ asn: "AS64500", name: "EXAMPLE-NET", count: 3 }],
  hosting_distribution: [{ provider: "aws", count: 1 }],
};

const counts = { affected: 3, confirmed: 1, not_detected: 1, inconclusive: 0, unchecked: 1, check_pending: 0,
  reported_unverified: 0, version_unknown: 0, not_affected_version: 1, no_longer_observed: 0, remediated: 1 };

export const advisory = {
  id: "adv1", slug: "cve-2099-0001", title: "Example VPN pre-auth RCE", severity: "critical", cves: ["CVE-2099-0001"],
  status: "published", published_version: 2, source_published_at: earlier, source_updated_at: now,
  version_published_at: now, counts, last_evaluated_at: now, evaluated_version: 2, stale: false, incomplete: [], has_check: true,
};

export const advisoryDetail = {
  ...advisory, summary: "A pre-authentication remote code execution in Example VPN.", remediation: "Upgrade to 7.2.5.",
  references: ["https://vendor.example.org/psirt/2099-0001"],
  affected_products: [{ vendor: "Example", product: "Example VPN", match_names: ["example vpn"], versions: [{ introduced: "7.0", fixed: "7.2.5" }] }],
  intel: [{ cve: "CVE-2099-0001", kev: true, kev_due_date: "2026-10-01", epss_score: 0.91, cvss_score: 9.8 }],
  check: { key: "cve-2099-0001", name: "Example VPN RCE detection", description: null },
  check_runs: [{ id: "cr1", organization_id: "o1", advisory_version: 2, check_key: "cve-2099-0001", scan_id: "s1",
    asset_ids: ["a3"], status: "completed", created_at: earlier, finished_at: now, summary: { detected: 1, not_detected: 1, inconclusive: 0 } }],
};

const evidence = (version: string | null, reason: string) => ({ observations: [{ product: "Example VPN", vendor: "Example",
  matched_name: "example vpn", version, source: "technology", verdict: "potentially_affected", reason, observed_at: now, third_party: false }] });

export const threatMatches = [
  { id: "m1", organization_id: "o1", asset: ref("a3", "http_endpoint", "https://vpn.example.com:10443"), owner: "Network team",
    business_unit: "IT", basis: "product", match_status: "potentially_affected", assessment: "confirmed",
    evidence: evidence("7.2.1", "version 7.2.1 is inside the affected range (from 7.0, fixed in 7.2.5)"),
    findings: [{ id: "f1", title: "Fortinet FortiOS - Path Traversal", severity: "critical", status: "new", unverified: false }],
    check_outcome: "detected", check_detail: "the approved check reported the issue on this asset", checked_at: now,
    remediation_status: "in_progress", assigned_to: null, remediation_note: null, first_matched_at: earlier, last_evaluated_at: now, advisory_version: 2 },
  { id: "m2", organization_id: "o1", asset: ref("a5", "http_endpoint", "https://vpn2.example.com"), owner: null, business_unit: null,
    basis: "product", match_status: "potentially_affected", assessment: "not_detected",
    evidence: evidence("7.1.0", "version 7.1.0 is inside the affected range (from 7.0, fixed in 7.2.5)"), findings: [],
    check_outcome: "not_detected", check_detail: "the check completed without detecting the issue. This is not proof the asset is safe",
    checked_at: now, remediation_status: "open", assigned_to: null, remediation_note: null, first_matched_at: earlier, last_evaluated_at: now, advisory_version: 2 },
  { id: "m3", organization_id: "o1", asset: ref("a6", "service", "198.51.100.9:443/tcp"), owner: null, business_unit: null,
    basis: "product", match_status: "version_unknown", assessment: "version_unknown",
    evidence: evidence(null, "the product was seen but no version was reported"), findings: [],
    check_outcome: "none", check_detail: null, checked_at: null, remediation_status: "open", assigned_to: null, remediation_note: null,
    first_matched_at: earlier, last_evaluated_at: now, advisory_version: 2 },
];

export const advisoryAdmin = {
  id: "adv1", slug: "cve-2099-0001", title: advisory.title, severity: "critical", status: "published", published_version: 2,
  version_published_at: now, updated_at: now, has_draft: true, draft_version: 3, versions: [],
  draft: { title: advisory.title, summary: "x", severity: "critical", cves: ["CVE-2099-0001"], references: [], remediation: "",
    affected: advisoryDetail.affected_products, check_keys: ["cve-2099-0001"], source_published_at: null, source_updated_at: null },
  published: null,
};

export const screenshotStatus = {
  available: true, enabled: true, cadence: "manual", reason: null,
  usage: { stored_bytes: 170000, captures_today: 2, active: 0 },
  limits: { per_tenant_daily: 50, per_tenant_queued: 10, retention_per_endpoint: 2, storage_quota_mb: 200,
    timeout_seconds: 20, viewport_width: 1280, viewport_height: 800 },
};

export const capture = (id: string, status: string, extra: Record<string, unknown> = {}) => ({
  id, asset_id: "a3", status, trigger: "manual", error: null, created_at: now, started_at: now, finished_at: now,
  captured_at: status === "succeeded" ? now : null, final_url: status === "succeeded" ? "https://vpn.example.com:10443/remote/login" : null,
  page_title: status === "succeeded" ? "Fortinet SSL VPN Login" : null, http_status: status === "succeeded" ? 200 : null,
  size: status === "succeeded" ? 84869 : null, width: 1280, height: 800, sha256: null, has_image: status === "succeeded", ...extra,
});

export const screenshotPolicy = { available: true, max_concurrent: 1, per_tenant_daily: 50, per_tenant_queued: 10,
  retention_per_endpoint: 2, storage_quota_mb: 200, failed_retention_days: 30, timeout_seconds: 20, viewport_width: 1280,
  viewport_height: 800, max_image_kb: 2048 };

const xnode = (id: string, type: string, labelText: string, depth: number, extra: Record<string, unknown> = {}) => ({
  id, kind: "asset", type, label: labelText, status: "active", scope_status: "in_scope", risk_score: 40, open_findings: 0,
  first_seen: earlier, last_seen: now, depth, hidden: {}, third_party_only: false, ...extra,
});
const xedge = (id: string, source: string, target: string, relation: string, freshness: string, extra: Record<string, unknown> = {}) => ({
  id, source, target, relation, meaning: `${relation} meaning`, active: freshness !== "inactive", evidence: "observed",
  source_label: "DNS resolution", first_seen: earlier, last_seen: now, age_days: 0, freshness, ...extra,
});

export const exposureMap = {
  organization: { id: "o1", name: "Example Corp" }, root_ids: ["x1"], expanded: null,
  nodes: [
    xnode("x1", "root_domain", "example.com", 0, { hidden: { subdomain_of: 40 } }),
    xnode("x2", "subdomain", "vpn.example.com", 1),
    xnode("x3", "ip_address", "198.51.100.7", 2, { scope_status: "derived" }),
    xnode("x4", "port", "198.51.100.7:10443/tcp", 3, { third_party_only: true }),
    xnode("x5", "http_endpoint", "https://vpn.example.com:10443", 2),
    xnode("x6", "ip_address", "198.51.100.99", 2, { status: "inactive" }),
    { id: "f:f1", kind: "finding", finding_id: "f1", type: "finding", label: "Fortinet FortiOS - Path Traversal", severity: "critical",
      status: "new", unverified: false, risk_score: 95, first_seen: earlier, last_seen: now, depth: 3, hidden: {} },
  ],
  edges: [
    xedge("e1", "x2", "x1", "subdomain_of", "current", { evidence: "derived", source_label: "Platform (from names)",
      meaning: "Naming: this host name is under the domain. Derived from the names, not a network connection." }),
    xedge("e2", "x2", "x3", "resolves_to", "stale", { age_days: 40 }),
    xedge("e3", "x3", "x4", "has_port", "historical", { source_label: "Internet exposure intelligence" }),
    xedge("e4", "x2", "x5", "serves", "current"),
    xedge("e5", "x2", "x6", "resolves_to", "inactive"),
    xedge("hf:f1", "x5", "f:f1", "has_finding", "current", { source_label: "Vulnerability detection" }),
  ],
  truncated: false, truncation_reasons: [],
  limits: { depth: 2, max_nodes: 150, max_edges: 450, per_node: 25, time_budget_ms: 4000 }, elapsed_ms: 12,
  notice: "Observed relationships only. A line never means one asset can be used to reach another.",
};

export const feedConfig = {
  settings: { enabled: true, publish: "kev", include_critical: false, critical_days: 30, auto_checks: true,
    aliases: { "acme:widget_server": ["acme widget"] } },
  builtin_aliases: { "apache:http_server": ["apache", "apache http server"] },
  status: { items: 1480, kev_items: 1450, by_status: { published: 1450, draft: 30 }, has_api_key: false,
    sources: { kev: { last_success_at: now, last_attempt_at: now, last_error: null, records: 3 }, critical: null } },
};


const unavailable = (reason: string) => ({ status: "unavailable", reason });
const diagStage = { id: "st1", position: 0, stage_type: "discovery", label: "Passive subdomain discovery", status: "partial",
  coverage: "partial", target_count: 1, rejected_count: 0, observation_count: 12, error: "timed out after 600s",
  started_at: earlier, dispatched_at: earlier, finished_at: now,
  timing: { queue_wait_ms: 1200, execution_ms: 600000, ingestion_ms: 340, total_ms: 601540, timed_out: true, retries: 0 },
  timed_out: true, retries: 0 };
export const diagScan = { id: "s1", organization_id: "o1", profile: "Standard ASM", status: "partial", trigger: "manual",
  created_at: earlier, started_at: earlier, finished_at: now, stages: [diagStage],
  summary: { queue_wait_ms: 1200, execution_ms: 600000, partial_stages: 1, failed_stages: 0, timeouts: 1 } };
export const readyBundle = { id: "b1", scope: "tenant", status: "ready", progress: 100, error: null, window_start: earlier, window_end: now,
  scan_ids: ["s1"], size: 4096, sha256: "ab".repeat(32), filename: "exteriq-support-tenant-20260925-1200-b1.zip",
  created_at: now, finished_at: now, expires_at: now,
  contents: { files: [{ name: "scans.jsonl", bytes: 900, sha256: "cd".repeat(32) }, { name: "stage-output/s1-0.txt", bytes: 1200, sha256: "ef".repeat(32) }],
    truncated: [], included: ["scan timelines"], omitted: ["database dumps"] } };
export const bundlePreview = { scope: "tenant", window_start: earlier, window_end: now,
  included: ["scan timelines", "diagnostic events"], excluded: ["environment files, keys and every other secret", "database dumps"],
  counts: { scans_selected: 1, scans_in_window: 3, audit_actions: 12 }, limits: { max_mb: 50, max_seconds: 120, retention_days: 7 } };
const platformHealth = { collected_at: now, version: "1.4.0",
  database: { status: "ok", server_version: "18.1", schema_version: "0013", expected_schema: "0013", size_bytes: 52428800, connections: 9 },
  host: { hostname: "asm-1", cpus: 4, load: [0.4, 0.3, 0.2], memory: { total_bytes: 8589934592, available_bytes: 4294967296 },
    disks: { data: { path_label: "data", total_bytes: 100e9, free_bytes: 60e9 }, tmp: unavailable("tmp storage is not accessible from this process") },
    cgroup_oom_kills: 0 },
  units: unavailable("not a native install (systemd unit data is available on native installs only)"),
  broker: { status: "ok" },
  services: { api: { status: "ok", instances: 2, versions: ["1.4.0"], last_seen_seconds: 4 },
    worker: { status: "ok", instances: 1, versions: ["1.4.0"], last_seen_seconds: 10 },
    ingest: unavailable("no heartbeat in the last 90 seconds"),
    scheduler: { status: "ok", instances: 1, versions: ["1.4.0"], last_seen_seconds: 12 } },
  scanners: { default: { status: "ok", instances: [{ host: "scan-1", pid: 7, version: "1.4.0", detection_rules: { available: true, count: 9000 },
    last_job: { status: "completed", ts: now }, ts: now }], recent_errors: [] } },
  queues: { core: { depth: 0, oldest_age_seconds: null, age_note: null }, "scanners.default": { depth: 3, oldest_age_seconds: 42, age_note: null } } };

export function mockApi(path: string): unknown {
  const routes: [RegExp, unknown][] = [
    [/^\/diagnostics\/tenant\/overview$/, { window_days: 7, scans: { completed: 4, partial: 1 },
      stages: { finished: 30, partial: 1, failed: 0, timeouts: 1 }, queue_wait_ms_p50: 1200,
      execution_ms_p50: unavailable("no stage timing recorded in the last 7 days"), notification_failures: 0,
      scanner: { status: "ok", instances: 1, detection_content: "installed", dedicated: true } }],
    [/^\/diagnostics\/(tenant|platform)\/scans$/, { items: [diagScan], total: 1, page: 1, page_size: 50 }],
    [/^\/diagnostics\/tenant\/events$/, { items: [{ ts: now, kind: "scan_stage", level: "warning", title: "Passive subdomain discovery: partial",
      detail: "timed out after 600s", scan_id: "s1" }], page: 1, page_size: 50, has_more: false }],
    [/^\/diagnostics\/platform\/health$/, platformHealth],
    [/^\/diagnostics\/platform\/events$/, { items: [{ id: 1, event_id: "e1", ts: now, level: "ERROR", service: "worker", event: "notification.failed",
      error_code: "ASM-NTF-001", message: "delivery failed", tenant_id: "t1", request_id: null, scan_id: null, pool: null, data: null }],
      total: 1, page: 1, page_size: 50 }],
    [/^\/diagnostics\/bundles\/preview$/, bundlePreview],
    [/^\/diagnostics\/bundles$/, [readyBundle]],
    [/^\/setup$/, { needed: true }],
    [/^\/exposure-map$/, exposureMap],
    [/^\/screenshots\/status$/, screenshotStatus],
    [/^\/assets\/[^/]+\/screenshots$/, { status: screenshotStatus, latest: capture("sc1", "succeeded"), captures: [capture("sc1", "succeeded")] }],
    [/^\/settings\/screenshots$/, { policy: screenshotPolicy, defaults: screenshotPolicy,
      bounds: { max_concurrent: [1, 8], per_tenant_daily: [1, 5000] } }],
    [/^\/threats$/, page([advisory])],
    [/^\/threats\/[^/]+\/assets$/, page(threatMatches)],
    [/^\/threats\/[^/]+\/checks$/, advisoryDetail.check_runs],
    [/^\/threats\/[^/]+$/, advisoryDetail],
    [/^\/threat-catalog$/, [advisoryAdmin]],
    [/^\/threat-catalog\/feed$/, feedConfig],
    [/^\/threat-catalog\/checks$/, [{ key: "cve-2099-0001", name: "Example VPN RCE detection", description: null, kind: "detection_template",
      template_id: "cve-2099-0001", enabled: true, updated_at: now }]],
    [/^\/threat-catalog\/[^/]+$/, advisoryAdmin],
    [/^\/auth\/me$/, me],
    [/^\/auth\/api-tokens$/, []],
    [/^\/organizations$/, [org]],
    [/^\/organizations\/[^/]+$/, org],
    [/^\/scopes$/, [{ id: "sc1", organization_id: "o1", entry_type: "domain", value: "example.com", include_subdomains: true,
      is_exclusion: false, allow_active_scanning: true, verification_status: "not_required", verified_at: null, notes: null, created_at: earlier }]],
    [/^\/dashboard\/summary$/, dashboard],
    [/^\/dashboard\/trends$/, [{ day: "2026-09-17", total_assets: 38, active_assets: 38, new_assets: 38, unknown_assets: 9, risk_score: 80, critical: 1, high: 3, medium: 3, low: 1 },
                              { day: "2026-09-18", total_assets: 40, active_assets: 38, new_assets: 2, unknown_assets: 9, risk_score: 88, critical: 1, high: 4, medium: 3, low: 1 }]],
    [/^\/assets\/facets$/, { asset_types: [], statuses: [], approval: [], technologies: [{ value: "nginx", count: 1 }], asns: [], owners: [], business_units: [], tags: [] }],
    [/^\/assets$/, page([asset])],
    [/^\/assets\/[^/]+\/timeline$/, page([event])],
    [/^\/assets\/[^/]+\/observations$/, page([{ id: 1, scan_id: "s1", source_label: "DNS resolution", observed_at: now, data: { resolves: true } }])],
    [/^\/assets\/[^/]+$/, assetDetail],
    [/^\/findings$/, page([finding, dastFinding])],
    [/^\/dashboard\/web-apps$/, page([{ id: "a3", url: "https://vpn.example.com:10443", host: "vpn.example.com",
      title: "Fortinet SSL VPN Login", webserver: "nginx", technologies: ["nginx"], status_code: 200,
      risk_score: 95, risk_level: "critical", approval_status: "unverified", open_findings: 3,
      by_severity: { critical: 1, high: 1, medium: 1, low: 0, info: 0 }, dast_verified: 1, crawled: true,
      first_seen: earlier, last_seen: now, last_scanned_at: now }])],
    [/^\/findings\/[^/]+\/activity$/, [{ id: "ac1", user_id: null, user_email: null, activity_type: "detected", previous: null, new: { severity: "critical" }, comment: null, scan_id: "s1", created_at: earlier }]],
    [/^\/findings\/[^/]+$/, { ...finding, description: "Path traversal", remediation: "Upgrade", references: [], evidence: { matcher: "x" },
      cwe: ["CWE-22"], cvss_vector: "CVSS:3.1/AV:N", epss_percentile: 0.99, kev_due_date: null, exploit_available: true, confidence: 90,
      occurrence_count: 2, notes: null, accepted_until: null, source_finding_id: "CVE-2018-13379",
      risk_factors: [{ key: "kev", label: "Known exploited in the wild (CISA KEV)", points: 20 }] }],
    [/^\/events$/, page([event])],
    [/^\/scans$/, page([scan])],
    [/^\/scans\/[^/]+\/decisions$/, page([{ id: 1, stage_id: "st1", target: "dev-api.example.com", decision: "rejected", reason: "hostname excluded from scope", active: false, created_at: now }])],
    [/^\/scans\/[^/]+\/stages\/[^/]+\/output$/, stageOutput],
    [/^\/scans\/[^/]+$/, scan],
    [/^\/scan-profiles$/, [profile]],
    [/^\/schedules$/, [{ id: "sch1", organization_id: "o1", profile_id: "p1", name: "Nightly", cron: "0 2 * * *", description: "Every day at 02:00", recurrence: { frequency: "daily", hour: 2, minute: 0, weekday: null, day: null }, timezone: "Asia/Riyadh", enabled: true, next_run_at: now, last_run_at: earlier, last_scan_id: "s1" }]],
    [/^\/reports$/, page([{ id: "r1", organization_id: "o1", report_type: "executive", report_format: "html", title: "Executive Attack Surface Report",
      status: "completed", size: 20480, error: null, parameters: {}, created_at: now, completed_at: now }])],
    [/^\/integrations$/, [{ id: "i1", name: "Wazuh", integration_type: "wazuh", config: { mode: "syslog", host: "wazuh", port: 514, protocol: "udp" },
      has_secret: false, enabled: true, last_success_at: now, last_error: null, last_error_at: null, created_at: earlier }]],
    [/^\/integrations\/policies$/, [{ id: "pl1", name: "High+", enabled: true, event_types: [], min_severity: "high", organization_ids: null,
      integration_ids: ["i1"], include_baseline: false, throttle_minutes: 0 }]],
    [/^\/integrations\/deliveries$/, []],
    [/^\/credentials\/providers$/, [{ provider: "shodan", used_by: ["Passive subdomain discovery"] }]],
    [/^\/credentials$/, []],
    [/^\/users$/, [{ user_id: "u1", email: "analyst@example.com", full_name: "Sara Analyst", role: "tenant_admin", is_active: true,
      mfa_enabled: false, last_login_at: now, created_at: earlier }]],
    [/^\/settings$/, { effective: { inactivity: { default: 3, port: 2 }, risk: { kev_points: 20, severity_points: { critical: 55 }, levels: { critical: 80, high: 60, medium: 35, low: 15 } },
      scanning: { require_scope_verification: false }, detection_rules: { risky_ports: true }, branding: {} }, defaults: {} }],
    [/^\/audit-logs\/verify$/, { intact: true, entries: 7, first_tampered_id: null, first_tampered_seq: null, reason: null }],
    [/^\/audit-logs$/, page([{ id: 7, chain_seq: 7, user_id: "u1", actor: "analyst@example.com", action: "scope.added", object_type: "scope_entry",
      object_id: "sc1", previous: null, new: { value: "example.com" }, ip_address: "10.0.0.5", user_agent: null, request_id: null, success: true, created_at: now }])],
    [/^\/tenants\/plans$/, [{ id: "pl", code: "self-hosted", name: "Self-hosted", max_assets: null, max_concurrent_scans: 4 }]],
    [/^\/tenants$/, [{ id: "t1", name: "Acme", slug: "acme", status: "active", worker_pool: "default", data_region: "sa-central",
      plan: { id: "pl", code: "self-hosted", name: "Self-hosted", max_assets: null, max_concurrent_scans: 4 }, created_at: earlier },
    { id: "t2", name: "Beta Holding", slug: "beta", status: "active", worker_pool: "default", data_region: null,
      plan: { id: "pl", code: "self-hosted", name: "Self-hosted", max_assets: null, max_concurrent_scans: 4 }, created_at: earlier }]],
  ];
  for (const [re, body] of routes) if (re.test(path)) return structuredClone(body);
  throw new Error(`unmocked API path ${path}`);
}
