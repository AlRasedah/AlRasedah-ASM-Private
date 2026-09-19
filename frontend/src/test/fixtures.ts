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
  ],
  memberships: [{ tenant: { id: "t1", name: "Acme", slug: "acme" }, role: "tenant_admin" }],
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
  source: "nuclei", source_label: "Vulnerability detection",
  asset: ref("a3", "http_endpoint", "https://vpn.example.com:10443"),
};

// A dynamically-confirmed web vulnerability from the OWASP ZAP active scanner (DAST).
const dastFinding = {
  id: "f2", organization_id: "o1", asset_id: "a3", title: "SQL Injection", category: "vulnerability",
  severity: "high", status: "new", cve: [], cvss_score: null, epss_score: null, kev: false,
  risk_score: 72, risk_level: "high", first_seen: earlier, last_seen: now, resolved_at: null, assigned_to: null,
  tags: ["zap"], false_positive: false, location: "https://vpn.example.com:10443/search [q]",
  source: "zap_active", source_label: "Active web scanning",
  asset: ref("a3", "http_endpoint", "https://vpn.example.com:10443"),
};

const scan = {
  id: "s1", organization_id: "o1", profile_id: "p1", profile_name: "Standard ASM", status: "completed", trigger: "manual",
  is_baseline: false, target_override: null, started_at: earlier, finished_at: now, created_at: earlier,
  stats: { new_assets: 2, events: 5, new_findings: 1 }, error: null,
  stages: [{ id: "st1", position: 0, stage_type: "dns_resolution", label: "DNS resolution", engine: "dnsx", status: "completed",
    is_active: false, target_count: 6, rejected_count: 1, observation_count: 18, started_at: earlier, finished_at: now,
    error: null, stats: { duration_seconds: 3.2 } }],
};

const profile = {
  id: "p1", slug: "standard-asm", name: "Standard ASM", description: "Recommended", is_builtin: true,
  is_active_scanning: true, retain_raw_output: false, tenant_id: null,
  stages: [{ stage: "dns_resolution", engine: "dnsx", config: {}, enabled: true, optional: false, active: false, label: "DNS resolution" }],
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

export function mockApi(path: string): unknown {
  const routes: [RegExp, unknown][] = [
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
    [/^\/assets\/[^/]+\/observations$/, page([{ id: 1, scan_id: "s1", source: "dnsx", source_label: "DNS resolution", observed_at: now, data: { resolves: true } }])],
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
    [/^\/scans\/[^/]+$/, scan],
    [/^\/scan-profiles$/, [profile]],
    [/^\/schedules$/, [{ id: "sch1", organization_id: "o1", profile_id: "p1", name: "Nightly", cron: "0 2 * * *", timezone: "Asia/Riyadh", enabled: true, next_run_at: now, last_run_at: earlier, last_scan_id: "s1" }]],
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
