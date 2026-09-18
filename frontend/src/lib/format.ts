export function fmtDate(v: string | null | undefined): string {
  if (!v) return "—";
  const d = new Date(v);
  return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

export function fmtDay(v: string | null | undefined): string {
  if (!v) return "—";
  return new Date(v).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "2-digit" });
}

export function timeAgo(v: string | null | undefined): string {
  if (!v) return "—";
  const s = Math.round((Date.now() - new Date(v).getTime()) / 1000);
  if (s < 60) return "just now";
  const m = Math.round(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  const d = Math.round(h / 24);
  if (d < 60) return `${d}d ago`;
  return fmtDay(v);
}

/** 42s · 7m · 1h 05m */
export function fmtDuration(seconds: number): string {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  return `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

export function label(v: string | null | undefined): string {
  if (!v) return "—";
  return v.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase());
}

export const ASSET_TYPE_LABELS: Record<string, string> = {
  root_domain: "Root domain",
  domain: "Domain",
  subdomain: "Subdomain",
  ip_address: "IP address",
  cidr: "Network",
  asn: "ASN",
  dns_record: "DNS record",
  certificate: "Certificate",
  port: "Open port",
  service: "Service",
  http_endpoint: "Web endpoint",
  web_application: "Web application",
  technology: "Technology",
  cloud_resource: "Cloud resource",
};

export const PRIMARY_TYPES = [
  "root_domain", "domain", "subdomain", "ip_address", "cidr", "port", "http_endpoint", "certificate", "cloud_resource",
];

export const APPROVAL_STATES = ["unverified", "approved", "expected", "third_party", "unknown", "unauthorized", "decommissioned"];
export const FINDING_STATES = ["new", "investigating", "accepted_risk", "false_positive", "remediated", "reopened"];
export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export const EVENT_LABELS: Record<string, string> = {
  new_asset: "New asset",
  new_subdomain: "New subdomain",
  asset_disappeared: "Asset disappeared",
  asset_reappeared: "Asset reappeared",
  dns_changed: "DNS changed",
  ip_changed: "IP changed",
  port_opened: "Port opened",
  port_closed: "Port closed",
  service_detected: "Service detected",
  service_changed: "Service changed",
  certificate_changed: "Certificate changed",
  certificate_expiring: "Certificate expiring",
  certificate_expired: "Certificate expired",
  technology_detected: "Technology detected",
  technology_changed: "Technology changed",
  technology_removed: "Technology removed",
  vulnerability_detected: "Vulnerability detected",
  vulnerability_resolved: "Vulnerability resolved",
  vulnerability_reopened: "Vulnerability reopened",
  risk_increased: "Risk increased",
  risk_decreased: "Risk decreased",
  asset_exposed: "New exposure",
  ownership_changed: "Ownership changed",
  approval_changed: "Approval changed",
  hosting_changed: "Hosting changed",
  shadow_it_discovered: "Shadow IT",
  scan_failed: "Scan failed",
  scan_completed: "Scan completed",
};

export const SEV_COLOR: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function riskColor(score: number): string {
  if (score >= 80) return SEV_COLOR.critical;
  if (score >= 60) return SEV_COLOR.high;
  if (score >= 35) return SEV_COLOR.medium;
  if (score >= 15) return SEV_COLOR.low;
  return SEV_COLOR.info;
}

export function compactDiff(prev: unknown, next: unknown): string {
  if (!prev && !next) return "";
  const s = (v: unknown) => (v === null || v === undefined ? "—" : typeof v === "string" ? v : JSON.stringify(v));
  return `${s(prev)} → ${s(next)}`;
}

export function bytes(n: number | null | undefined): string {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
