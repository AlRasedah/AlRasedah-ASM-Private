# Security design

Exteriq ASM stores a map of customers' attack surfaces and drives scanners — a
high-value target. This document lists the threats considered and the controls in place.

## Threats and controls

| Threat | Controls |
|---|---|
| Cross-tenant data access | `tenant_id` on every tenant row; PostgreSQL RLS **forced** on all tenant tables; app connects as non-superuser, non-BYPASSRLS role; sessions without context see nothing; API-level ownership checks; tests for reads, writes, updates and deletes across tenants |
| Scanning without authorization | Explicit per-organization scope (domains/IPs/CIDRs, exclusions win); every target checked before each stage; active stages require `allow_active_scanning`; ownership verification (`require_scope_verification`, or platform-wide `ASM_REQUIRE_SCOPE_VERIFICATION` which tenants cannot switch off) accepts only proof — DNS TXT for domains, platform-administrator approval for IPs/CIDRs — never entries recorded while it was off; CIDR size limits; all decisions logged in `scope_decisions`; out-of-scope assets are never scanned |
| Scanning internal infrastructure through customer DNS | Active scanning never targets non-public destinations (loopback, RFC 1918, link-local/metadata, CGNAT), whether from scope entries or addresses in-scope names resolve to; sensors re-resolve every active target just before connecting and drop non-public or scope-excluded destinations; ZAP is confined to the exact authorized origin and seeds without redirects; an egress firewall on the scanner network closes the DNS-rebinding window (DEPLOYMENT.md §5) |
| Intrusive or destructive scanning | Safe profiles by default; Nuclei `dos`/`fuzz`/`intrusive`/brute-force classes excluded (`dos` cannot be re-enabled); interactsh (out-of-band) disabled by default; code/headless templates never enabled; connect scans (no raw sockets); global and per-profile rate caps; scanner identification header |
| Command / argument injection | No shell (`create_subprocess_exec`); executable allowlist per adapter; strict pydantic configs with `extra="forbid"` (no free-form arguments); targets re-validated in the sensor (no leading `-`, no whitespace/metacharacters, IDNA normalization) and passed via files; port specs and tags validated by regex |
| Compromised scanner binary | Sensors run in separate containers with no database credentials, no access to the data network, non-root, read-only root FS, all capabilities dropped, `no-new-privileges`, resource limits. Worker pools are isolated from the platform and each other: per-pool broker ACL users (own job/result queues and keys only; no `core` queue, no admin commands), per-pool keys derived from a master key the sensors never see, results as MAC'd envelopes consumed by a separate app that runs nothing but result submission and accepts a result only for the job persisted for that stage (job id, tenant, scan, stage, engine, pool). A compromised scanner can affect only its own pool's jobs — give tenants that must not share scanners their own pool |
| False remediation from broken scans | Coverage (the basis for "port closed", "asset gone", "finding resolved") is accepted only from runs that proved they finished: errors, failed/timed-out processes, deadlines, result limits and truncated output all make a run partial and coverage-free, enforced in the sensor and again at ingestion |
| Shared DAST state | One job per ZAP daemon at a time (pool-wide lease) in a fresh session wiped afterwards; unique context/rule names; alerts filtered to the job's origin; remote scans stopped on deadline/cancellation |
| Credential theft | Argon2id (64 MiB, t=3); lockout after repeated failures; rate limiting per IP and per account; constant-time comparisons and timing equalization for unknown users; generic error messages; MFA (TOTP). Account-security changes (password, MFA enrollment/removal, API-token management) require an interactive session — never an API token — and MFA enrollment re-asks for the password |
| Session hijacking | 15-minute access tokens kept in memory; refresh tokens opaque, hashed (HMAC-SHA256) at rest, rotated on each use, reuse ⇒ session revoked; `HttpOnly; Secure; SameSite=Strict` cookies scoped to the auth path; double-submit CSRF on refresh; server-side revocation checked on every request; role re-read from the database per request |
| Secret disclosure | Scanner and integration secrets encrypted with AES-256-GCM, AAD-bound to tenant + name, key rotation via key ids; never returned by the API (last four chars only); sealed (AES-GCM, bound to job id) inside broker messages to sensors; log redaction filter |
| SSRF via integrations | Outbound URLs restricted to http(s), no embedded credentials, no redirects; `ASM_ALLOW_PRIVATE_WEBHOOK_TARGETS=false` blocks private/reserved destinations (recommended for SaaS); SpiderFoot URL is deployment config, not user input; Wazuh file output restricted to a fixed export directory with a validated file name |
| Injection in UI / reports | React escaping; Jinja2 autoescape; HTML reports served with `CSP: default-src 'none'; sandbox`; CSV exports neutralize formula injection |
| Tampering with evidence | `audit_logs` append-only (trigger blocks UPDATE/DELETE/TRUNCATE) and hash-chained per tenant (`verify-audit`); finding history is immutable activity records |
| Abuse / DoS of the API | nginx request limits (stricter on `/auth`), application rate limiter (Redis-backed), request size limits, pagination caps |
| Supply chain | Tools compiled from pinned upstream versions; image build args to pin/upgrade; third-party inventory in THIRD_PARTY_LICENSES.md |

## Hardening recommendations

1. **Separate database role for workers** (SaaS): create a second role with `BYPASSRLS`
   for scheduler/maintenance only and remove the `app.bypass_rls` GUC path from API
   processes (`app/db/rls.py` policies keep working unchanged).
2. Put sensors on dedicated hosts with a fixed egress IP and firewall them from internal
   networks and metadata endpoints (`sensors` network already blocks the database; the
   application-level destination checks cannot fully prevent DNS rebinding on their own).
3. Set `ASM_REQUIRE_SCOPE_VERIFICATION=true` for self-service SaaS (tenants cannot opt out).
   Existing unproven scope then needs verification/approval before active scanning.
4. Set `ASM_ALLOW_PRIVATE_WEBHOOK_TARGETS=false` unless integrations target internal SIEMs.
5. Store `.env` in a secrets manager; use the `SecretsBackend` seam for Vault/KMS.
6. Enforce MFA for tenant administrators (policy hook: `users.mfa_enabled`).

## Reporting vulnerabilities

Report security issues privately to AlRasedah's security contact; do not open public issues.
