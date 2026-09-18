# 10. Design decisions (ADR log)

Short records of the decisions that shape the code. Format: context → decision →
consequences → alternatives considered.

## ADR-001 Own platform, tools as sensors
**Context**: requirement to own data, logic and UI; tools must be replaceable.
**Decision**: independent platform; each tool wrapped by an adapter emitting a
scanner-independent schema; tools run in separate containers.
**Consequences**: adapters must be maintained per tool version; no tool-specific columns.
**Alternatives**: forking SpiderFoot/reNgine (rejected: ownership, licensing, coupling).

## ADR-002 Coverage statements for disappearance
**Context**: "not seen" is ambiguous — gone, or never looked?
**Decision**: sensors declare liveness/relation/finding coverage with constraints; failed runs
declare none; consecutive-miss thresholds per type.
**Consequences**: adapters must reason about completeness; reliable closed/gone/resolved events.
**Alternatives**: "anything not seen in this scan is gone" (false alarms on every partial
or passive scan); time-only expiry (slow, still kept as `max_age_days` fallback).

## ADR-003 Stages read targets from the database
**Decision**: `build_targets` derives inputs from inventory, not from the previous tool's
output.
**Consequences**: every known asset is re-checked each scan (enables disappearance and
reappearance), stages are independent and re-orderable in profiles.

## ADR-004 PostgreSQL for graph and history
**Decision**: relationships in `asset_relationships`, history in `asset_observations` and
`asset_events`; no graph database, no Elasticsearch.
**Consequences**: one datastore to operate/back up; graph queries are 1–2 hop joins which is
all the product needs today. Revisit only with demonstrated need.

## ADR-005 Tenant isolation with forced RLS + GUC context
**Decision**: `tenant_id` everywhere; FORCE RLS; app role non-superuser/NOBYPASSRLS;
transaction-local `app.tenant_id` set by a session listener; explicit `system_session` for
cross-tenant work.
**Consequences**: a forgotten filter fails closed; cross-tenant counts must use a system
session (see the concurrency bug in the build log). The bypass GUC could be set by a SQL
injection — mitigated by ORM-only queries; SaaS hardening: separate BYPASSRLS role for
workers.
**Alternatives**: schema-per-tenant or DB-per-tenant (heavier ops, migrations × N).

## ADR-006 Synchronous SQLAlchemy everywhere
**Decision**: sync SQLAlchemy 2.x + psycopg 3; FastAPI sync endpoints in the threadpool.
**Consequences**: identical service code in API and Celery; simpler transactions. The async
sensor framework is isolated in its own package.
**Alternatives**: async SQLAlchemy in the API + sync in workers (duplicated code paths).

## ADR-007 Celery state machine, sensors on their own queues
**Decision**: `start_scan → advance_scan → chain(sensor on scanners.<pool>, ingest on core)
→ advance_scan`, errback `stage_failed`, watchdog for lost jobs; results via the broker.
**Consequences**: no task blocks waiting on another; sensors need only broker credentials;
per-tenant pools come for free. Large results travel through Redis/Valkey (gzip-compressed).
**Alternatives**: sensors writing to the DB directly (breaks isolation), Kafka (unjustified).

## ADR-008 Inline mode
**Decision**: `ASM_SENSOR_MODE=inline` runs the same orchestrator synchronously.
**Consequences**: tests and development need no broker; must never be used in production
(the sensor container is the security boundary).

## ADR-009 Enums as VARCHAR
**Decision**: `enum_column()` stores StrEnums as VARCHAR without CHECK constraints.
**Consequences**: new event/asset types without migrations; validation in the application.

## ADR-010 Baseline scans do not alert
**Decision**: first successful scan per organization marks events `is_baseline`.
**Consequences**: no alert storm on onboarding; policies can opt in.

## ADR-011 Risk is explainable and configurable
**Decision**: additive factors (severity/CVSS, KEV, EPSS, exploit, exposure, admin surface,
risky port, criticality, shadow IT, novelty, age) × confidence, stored per finding/asset,
weights in tenant settings; parents inherit children.
**Consequences**: analysts see why; tuning without code. Not a statistical model — tune on
real data.

## ADR-012 Platform detection rules reuse the sensor path
**Decision**: rules emit a `SensorResult` (`source="asm-rules"`) ingested like any sensor.
**Consequences**: dedup, history, auto-resolution, events and risk for free; one code path.

## ADR-013 Security choices for sensors
No shell; allowlisted binaries; strict configs without free-form args; targets via files;
connect scans (no raw sockets); Nuclei safe classes with `dos` non-removable; interactsh off
(also keeps data in-region); scanner identification header; httpx follows same-host
redirects only.

## ADR-014 Tokens: short JWT + rotating opaque refresh cookie
**Decision**: in-memory 15-minute JWT; refresh token hashed server-side, rotated each use,
reuse ⇒ revoke; SameSite=Strict HttpOnly cookie on the auth path + double-submit CSRF;
server-side session check each request.
**Alternatives**: long-lived JWTs (no revocation), tokens in localStorage (XSS exposure).

## ADR-015 Explicit port sets, never "top N"
**Decision**: platform-defined port lists passed with `-p`.
**Consequences**: coverage is exact; results are stable across tool versions.

## ADR-016 Licensing-driven component choices
- Valkey instead of Redis ≥ 7.4 (RSAL/SSPL is a problem for SaaS).
- Nmap not integrated (NPSL restricts commercial redistribution).
- BBOT (GPL-3.0) optional, not installed by default, executed only as a program.
- MinIO (AGPL) only as an optional dev profile.
- Platform license left as a proprietary placeholder — a business decision.
See `THIRD_PARTY_LICENSES.md`.

## ADR-017 Portable infrastructure
Docker Compose default; PostgreSQL, Valkey, nginx, S3-compatible storage; intel feeds
mirrorable/importable offline; no hyperscaler services — deployable entirely in-Kingdom.
Kubernetes later maps services 1:1 to Deployments/Jobs without code changes.

## ADR-018 Permissive email syntax
**Decision**: accept any `local@domain` (lower-cased) instead of strict RFC/deliverability
validation.
**Context**: strict validation rejected `.local`/`.internal` domains used by enterprise
directories (and the demo account).

## ADR-019 Al-Rasedah brand as the UI design system
**Context**: the console shipped with a generic teal-on-slate dark theme; the product is
sold under the Al-Rasedah Technology brand, whose site (alrasedah.com.sa) defines a
navy/copper palette, light and dark themes, IBM Plex Sans Arabic + Inter, and the
copper-eye logo.
**Decision**: keep the console's component structure and class names, and replace its
tokens with the brand's (semantic names from the site: `--background`, `--surface`,
`--foreground`, `--brand`, …). Dark stays the default; the site's light theme is included.
Severity colours stay from the console (the brand has none), with added light-theme values
and separate `-text` tokens. Fonts are self-hosted. Report accent default follows the brand
(`#a3571f`, the light-theme copper, since reports are printed on white).
**Consequences**: one accent colour; copper must never mean severity (amber `--sev-high` is
close in hue, so severity always carries its word); no hex literals in TSX; the design-system
artifact (chapter 7.8) and `styles.css` must be kept in step.
**Alternatives**: a UI kit (MUI/shadcn — rejected: heavier, fights the brand, not needed for
this surface); tenant-themable accents in the UI (deferred — tenant branding applies to
reports only).
