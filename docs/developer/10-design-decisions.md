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
**Decision**: `start_scan → advance_scan → [sensor job on scanners.<pool>] → authenticated
result on results.<pool> → asm-ingest → advance_scan`; watchdog for lost jobs; results via
the broker. *(Revised after the 2026-09-19 audit: the original design chained the sensor task
to a core `ingest_stage` task, which meant sensor workers published core tasks and shared the
platform's broker account and key.)*
**Consequences**: no task blocks waiting on another; sensors need only their pool's broker
user and key; a pool is a trust boundary (ACLs, per-pool HKDF keys, MAC'd results bound to
the persisted job, a result consumer that registers a single task). Large results travel
through Redis/Valkey. State transitions are row-locked and committed before publishing.
**Alternatives**: sensors writing to the DB directly (breaks isolation), Celery's X.509
message signing for every task (heavier key management; ACLs + result MACs cover the same
threats here), Kafka (unjustified).

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
<!-- ADR-016..019 predate the 2026-09-19 audit; 020 onwards are below, in order of decision. -->
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

## ADR-020 Third-party intelligence is historical and unverified
**Decision**: sensors that report a third-party database's view (today `shodan`) set
`SensorResult.historical`; ingestion then adds new knowledge but never refreshes `last_seen`,
reactivates an asset, or lets that source close anything. Their CVE reports are stored with
`findings.unverified = true`, hidden from the findings list, risk scores, reports and alerts
until a sensor that actually tested the service reports the same issue.
**Consequences**: Shodan (and later similar sources) widen coverage — including for scope
that may not be actively scanned — without weakening change detection or inflating risk.
The UI needs a second findings view, and the API a filter, which is the honest trade.
**Alternatives**: treating Shodan like a live scanner (dead services would look alive and
version-matched CVEs would drive risk scores), or discarding its CVE list entirely (loses a
useful lead).

## ADR-021 Platform-managed email
**Decision**: the mail server lives in `platform_settings` (encrypted password), editable by
platform administrators in the UI and overriding `ASM_SMTP_*`; every user can have alerts
sent to their own *login* address (`user_alert_preferences`, default on for high/critical).
**Consequences**: a deployment can be operated entirely from the web interface, which is the
product requirement; `.env` stays a bootstrap default. Tenants do not get their own mail
server: in a multi-tenant deployment that would let a tenant admin change how everyone's
password resets are sent. Per-user alerts never take a typed address, so they cannot be used
to forward another tenant's events.
**Alternatives**: SMTP only in `.env` (needs shell access for every change — rejected),
per-tenant relays (revisit if a customer needs their own sending domain).

## ADR-022 The product names capabilities; it never names its engines
**Context**: a real deployment showed stage rows reading "Asset discovery" three times (three
different discovery engines on one stage type), errors reading `nuclei exit code 1: [FTL]
Could not run nuclei: no templates provided for scan`, engine names in every API response,
and an `X-ASM-Scanner` header on outgoing probes. Anything the browser receives is
inspectable, so the engine list was effectively published; and none of it helped the reader.
**Decision**: the interface speaks in capabilities. Stages, findings and observations carry
`display_name` labels (`scans/engines.label_for`); profiles and the capabilities endpoint
identify an engine by `eng_<hmac>` computed under the deployment's `secret_key`, so the
identifier is stable for the editor and meaningless anywhere else; config schemas are
scrubbed of class titles; errors go through `scans/messages.friendly`, which maps known
failures to advice and scrubs anything left over. Adapters raise `ConfigurationError` with a
product-level sentence. Scan traffic sends no identifying header unless the deployment opts
in (`ASM_SCANNER_IDENTITY`) and uses a neutral user agent.
**Consequences**: one more indirection between the pipeline and the API, and a test
(`test_engine_disclosure.py`) that fails whenever a name leaks — including through pydantic
titles, tags and rule-id prefixes, which is how most leaks happened. Raw output still exists,
in the worker log, where the operator (not the customer) reads it. Support conversations lose
the tool name as shorthand; the capability label has to be good enough.
**Not hidden**: `credential_providers`. The customer buys and pastes those keys, so
Integrations names Shodan and the rest.
**Alternatives**: renaming only the visible strings (leaks return with every new adapter);
a per-deployment name map in config (same effect, one more thing to keep in step).

## ADR-023 Per-scan session secret for authenticated DAST
**Decision**: the cookie typed into the Start-scan modal is encrypted on the scan row
(`scans.auth_secret_encrypted`, AAD `scan:<id>:auth`), delivered through the normal sealed
credential channel as the `zap_auth` provider, and erased at `finalize_scan`/`_cancel`.
**Consequences**: an authenticated crawl needs no stored credential and leaves nothing behind
once the scan ends; a session that expires mid-scan simply yields unauthenticated results.
The value is scoped to the authorized origin by the ZAP Replacer rule and CRLF is refused.
**Alternatives**: only tenant-stored credentials (a session cookie is short-lived and
per-tester — wrong lifetime), passing it in the job without encryption at rest (a scan row is
long-lived and backed up).

## ADR-024 Wildcard scope entries are input, not storage
**Decision**: `*.example.com` is accepted wherever scope is typed and stored as the domain
with `include_subdomains`; pasting both forms widens the existing entry instead of colliding.
A wildcard may only replace the first label, and never covers a public suffix.
**Context**: authorization letters are written `*.example.com`, so that is what people paste;
it was silently rewritten to `example.com`, which looked like the tool ignoring the input.
**Consequences**: one representation in the database, so the scope checker is unchanged.
`a.*.example.com` is refused with the accepted form rather than guessed at.
