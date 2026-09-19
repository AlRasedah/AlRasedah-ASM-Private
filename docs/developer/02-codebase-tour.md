# 2. Codebase tour

```text
.
├── backend/                 the platform (Python package `app`)
├── workers/                 the sensor framework (Python package `asm_sensors`)
├── frontend/                the web UI (React + TypeScript + Vite)
├── docker/                  Dockerfiles, entrypoints, nginx configs, PostgreSQL init
├── docker-compose.yml       default deployment
├── tests/                   pytest suites (sensors + backend)
├── scripts/                 developer and operator helpers
├── docs/                    product docs + this handbook
└── .github/workflows/ci.yml CI
```

## `workers/asm_sensors` — sensor framework (no platform dependency)

| File | What it contains |
|---|---|
| `observations.py` | The scanner-independent contract: `ObservedType`, `RelationType`, `Severity`, `FindingCategory`, `AssetObservation`, `RelationObservation`, `FindingObservation`, coverage models (`LivenessCoverage`, `RelationCoverage`, `FindingCoverage`) and `SensorResult`. The platform imports these enums too, so there is one definition. |
| `targets.py` | `Target` model and strict validators (`validate_hostname`, `validate_ip`, `validate_cidr`, `validate_url`, `split_host_port`). Rejects wildcards, leading `-`, whitespace, credentials in URLs; IDNA-normalizes. |
| `execution.py` | `run_process` (asyncio subprocess, no shell, NUL check, output caps, timeout with process-group kill), `resolve_binary` (allowlist + `ASM_BIN_<NAME>` override), `minimal_env`. |
| `base.py` | `ScannerAdapter` ABC (`validate_configuration → execute → parse_results → normalize`, driven by `run()`), `AdapterConfig` (`extra="forbid"`), `ExecutionContext`, `RawOutput`, `StageType`, helpers (`write_targets_file`, `iter_json_lines`, `make_artifact`). |
| `ports.py` | Explicit port sets (`web`, `common`, `extended`, `full`) and spec helpers (`validate_port_spec`, `port_in_spec`, `normalize_spec`). |
| `registry.py` | `@register`, `get_adapter`, `describe_adapters` (feeds the profile editor), entry-point discovery for external adapters. |
| `jobs.py` | `SensorJob` (the message the platform sends), task name `asm.sensors.run`, AES-GCM credential sealing bound to the job id. |
| `runner.py` | `execute_job`: build the `ExecutionContext` from job + deployment env, unseal credentials, run the adapter in a temp dir, turn every error into a *failed* `SensorResult` (a sensor never crashes the worker). |
| `worker.py` | The Celery app for sensor containers (`celery -A asm_sensors.worker worker -Q scanners.default`). |
| `adapters/_common.py` | `ObservationSet` (dedup while building observations), `clean_hostname/ip/cidr/asn`, `port_value`. |
| `adapters/<tool>/` | One package per tool: `amass`, `subfinder`, `crtsh`, `dnsx`, `asnlookup`, `naabu`, `httpx`, `nuclei`, `spiderfoot`, `bbot`, `zap` (the OWASP ZAP `zap_spider` + `zap_active` DAST engines). |

## `backend/app` — the platform

### Core plumbing

| Path | Responsibility |
|---|---|
| `main.py` | `create_app()`: logging, exception handlers (uniform `{"error": {code, message, details}}`), `RequestContextMiddleware` (request id, client IP, API rate limit, security headers, CSP), CORS, router mount at `/api/v1`, docs at `/api/docs`. |
| `core/config.py` | `Settings` (pydantic-settings, prefix `ASM_`), refuses placeholder secrets in production. |
| `core/security.py` | Argon2id hashing, password policy, opaque token generation + HMAC hashing, JWT access tokens and MFA challenge tokens. |
| `core/crypto.py` | AES-256-GCM `encrypt/decrypt` with key ids (rotation) and AAD; `transport_key()` for sealing sensor credentials. |
| `core/context.py` | `RequestContext` in a `ContextVar` (request id, IP, user agent, actor, tenant) — read by the audit logger. |
| `core/logging.py` | JSON log formatter and `RedactingFilter` (passwords, tokens, bearer headers). |
| `core/rate_limit.py` | Fixed-window limiter on Redis with in-memory fallback. |
| `core/errors.py` | `AppError` hierarchy (`NotFound`, `Forbidden`, `Unauthorized`, `Conflict`, `ValidationFailed`, `QuotaExceeded`, `RateLimited`, `ScopeViolation`) → HTTP codes. |
| `db/base.py` | Declarative `Base` (naming convention, type map), mixins `UUIDPk`, `Timestamps`, `TenantScoped`, `enum_column()` (enums stored as VARCHAR). |
| `db/session.py` | Engine/sessionmaker, the `after_begin` listener that sets `app.tenant_id` / `app.user_id` / `app.bypass_rls` per transaction, `new_session`, `session_scope`, `system_session`. |
| `db/rls.py` | SQL generators for RLS policies and the audit-log immutability trigger (used by migrations). |
| `cli.py` | `python -m app.cli` — generate-keys, bootstrap, create-admin, intel-import/refresh, run-scan (inline), verify-audit. |

### Domain modules

| Path | Responsibility |
|---|---|
| `models/` | SQLAlchemy models, one file per area (`tenancy`, `auth`, `audit`, `scope`, `assets`, `events`, `scans`, `findings`, `intel`, `integrations`, `reports`) + `enums.py`. `models/__init__.py` exports everything and `TENANT_TABLES`. |
| `auth/permissions.py` | `Permission` vocabulary, role → permission sets, `can_assign`. |
| `auth/service.py` | Login (lockout, timing equalization), session issue/refresh/rotation/reuse detection, logout, tenant switch, password change/reset, TOTP MFA, API tokens. |
| `tenants/service.py` | Plans, tenant creation, quota checks, usage records, `bootstrap()` (plans, built-in profiles, first admin). |
| `tenants/settings.py` | Default tenant/org settings (inactivity thresholds, risk weights, detection rules, …) and `deep_merge`. |
| `scope/checker.py` | `ScopeChecker` — **the** authorization decision for targets. Pure logic. |
| `scope/service.py` | Scope CRUD with validation, `sync_scope_assets` (scope → root-domain/IP/CIDR assets), `rescope_assets`, DNS TXT ownership verification. |
| `assets/normalization.py` | Canonical values per type, hostname classification with the offline public-suffix list, port value parsing. |
| `assets/cloud.py` | Hostname patterns → cloud/CDN/SaaS provider; ASN → provider. |
| `assets/ingest.py` | `Ingestor` — applies a `SensorResult` to the database (chapter 4). The biggest and most important module. |
| `assets/queries.py` | `AssetFilter` + `build()` for inventory/exports/reports; `display_ips`. |
| `changes/knowledge.py` | Security knowledge: risky ports and severities, management-interface markers, login markers. |
| `changes/detector.py` | Pure functions producing `EventDraft`s for new assets, attribute changes, disappear/reappear, technology/certificate changes, risk changes, certificate expiry. |
| `findings/service.py` | Fingerprinting/dedup, upsert with intel enrichment, automatic resolution, reopen, analyst workflow with transition rules. |
| `findings/rules.py` | Platform detection rules (risky exposed services, admin interfaces, API docs, weak TLS, cleartext login, certificate problems) emitted as a `SensorResult` with source `asm-rules`. |
| `risk/engine.py` | Pure scoring of findings and assets with explained factors. |
| `risk/service.py` | `recompute_organization` (scores, roll-up through relationships, risk events), `organization_score`. |
| `scans/profiles.py` | Built-in profiles, stage order and labels, `validate_stages`, `ensure_builtin_profiles`. |
| `scans/targets.py` | `build_targets` — derives each stage's targets from inventory + scope. |
| `scans/orchestrator.py` | `create_scan`, `cancel_scan`, `try_start`, `prepare_next_stage` (authorization + job), `complete_stage` (ingest + rules), `fail_stage`, `finalize_scan`, `run_inline`. |
| `scans/schedules.py` | Cron/timezone helpers. |
| `intel/service.py` | KEV, EPSS, NVD fetch/parse/cache, offline import, re-enrichment. |
| `integrations/channels.py` | Notification channel adapters and their config models; SSRF guard; Wazuh/syslog formatting. |
| `integrations/notifications.py` | Policy matching, throttling, batching per channel, delivery log, retries, test sends. |
| `integrations/mailer.py` | SMTP sending; password reset mail. |
| `reporting/` | `service.py` (context building, HTML/PDF/CSV rendering, `run_report`), `charts.py` (dependency-free SVG), `templates/report.html`. |
| `services/audit.py` | `record()` (hash-chained, advisory-locked per tenant), `verify_chain`, `diff`, `Action` names. |
| `services/secrets.py` | Encrypted secrets (DB backend, Vault seam), scanner credential lookup. |
| `services/storage.py` | Object store abstraction (local / S3-compatible). |
| `services/metrics.py` | Daily `MetricSnapshot` per organization. |
| `services/dashboard.py` | Dashboard summary and trends (also used by reports). |
| `services/maintenance.py` | Age-out, certificate expiry alerts, risk-acceptance expiry, retention purge, schedule firing. |
| `workers/celery_app.py` | Celery app for core worker + beat schedule. |
| `workers/tasks.py` | Scan state machine tasks and periodic tasks. |
| `workers/dispatch.py` | Facade used by the API: Celery in production, synchronous in inline mode. |
| `schemas/` | Pydantic request/response models (`common.py` has `Page`, `paginate`, `Email`, `source_label`). |
| `api/deps.py` | `get_principal` (JWT or API token), `require(*permissions)`, `get_db` (tenant session), `get_system_db`, `Paging`. |
| `api/v1/*.py` | Routers: `auth`, `organizations`, `scopes`, `assets`, `findings`, `scans` (+ profiles, schedules), `events`, `dashboard`, `reports`, `integrations` (+ policies, deliveries, credentials), `users`, `tenants`, `settings` (+ audit, intel, health). |

### Migrations

`backend/alembic/versions/0001_initial_schema.py` — autogenerated table DDL wrapped with
`CREATE EXTENSION pg_trgm` and `apply_rls()` (policies for every tenant table, users,
tenants, profiles, audit log and private auth tables). `alembic/env.py` sets
`app.bypass_rls = on` for the migration connection.

## `frontend/src`

| Path | Responsibility |
|---|---|
| `main.tsx` | React root: QueryClient, BrowserRouter, AuthProvider. |
| `App.tsx` | Routes; lazy-loaded pages; `RequireAuth`. |
| `api/client.ts` | `api()` fetch wrapper, in-memory access token, single-flight refresh with CSRF header, `download`, `openBlob`. |
| `api/types.ts` | TypeScript mirrors of API schemas. |
| `auth/AuthContext.tsx` | Session restore, login/MFA, logout, tenant switch, `can(permission)`. |
| `auth/OrgContext.tsx` | Selected organization (persisted in localStorage) used as a global filter. |
| `components/` | `Layout` (sidebar/topbar), `ui.tsx` (Card, badges, RiskScore, Tabs, Modal, Pagination, …), `Charts.tsx` (Recharts wrappers), `Timeline.tsx`. |
| `lib/format.ts`, `lib/useFilters.ts` | Formatting/labels; URL-synced filters (`set`, `setMany`). |
| `dashboard/`, `assets/`, `findings/`, `scans/`, `pages/` | Screens. |
| `test/` | Vitest smoke tests with mocked API (`fixtures.ts`). |
| `styles.css` | The whole Al-Rasedah design system: `@font-face`, navy/copper tokens (dark default + light theme), component classes; logical properties for RTL. See chapter 7.8. |
| `fonts/` | Self-hosted Inter and IBM Plex Sans Arabic `.woff2` files (SIL OFL 1.1), bundled by Vite. |

`frontend/public/` holds files served as-is: `brand-symbol.svg` (the copper-eye logo) and
`favicon.svg` (the same symbol).

## `docker/`

| Path | Purpose |
|---|---|
| `backend/Dockerfile`, `entrypoint.sh` | Platform image; roles `api` (gunicorn+uvicorn), `worker`, `scheduler`, `migrate`, `cli`. |
| `scanner/Dockerfile`, `entrypoint.sh` | Multi-stage: Go builder compiles tools at pinned versions → Python Alpine runtime with `asm_sensors`; roles `worker`, `update-templates`, `versions`. |
| `web/Dockerfile`, `nginx.conf` | Build the SPA, serve with unprivileged nginx and a strict CSP. |
| `proxy/nginx.conf`, `nginx-tls.conf` | Reverse proxy (HTTP / TLS variants) with request limits. |
| `postgres/init/01-app-role.sh` | Creates the non-superuser application role and database on first init. |

## `tests/`

| Path | Purpose |
|---|---|
| `conftest.py` | Sets test environment variables **before** importing the app. |
| `sensors/` | Parser tests on recorded output (`fixtures/`), framework tests. |
| `backend/conftest.py` | Creates the test DB + non-superuser role, migrates, bootstraps; truncates between tests; `Factory` helpers. |
| `backend/sensors_fake.py` | `FakeSensors` — replaces adapter execution with recorded output. |
| `backend/test_*.py` | Unit (pure logic), database (RLS, change detection, pipeline) and API tests. |

## `scripts/`

| Script | Purpose |
|---|---|
| `generate_env.py` / `generate-env.sh` | Create `.env` with random secrets |
| `dev_db.py` | Create non-superuser role + database |
| `dev-postgres-wsl.sh` | User-space PostgreSQL in WSL |
| `dev_api.py` | Run the API with development defaults |
| `seed_demo.py` | Demo tenant populated through the real pipeline with replayed data |
