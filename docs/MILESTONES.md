# Delivery status

Status of the initial build plan. "Verified" states *how* each item was checked in this
repository, so it is clear what has and has not been exercised.

Verification environment for this iteration: Python 3.13 on Windows against PostgreSQL 18
(non-superuser application role, RLS enforced); Node 24 for the UI. Docker Engine was **not
available** in the build environment, so container images were **not built or run** here —
the Compose file was validated with `docker compose config`, and CI builds the images
(`.github/workflows/ci.yml`, job `deployment`).

## First deliverable

| # | Item | Where | Verified |
|---|---|---|---|
| 1 | System architecture | docs/ARCHITECTURE.md | reviewed |
| 2 | Repository structure | README.md | — |
| 3 | PostgreSQL schema | backend/alembic/versions/0001_initial_schema.py (+ RLS, audit trigger) | upgrade ↔ downgrade ↔ upgrade on PostgreSQL 18 |
| 4 | SQLAlchemy models | backend/app/models | test suite |
| 5 | Docker Compose architecture | docker-compose.yml, docker/ | `docker compose config` only (images not built locally) |
| 6 | FastAPI skeleton | backend/app/main.py, app/api | API tests; OpenAPI UI rendered in a browser |
| 7 | Authentication & tenant model | app/auth, app/models/auth.py, RLS | test_api_auth.py, test_tenant_isolation.py |
| 8 | Asset model | app/models/assets.py | test_change_detection.py, test_pipeline.py |
| 9 | Scanner adapter interface | workers/asm_sensors/base.py | tests/sensors |
| 10 | Working Amass adapter | workers/asm_sensors/adapters/amass | parser tests on v4 graph + v3 JSON output; not yet run against a live Amass binary |
| 11 | Asset normalization pipeline | app/assets/normalization.py, ingest.py | unit + scenario tests |
| 12 | Initial React dashboard | frontend/ | type-check, production build, 21 UI smoke tests (jsdom) |
| 13 | README with installation | README.md, docs/DEPLOYMENT.md | — |

## Milestones

| Milestone | Scope | Status |
|---|---|---|
| 1 — Core | FastAPI, PostgreSQL, React, auth, organizations, scopes, Compose, Celery/Redis | ✅ implemented |
| 2 — Asset discovery | Amass, Subfinder, crt.sh, dnsx, httpx; domains, subdomains, DNS, IPs, endpoints | ✅ implemented |
| 3 — Exposure scanning | Naabu, Nuclei; ports, services, findings | ✅ implemented |
| 4 — ASM behaviour | first/last seen, coverage-based change detection, timeline, alerts, disappearance, port/service changes, baseline | ✅ implemented |
| 5 — Risk | configurable engine, EPSS, KEV, NVD CVSS, criticality, prioritization, explanations | ✅ implemented |
| 6 — Workflow | assignment, status workflow with transition rules, notes/comments, tags, owner, approval states | ✅ implemented |
| 7 — Integrations | email, signed webhooks, Wazuh (syslog/file/HTTP), Slack, Teams; policies, throttling, retries | ✅ implemented (Jira/ServiceNow: adapter slots only) |
| 8 — Enrichment | SpiderFoot (optional), BBOT (optional), Team Cymru ASN, cloud/CDN detection | ✅ implemented; SpiderFoot/BBOT API/CLI details need validation against deployed versions |

Also delivered: reporting (6 report types, HTML/PDF/CSV), scan schedules, quotas/plans and
usage metering, encrypted secrets with a Vault seam, S3-compatible storage abstraction,
append-only hash-chained audit log, API tokens, TOTP MFA, platform tenant administration,
demo data replay, CI pipeline.

## Test inventory

| Suite | Tests | Covers |
|---|---|---|
| tests/sensors | 90 | parsers for every engine (recorded output), target validation, safe subprocess execution, coverage-dropping on failures, credential sealing and result signing, job claims, scanner identity on the wire, registry |
| tests/backend (unit) | 55 | scope authorization incl. wildcards, normalization/PSL, cloud detection, change-detection rules, risk engine, user-facing error messages |
| tests/backend (database) | 60 | RLS isolation, audit immutability & hash chain, change detection scenarios, full pipeline runs, scan concurrency under contention, historical/unverified ingestion, per-scan DAST secrets, platform email |
| tests/backend (API) | 60 | auth flows (refresh rotation & reuse detection, lockout, rate limit, MFA, reset, API tokens), RBAC, cross-tenant access, scope → scan → inventory → findings workflow, reports, notifications incl. Wazuh, engine non-disclosure |
| tests/integration | 2 | broker trust boundary against a real Valkey with the compose ACL (skipped without one) |
| frontend/src/test | 33 | every page renders with API data; asset tabs; authorization log |

274 Python tests in total. The counts per group are approximate — several files span
categories — but the total and the integration count are exact.

## Known gaps / next steps

1. **Run against live tools**: build `asm-scanner` and execute Passive Discovery and Standard
   ASM scans against an owned domain; confirm tool flags for the pinned versions (especially
   Amass v4 `-o`/`-dir`, BBOT 2.x output path, SpiderFoot 4 export endpoint). The full
   checklist is the manual pass in the developer handbook, chapter 9.8 — it is the main thing
   standing between the current state and a release.
2. **Wildcard DNS handling**: detect wildcard zones before ingesting brute-forced/passive
   names. (Unrelated to `*.example.com` *scope entries*, which are supported.)
3. **Screenshots** of web endpoints (httpx headless) — schema slot exists (`meta`), UI tab planned.
4. **SSO**: SAML/OIDC (Entra ID, Google Workspace) using `users.auth_provider/external_id`.
5. **Custom roles** backed by a `roles` table using the existing `Permission` vocabulary.
6. **Jira / ServiceNow** ticketing channels — the adapters exist with `implemented = False`,
   so the API and UI do not offer them; finish them and flip the flag.
7. **Scale**: set-based SQL for risk recomputation and ingestion of very large surfaces;
   `asset_observations` partitioning by month.
8. **Arabic UI / RTL**: styles use logical properties; add translations and `dir="rtl"`.
9. Separate `BYPASSRLS` database role for scheduler/maintenance in SaaS (see SECURITY.md).
