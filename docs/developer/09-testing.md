# 9. Testing

```bash
pytest -q                                   # 473 backend + sensor tests, ~3 min
cd frontend && npm test && npm run typecheck  # 56 UI tests, ~20 s
cd backend && ruff check app ../workers/asm_sensors
```

Two of the 473 are the broker-isolation integration tests; they skip unless a Valkey/Redis
is reachable (§9.6). `ASM_TEST_ADMIN_URL` is a **psycopg** DSN
(`postgresql://postgres:postgres@127.0.0.1:55432/postgres`), not a SQLAlchemy URL — a
`postgresql+psycopg://` value fails to connect and every database test silently *skips*
rather than failing, so check the skip count before trusting a green run.

## 9.1 Principles

- **No network, no scanner binaries.** Scanner behaviour is tested with recorded output
  (`tests/sensors/fixtures/*.jsonl|txt`) using documentation IP ranges and `example.com`.
- **Real PostgreSQL.** Tenant isolation depends on PostgreSQL RLS, which SQLite cannot
  emulate; the suite creates a dedicated database and a non-superuser, non-BYPASSRLS role
  and asserts that before running.
- **Pure logic first.** Scope decisions, normalization, change rules and risk scoring are
  pure functions with fast unit tests; database and API tests cover integration.

## 9.2 How the harness works

`tests/conftest.py` sets environment variables **before any app import**: `ASM_ENV=test`
(cheap Argon2 parameters, no Redis for rate limiting), secret key, inline sensor mode,
permissive scope (documentation IPs), insecure cookies, a temp storage directory, and
`ASM_DATABASE_URL` pointing at the test role/database derived from `ASM_TEST_ADMIN_URL`.

`tests/backend/conftest.py`:

| Fixture | Scope | Does |
|---|---|---|
| `database` | session | (re)create DB + role via `scripts/dev_db.ensure`, assert role flags, `alembic upgrade head`, `bootstrap()`; skips DB tests if PostgreSQL is unreachable |
| `db_clean` | test | as the admin user with `session_replication_role = replica` (bypasses the audit trigger), `TRUNCATE tenants, users, audit_logs, … CASCADE`, then re-seed built-in profiles (the cascade empties `scan_profiles`), reset the rate limiter cache |
| `factory` | test | `Factory.tenant()`, `.user(tenant_id, role=…, email=…)`, `.org(tenant_id, domains=…, ips=…, cidrs=…, exclusions=…)` — create through the real services |
| `tenant_db` | test | `tenant_db(tenant_id)` opens tenant-scoped sessions (closed automatically) |
| `system_db` | test | a system session |

`tests/backend/sensors_fake.py` — `FakeSensors(monkeypatch, outputs)` replaces every
registered adapter's `execute` with recorded output (file name, list of records, bytes or a
callable of the targets) and `validate_configuration` with a no-op. It records the targets
each engine received (`fake.calls`) so tests can assert that scope enforcement worked. It
is also reused by `scripts/seed_demo.py`.

## 9.3 Suites

| File | Kind | Highlights |
|---|---|---|
| `tests/sensors/test_parsers.py` | unit | every adapter against its fixture: Amass graph + legacy JSON + ANSI, Subfinder invalid names, dnsx NXDOMAIN + coverage, Naabu both JSON shapes, httpx services/tech/certs/coverage per port, Nuclei CVE/tech/network mapping and safe defaults |
| `tests/sensors/test_framework.py` | unit | unsafe targets rejected, IDNA, no-shell execution with metacharacters, timeout kill, output cap, NUL rejection, allowlist, partial runs drop coverage, artifacts, rate clamping, missing binary → clean failure, credential sealing bound to job id, registry |
| `test_scope_checker.py` | unit | exclusions win, look-alike domains, active permission, derived IPs (and from excluded names), CIDRs, verification |
| `test_normalization.py` | unit | canonical values, PSL (incl. `gov.sa`, `com.sa`), classification, cloud patterns, ASN providers |
| `test_detector.py` | unit | every change rule and severity choice |
| `test_risk_engine.py` | unit | KEV/EPSS effect, context factors, confidence, age, bounds, asset roll-up, levels |
| `test_tenant_isolation.py` | DB | forced RLS on every tenant table, reads/writes/updates/deletes across tenants, no-context session sees nothing, user visibility, audit immutability, hash chain |
| `test_change_detection.py` | DB | baseline + scope, IP change and retirement of old IP, port open/close/re-open, uncovered ports untouched, failed runs never close, host disappear/reappear, endpoint cascade, finding dedup/resolve/reopen/filters, service/technology/certificate changes, cloud resources, hosting change |
| `test_pipeline.py` | DB | full Standard ASM scan inline (scope enforcement at sensor level, inventory, scanner + rule findings, risk, baseline), second scan diff, scope/duplicate guards, optional vs required stage failures, passive profile never runs active sensors, global concurrency across tenants |
| `test_api_auth.py` | API | login/me/refresh/logout, refresh-token reuse, lockout + generic errors, login rate limit, RBAC, cross-tenant 404s, MFA, password reset, internal-domain emails, API tokens, security headers, **idle timeout** (refused and revoked after the window, renewed while in use, `0` disables, the window reaches the browser, API tokens exempt) |
| `test_api_workflows.py` | API | scope check endpoint, the full analyst workflow, all report types, notifications (baseline suppressed, signed webhook, Wazuh file), syslog format, write-only credentials |
| `test_review_fixes.py` | DB/API | the manual-test-report fixes of chapter 11.6 (audit chain seq, suspend guards, confirmations, sorting, …) |
| `frontend/src/test/pages.test.tsx` | UI | every page renders with realistic data; asset tabs; authorization log |

Added with the 2026-09-19 audit remediation and the work that followed (chapters 11.9–11.10);
each of these is the regression test for a defect that reached a real environment:

| File | Kind | Guards |
|---|---|---|
| `tests/sensors/test_audit_fixes.py` | unit | job claims (a redelivered job runs once), per-pool HKDF keys, result MAC, anchored ZAP origin regex, the exclusive-daemon lease, credentials never in logs, egress filter on derived destinations |
| `tests/backend/test_audit_fixes.py` | DB/API | the advisory lock under concurrent starts, suspended tenant/inactive organization cancels the scan, an incomplete run never resolves findings, results rejected unless they answer the stage's persisted job, verification enforced on scope that already existed, a viewer's API token cannot enrol the owner's MFA |
| `tests/integration/test_broker_isolation.py` | integration | real Celery workers on a real Valkey with the compose ACL: a sensor worker cannot publish core tasks, read another pool's queue, or use the platform's account. **Needs a broker** (§9.6) |
| `tests/sensors/test_shodan.py` | unit | host-lookup parsing from a recorded response, the historical flag, coverage limited to its own tag, key errors that never carry the URL |
| `tests/backend/test_shodan_pipeline.py` | DB | historical results add assets without refreshing `last_seen` or reviving anything; its CVEs land as `unverified` and stay out of risk |
| `tests/backend/test_platform_email.py` | DB/API | platform SMTP settings override `ASM_SMTP_*`, the password is encrypted and write-only, per-user alerts go to the login address only |
| `tests/backend/test_scan_auth_secret.py` | DB | the Start-scan cookie is encrypted per scan, reaches only the DAST engines, and is erased when the scan ends or is cancelled |
| `tests/backend/test_scope_wildcards.py` | unit/API | `*.example.com` expands to the domain with subdomains, widens an existing entry instead of colliding, and `a.*.example.com` / `*example.com` / a wildcard on a public suffix are refused |
| `tests/backend/test_engine_disclosure.py` | API | **no engine or upstream project name in any response** (scans, profiles, capabilities, findings, assets, observations), opaque tokens round-trip through the profile editor, and every mapped error message is advice without a tool name |
| `tests/sensors/test_identity.py` | unit | no product header unless `ASM_SCANNER_IDENTITY` is set, neutral user agent, CRLF refused in either |
| `tests/backend/test_target_ports.py` | unit/DB | `host:port` is accepted where a scan is limited to targets (IPv6 still parses as an address, a bad port is still refused, scope still applies), the named port is probed even though the sweep would not reach it, and the host's other ports are left out of the crawl and the attack |
| `tests/backend/test_cli_admin.py` | DB | `create-admin` refuses a tenant name that does not exist (and suggests the near match) instead of silently creating an empty tenant; first-run bootstrap still works; an existing account keeps the tenant it signs in to and the operator is told (chapter 11.11) |

Added with the Threat Center, website screenshots and the exposure map (chapter 11.15):

| File | Kind | Guards |
|---|---|---|
| `tests/backend/test_threat_matching.py` | unit | the version rule (ordering, unparseable = unknown), range semantics, strongest verdict per asset, the assessment order (a product match is never confirmed; third-party stays unverified; failed checks are inconclusive), advisory content refusing commands/templates/download fields, credentialed or non-http references and odd check keys |
| `tests/backend/test_threat_center.py` | DB/API | catalog is platform-admin only; drafts invisible and the catalog unwritable from tenant sessions (RLS); inventory matches never confirmed; versions outside/unknown; verified findings confirm, Shodan reports do not; repeated evaluation creates no duplicate matches or events; a check runs through `create_scan` with the internal profile, only the approved detection, only the selected endpoint; a second click is a 409; "not detected" is labelled not-proof and changes no remediation; crashed or timed-out checks are inconclusive and close nothing; scope without active permission refuses the check; remediation separate from assessment; two tenants with the same asset names see only their own matches, counts, check runs and export, and guessed ids are 404 |
| `tests/sensors/test_screenshot.py` | unit (local HTTP + stand-in browser) | address rules incl. IPv4-in-IPv6 and metadata in lab mode; the proxy pins each connection and survives DNS rebinding; ports, schemes, exclusions, response and connection limits; blocked subresources never reach the origin; redirect limits and blocked redirects without leaking query strings; sandbox/no-image/not-PNG/too-big failures; non-pages never start a browser; a hung page and a cancelled job kill the browser and close the proxy; one browser per pool; fresh, deleted profiles; runner egress refusal; stale-browser reaper; vendor background services refused and one feature-flag list |
| `tests/backend/test_screenshots.py` | DB/API | off until platform and tenant enable it (reasons shown); policy bounds; end-to-end through the sealed job; only web endpoints in authorized scope, re-checked at dispatch; failures never remove the previous image; retention keeps two and deletes objects; storage quota; daily/queue limits and reuse of an active capture; eight concurrent dispatchers on eight connections reserve exactly one slot, with fairness; the watchdog frees lost slots; result binding (job id, tenant, pool, adapter, replay); cross-tenant image/cancel/delete/request are 404; organization deletion removes images; weekly schedule; not a scan stage; cancel revokes and refuses late results |
| `tests/backend/test_exposure_map.py` | DB/API | the chain and edge metadata with no engine names; depth/node/edge bounds and validation; time budget → partial map; a 600-subdomain node is capped at 25 with "+575" and expands to 100; cycles terminate; current/stale/inactive/historical/unverified distinguished; tenant and organization boundaries (404); cache keys carry tenant and role |
| `frontend/src/test/features.test.tsx` | UI | per-role actions (viewer vs analyst vs tenant admin vs platform admin), the 409 explanation, "not proof of safety", empty/error states, inventory-only advisories, tenant switching refetch; screenshots: blob-fetched image through the asset-scoped endpoint, disabled feature explained, queued/running/failed/blocked states with the old image kept, settings cards; exposure map: line explanations, third-party/inactive/hidden marks, expansion request, partial/empty/error states, filters refetch |

## 9.4 Writing tests

- Pure logic → a unit test next to the similar ones; no fixtures needed.
- Ingestion/change behaviour → `test_change_detection.py` style: build `SensorResult`s with
  the helpers (`a()`, `rel()`, `dns()`, `ports()`, `dns_cov()`) and call `World.ingest`
  repeatedly, flipping `world.baseline = False` after the first run.
- Whole pipeline → `test_pipeline.py` with `FakeSensors`; override a tool's output with
  `fake.set("naabu", b"...")`.
- HTTP → `TestClient(app)` and the `login`/`bearer` helpers; remember cookies are scoped to
  `/api/v1/auth`.

## 9.5 CI

`.github/workflows/ci.yml`: `backend` (PostgreSQL 16 service, a disposable Valkey 8 for the
broker test, ruff, pytest), `frontend` (npm ci, typecheck, tests, build), `deployment`
(compose validation, build all images, print scanner tool versions).

## 9.6 The broker-isolation test

`tests/integration/test_broker_isolation.py` is the only test needing a service beyond
PostgreSQL, because the thing it proves — that a compromised sensor worker cannot step
outside its pool — lives in the Valkey ACL, not in our code. It reads the ACL rules out of
`docker-compose.yml`, applies them to a **disposable** server (database 0 is flushed), and
runs real Celery workers against it.

```bash
docker run -d --name valkey -p 56379:6379 valkey/valkey:8-alpine valkey-server --requirepass secret
ASM_TEST_BROKER_ADMIN_URL=redis://:secret@127.0.0.1:56379/0 pytest tests/integration -q
```

Without `ASM_TEST_BROKER_ADMIN_URL` both tests skip. If you change the ACL in
`docker-compose.yml`, run this — the rules are exact (`PSUBSCRIBE` needs a literal channel
match, so a pidbox pattern with a trailing `*` fails), and a denial surfaces as a generic
`ResponseError`.

## 9.7 What the suites cannot tell you

The fixtures are recorded output, so every test passes against a machine with no scanner
binaries, no broker, no ZAP, no SpiderFoot and no API keys. That is deliberate, and it means
the suite says nothing about: real tool versions and their flags, ZAP and SpiderFoot API
paths, whether Nuclei's templates downloaded, delivery to a real SMTP/Wazuh/Slack endpoint,
PDF rendering, image builds and container start-up, or behaviour at scale. Those belong to
the manual pass in §9.8 and the "Not verified" column of chapter 11.4 — read it before
claiming a release is tested.

## 9.8 The manual pass

Run on a deployed stack (`docker compose up -d`, DAST and enrichment profiles included),
against a domain you own and have authorized. Ordered so a failure stops you early. Anything
already covered by the suites is left out on purpose.

**A. The stack comes up**
1. `docker compose build` then `up -d`; every container healthy.
2. `docker compose run --rm asm-scanner versions` — each engine prints a version. A missing
   binary here is what "This capability is not installed in the scanner deployed here"
   means later.
3. Scanner start-up downloads the detection templates (~1 GB). Confirm it finished, or the
   detection stage will report "Detection content is not installed yet."
4. Sign in; `/settings` → **Email delivery** → save the mail server → **Send test email**.

**B. First scan**
5. Add scope both ways — `example.com` and `*.example.com` — and verify ownership (DNS TXT)
   or approve as platform admin.
6. Run **Passive Discovery**, then **Standard ASM**. Watch the Pipeline: every stage should
   carry a distinct capability name, and any failure should read as advice, not as tool
   output. Any raw tool text here is a missing mapping in `app/scans/messages.py`.
7. Compare observations against what you know of the domain; note anything the fixtures do
   not predict (this is how adapter bugs at real tool versions surface).
8. Open the browser network tab on Scans, Findings and Scan profiles: no engine or project
   name in any response. A leak here is a bug in `scans/engines.py` — add the case to
   `test_engine_disclosure.py`.

**C. The new surfaces**
9. Integrations → add the **Shodan** key → **Test** → run a scan with an IP in scope →
   confirm the exposure stage produces observations, and that its CVEs appear in the
   **unverified** findings view only, not in risk.
10. Start scan → the DAST profile → paste a session **Cookie** → confirm the crawl reaches
    authenticated pages, and that `scans.auth_secret_encrypted` is NULL once it ends.
11. Account → personal alerts → trigger a high-severity change → mail arrives at the login
    address.
12. Timings: record each stage's duration. The budgets in §11.10 were set from one report;
    the second data point is yours.

**D. Delivery**
13. Wazuh: point a test manager at the syslog channel, validate with `wazuh-logtest`.
14. Generate each report type, including PDF (WeasyPrint only exists inside the image).
