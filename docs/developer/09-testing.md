# 9. Testing

```bash
pytest -q                                   # 123 backend + sensor tests, ~25 s
cd frontend && npm test && npm run typecheck  # 21 UI tests, ~2 s
cd backend && ruff check app ../workers/asm_sensors
```

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
| `test_api_auth.py` | API | login/me/refresh/logout, refresh-token reuse, lockout + generic errors, login rate limit, RBAC, cross-tenant 404s, MFA, password reset, internal-domain emails, API tokens, security headers |
| `test_api_workflows.py` | API | scope check endpoint, the full analyst workflow, all report types, notifications (baseline suppressed, signed webhook, Wazuh file), syslog format, write-only credentials |
| `frontend/src/test/pages.test.tsx` | UI | every page renders with realistic data; asset tabs; authorization log |

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

`.github/workflows/ci.yml`: `backend` (PostgreSQL 16 service, ruff, pytest), `frontend`
(npm ci, typecheck, tests, build), `deployment` (compose validation, build all images,
print scanner tool versions).
