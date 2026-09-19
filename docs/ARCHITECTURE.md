# Exteriq ASM — System architecture

## 1. Goals and principles

| Principle | Consequence in the design |
|---|---|
| The platform owns the data and the logic | Asset model, history, change detection, risk, workflows, reports and integrations live in the platform. Scanners only *observe*. |
| Scanners are replaceable sensors | One adapter per tool, one scanner-independent observation schema. The database never stores a tool's native format as its model. |
| History over snapshots | Assets are never deleted because a scan missed them. Every sighting is recorded; disappearance is inferred from *coverage*. |
| Tenant isolation by construction | `tenant_id` on every tenant-owned row, enforced by PostgreSQL Row-Level Security in addition to application checks. |
| Safe by default | Every active target is authorized against the organization's scope; safe detection only; strict input validation; no shell. |
| Portable | Docker Compose, PostgreSQL, a Redis-protocol broker (Valkey), S3-compatible storage — no hyperscaler lock-in; Kubernetes-ready without redesign. |

## 2. Components

| Service | Image | Responsibility | Networks |
|---|---|---|---|
| `reverse-proxy` | nginx (unprivileged) | Single public entry point, TLS, request limits | edge |
| `asm-web` | nginx + static React build | Web UI | edge |
| `asm-api` | platform | REST API, authentication, RBAC | edge, data, egress (DNS verification, SMTP) |
| `asm-worker` | platform | Celery `core` queue: orchestration, ingestion, change detection, detection rules, risk, notifications, reports, intel | data, egress |
| `asm-scheduler` | platform | Celery beat: schedules, queued scans, watchdog, maintenance, nightly risk/metrics, intel refresh | data |
| `asm-migrate` | platform | One-shot: `alembic upgrade head` + bootstrap (plans, built-in profiles, first admin) | data |
| `asm-scanner` | sensor image | Celery `scanners.<pool>` queue: executes sensor jobs; **no database credentials** | sensors, egress |
| `postgres` | PostgreSQL 16 | System of record | data |
| `redis` | Valkey 8 | Broker, results, rate-limit counters | data, sensors |
| `spiderfoot` (optional) | built from upstream | OSINT enrichment over HTTP API | sensors, egress |
| `zap` (optional) | OWASP ZAP daemon | Web crawling & DAST over REST API (`--profile dast`) | sensors, egress |

The `data` and `sensors` networks are `internal: true`. The sensor containers can reach
the broker and the internet, but not PostgreSQL. A compromised scanner binary therefore
cannot read or tamper with other tenants' data.

## 3. Sensor framework (`workers/asm_sensors`)

```text
SensorJob (platform -> broker)             SensorResult (sensor -> broker -> platform)
  adapter, targets[], config,                observations[]: AssetObservation | RelationObservation | FindingObservation
  sealed_credentials, timeout               coverage[]:     LivenessCoverage | RelationCoverage | FindingCoverage
                                            status, errors, stats, optional raw artifacts
```

Adapter contract (`asm_sensors.base.ScannerAdapter`):

```python
class ScannerAdapter:
    name: str
    stage_types: frozenset[StageType]
    target_kinds: frozenset[TargetKind]
    active: bool                      # sends traffic to the target itself
    config_model: type[AdapterConfig] # pydantic, extra="forbid" (no free-form args)

    async def validate_configuration(self, config, ctx): ...
    async def execute(self, targets, config, ctx) -> RawOutput: ...
    async def parse_results(self, raw) -> list[dict]: ...
    async def normalize(self, parsed, targets, config) -> NormalizedOutput: ...
```

`run()` drives the four steps, enforces the global rate cap, and **drops coverage when a
run failed or was partial** — a broken sensor can never cause "port closed" or "asset gone"
events. Built-in adapters: `amass`, `subfinder`, `crtsh`, `dnsx`, `asnlookup` (Team Cymru),
`naabu`, `httpx`, `nuclei`, `spiderfoot` (optional), `bbot` (optional), `zap_spider` /
`zap_active` (optional OWASP ZAP DAST). See [SENSORS.md](SENSORS.md) for adding one.

### Coverage

Coverage statements are what turn a recon tool into ASM:

- `LivenessCoverage(hostname, [..])` — these names were resolved; a name that did not
  resolve is *missed*.
- `RelationCoverage(parent=ip, relation=has_port, child=port, constraints={port_spec})` — all
  open ports within `port_spec` on these IPs were enumerated; a previously open port inside the
  spec that is not re-observed is *missed*. Ports outside the probed spec are untouched.
- `FindingCoverage(assets, severities, tags)` — these assets were tested with this class of
  checks; unobserved open findings in that class are candidates for automatic resolution.

## 4. Scan pipeline

```text
scope (domains) ─► subdomain discovery (Subfinder, crt.sh, Amass passive; optional BBOT)
                ─► OSINT enrichment (optional SpiderFoot)
inventory       ─► DNS resolution (dnsx) of ALL known in-scope names         [liveness + IP changes]
                ─► network ownership (Team Cymru ASN)                         [hosting changes]
scope + derived ─► port discovery (Naabu, explicit port sets)                 [authorized IPs only]
                ─► web fingerprinting (httpx: status, title, server, tech, TLS certificate)
                ─► exposure & vulnerability detection (Nuclei safe templates)
each stage      ─► ingestion ─► change detection ─► platform detection rules
end of scan     ─► risk recomputation ─► metrics snapshot ─► notifications
```

Stages read their targets from the **database**, not from the previous tool's output. DNS
resolution re-checks every known in-scope name; port discovery covers every authorized IP.
That is what allows disappearance to be detected.

Orchestration is a Celery state machine (`app/workers/tasks.py`):
`start_scan → advance_scan → [sensor job on scanners.<pool>] → ingest_stage → advance_scan …`,
with `stage_failed` as error callback and a watchdog for lost jobs. Optional stages
(`"optional": true`) that fail are marked *skipped*; required stage failures make the scan
*partial*. `ASM_SENSOR_MODE=inline` runs the same orchestrator synchronously (tests/dev).

Authorization happens in `prepare_next_stage`: each target is checked by
`app.scope.checker.ScopeChecker` (exclusions win; active mode requires
`allow_active_scanning`; derived IPs must resolve from an in-scope name) and every decision is
written to `scope_decisions`.

## 5. Data model (PostgreSQL)

```text
plans ─┐
tenants ─┬─ tenant_memberships ── users ── user_sessions / password_reset_tokens / api_tokens
         ├─ organizations ─┬─ scope_entries
         │                 ├─ assets ─┬─ asset_relationships (graph: source, target, relation, active, first/last seen)
         │                 │          ├─ asset_observations (every sighting, per scan/stage, attributes)
         │                 │          ├─ asset_events (change log: previous/new state, severity, ack, notified, baseline)
         │                 │          └─ findings ── finding_activities (detections, resolutions, workflow, comments)
         │                 ├─ scans ── scan_stages ── scope_decisions / scan_artifacts
         │                 ├─ scan_schedules
         │                 └─ metric_snapshots (daily trends)
         ├─ secrets (AES-256-GCM, AAD-bound)       integrations ── notification_policies ── notification_deliveries
         ├─ reports                                usage_records (quotas / future billing)
         └─ audit_logs (append-only, hash-chained)
vuln_intel, intel_feed_state (global cache: KEV, EPSS, CVSS)
scan_profiles (tenant_id NULL = built-in)
```

### Asset

`assets` carries every required attribute: UUID, `tenant_id`, `organization_id`,
`asset_type`, `value`, `normalized_value`, `first_seen`, `last_seen`, `discovered_at`,
`last_scanned_at`, `status` (active/inactive, `inactive_since`, `missed_count`),
`source`/`sources`, `discovery_method`, `confidence`, `owner`, `business_unit`,
`criticality`, `tags`, `notes`, `approval_status`, `scope_status`, `risk_score`/`risk_level`/
`risk_factors`, `metadata` (JSONB attributes), `created_at`, `updated_at`.
Uniqueness: `(tenant_id, organization_id, asset_type, normalized_value)`.

Asset types: `root_domain`, `domain`, `subdomain`, `ip_address`, `cidr`, `asn`,
`dns_record`, `certificate`, `port`, `service`, `http_endpoint`, `web_application`,
`technology`, `cloud_resource`. Vulnerabilities/exposures are `findings`, attached to the
most specific asset.

Scope status: `in_scope` (matches a scope entry), `derived` (linked to an in-scope asset,
e.g. a resolved IP or a technology), `out_of_scope` (third-party infrastructure related to
the organization — e.g. a CNAME target; stored for context, never scanned). Unrelated
third-party noise from sensors is dropped.

### Enumerations are VARCHAR

Enums are stored as `VARCHAR` (validated in the application), so new event types or asset
types never require a migration.

## 6. Multi-tenancy

- Users are global identities; `tenant_memberships` grant a role per tenant (MSSP-friendly).
- The API opens a session bound to the caller's tenant: `SET LOCAL app.tenant_id` on every
  transaction (`app/db/session.py`). RLS policies (`app/db/rls.py`, created by migration 0001)
  use `tenant_id = current_setting('app.tenant_id')`, **forced** so the table owner is
  subject to them, and the application connects as a role without `SUPERUSER`/`BYPASSRLS`.
- A session without a tenant context sees nothing (fail closed).
- Background/system work that must span tenants (authentication lookups, schedulers)
  uses an explicit system session (`app.bypass_rls`), then switches to per-tenant sessions
  for tenant work. See [SECURITY.md](SECURITY.md) for the hardening option of a separate
  `BYPASSRLS` role for workers.
- Tested in `tests/backend/test_tenant_isolation.py` and `test_api_auth.py::test_cross_tenant_access_is_impossible`.

## 7. SaaS readiness

| Need | Provision |
|---|---|
| Plans and quotas | `plans` (max organizations/assets/users/scans per day/concurrency, active scanning allowed, features, billing placeholders); enforced in services |
| Usage metering | `usage_records` (scans, sensor seconds, …) |
| Isolation | RLS; per-tenant worker pools (`tenants.worker_pool` → queue `scanners.<pool>`) |
| Scale-out | Stateless API/worker containers; sensors scale by replicas or pools; broker-based work distribution |
| Object storage | `app/services/storage.py` (local volume or any S3-compatible store) |
| Secrets | `app/services/secrets.py` backend seam for Vault/KMS |
| Region | `ASM_DATA_REGION` recorded per tenant; no external dependency requires leaving the region (intel feeds can be mirrored) |
| Payments | Not implemented by design; `plans`/`tenants.billing` hold the data needed later |

Kubernetes later: each Compose service maps to a Deployment (sensors as a separately
scaled Deployment per pool, `asm-migrate` as a Job, beat as a single-replica Deployment);
no code changes are required.

## 8. Change detection and risk

See [CHANGE_DETECTION.md](CHANGE_DETECTION.md) and [RISK_SCORING.md](RISK_SCORING.md).

## 9. Authentication

Argon2id password hashing; short-lived JWT access tokens (in-memory in the SPA); opaque
refresh tokens rotated on every use, stored hashed, delivered as `HttpOnly; SameSite=Strict`
cookies scoped to `/api/v1/auth` with double-submit CSRF protection; refresh-token reuse
revokes the session; account lockout; TOTP MFA; password reset with single-use hashed
tokens; API tokens for automation that never exceed the owner's role.
`users.auth_provider`/`external_id` prepare SAML/OIDC (Entra ID, Google Workspace).
