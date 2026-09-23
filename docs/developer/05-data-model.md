# 5. Data model and migrations

Models live in `backend/app/models/`; the authoritative DDL is
`backend/alembic/versions/0001_initial_schema.py`.

## 5.1 Conventions

| Convention | Detail |
|---|---|
| Primary keys | UUID v4 (`UUIDPk` mixin) except high-volume append tables (`audit_logs`, `asset_observations`, `scope_decisions`) which use BIGINT identity |
| Tenancy | `TenantScoped` mixin adds `tenant_id` FK → `tenants.id` `ON DELETE CASCADE`, indexed |
| Timestamps | `timestamptz` everywhere; `created_at`/`updated_at` via `Timestamps` mixin (server defaults) |
| Enums | Python `StrEnum` stored as `VARCHAR` via `enum_column()` — adding a value never needs a migration; validated by SQLAlchemy/pydantic |
| JSON | `JSONB` for attributes, settings, stats, evidence, event states |
| Arrays | `VARCHAR[]` for tags, sources, CVEs (GIN indexes on `assets.tags`, `findings.cve`) |
| Constraint names | deterministic naming convention in `db/base.py` (so autogenerate diffs are stable) |
| Deletion | business data is deactivated/resolved, never deleted by the pipeline; deleting an organization cascades |

## 5.2 Tables

### Identity and tenancy

| Table | Key columns | Notes |
|---|---|---|
| `plans` | `code`, quotas (`max_organizations/assets/users/scans_per_day/concurrent_scans`), `allow_active_scanning`, `features`, billing placeholders | global; seeded by `ensure_plans` |
| `tenants` | `name`, `slug` (unique), `status`, `plan_id`, `worker_pool`, `data_region`, `settings`, `billing` | RLS: only own row unless bypass |
| `users` | `email` (unique, lower-cased), `password_hash`, `is_platform_admin`, MFA fields, `auth_provider`/`external_id` (SSO-ready), lockout fields, `default_tenant_id` | global identity |
| `tenant_memberships` | `(tenant_id, user_id)` unique, `role`, `is_active` | grants access |
| `user_sessions` | `refresh_token_hash` (unique), `previous_token_hash`, expiries, `revoked_at/reason`, IP/UA | system-only RLS |
| `password_reset_tokens` | `token_hash`, `expires_at`, `used_at` | also used for invitations |
| `api_tokens` | `token_prefix`, `token_hash`, `role`, `expires_at`, `revoked_at` | tenant-scoped |
| `audit_logs` | `action`, actor, object, `previous`/`new`, IP/UA/request id, `prev_hash`/`hash` | append-only trigger |
| `organizations` | `name` unique per tenant, `settings`, `baseline_completed_at`, `is_active` | |
| `usage_records` | `metric`, `quantity`, `period` | metering |
| `metric_snapshots` | per org per day: totals, new, unknown, open findings by severity, risk score | trends |

### Scope and secrets

| Table | Key columns |
|---|---|
| `scope_entries` | `entry_type` (domain/ip/cidr), `value`, `include_subdomains`, `is_exclusion`, `allow_active_scanning`, `verification_status/token`, unique per `(org, type, value, is_exclusion)` |
| `secrets` | `name` unique per tenant, `kind` (scanner_credential/integration), `provider`, `backend`, `ciphertext`, `key_id`, `last_four`, `external_ref` (Vault) |

### Inventory and history

| Table | Key columns | Notes |
|---|---|---|
| `assets` | see ARCHITECTURE §5 | unique `(tenant_id, organization_id, asset_type, normalized_value)`; trigram GIN index on `normalized_value` for substring search |
| `asset_relationships` | `source_asset_id`, `target_asset_id`, `relation_type`, `active`, `missed_count`, `first_seen`, `last_seen`, `attributes` (e.g. technology version) | unique `(source, target, relation)` |
| `asset_observations` | `asset_id`, `scan_id`, `stage_id`, `source`, `observed_at`, `data` | grows fastest; retention purge; candidate for monthly partitioning |
| `asset_events` | `event_type`, `severity`, `title`, `summary`, `previous_state`, `new_state`, `details`, `occurred_at`, `is_baseline`, `acknowledged*`, `notified*`, denormalized `asset_type/asset_value` | the change log |

Relationship vocabulary (`asm_sensors.observations.RelationType`): `resolves_to`, `cname`,
`ns_record`, `mx_record`, `ptr`, `subdomain_of`, `contains`, `announces`, `belongs_to_asn`,
`has_port`, `runs_service`, `serves`, `hosted_on`, `uses_technology`,
`presents_certificate`, `certificate_for`, `hosted_by`, `redirects_to`, `related_to`.

Canonical values (`assets.normalized_value`):

| Type | Example |
|---|---|
| hostname types | `api.example.com` (lower-case, no trailing dot, IDNA) |
| `ip_address` | `2001:db8::1` |
| `cidr` | `192.0.2.0/24` |
| `asn` | `AS13335` |
| `port`, `service` | `192.0.2.1:443/tcp`, `[2001:db8::1]:22/tcp` |
| `http_endpoint` | `https://api.example.com`, `http://example.com:8080` (base URL, default ports dropped) |
| `certificate` | lower-case hex SHA-256 fingerprint |
| `technology` | lower-case product name (`nginx`); version lives on the `uses_technology` edge |
| `cloud_resource` | `provider:service:hostname` (`aws:cloudfront:d111.cloudfront.net`) |

### Scanning

| Table | Key columns |
|---|---|
| `scan_profiles` | `tenant_id` NULL = built-in; `slug`, `stages` (validated list), `is_active_scanning`, `retain_raw_output` |
| `scans` | `status`, `trigger`, `profile_snapshot`, `target_override`, `is_baseline`, `stats`, timings, `error`; `auth_secret_encrypted` + `auth_header_name` (per-scan DAST session secret, erased when the scan ends — ADR-023) |
| `scan_stages` | `position`, `stage_type`, `engine`, `config` (+`_optional`), `status`, `is_active`, `target_count`, `rejected_count`, `observation_count`, `task_id`, `dispatched_at`, `worker_pool`, `stats`, `error` |

`scan_stages.engine` is the internal name; it is **never** sent to a browser — the API sends
`label` (the capability) and, where the profile editor needs an identifier, an opaque
`eng_…` token (ADR-022). `error` stores the sanitized message, not the tool's output.
| `scope_decisions` | `target`, `decision`, `reason`, `matched_entry_id`, `active` |
| `scan_schedules` | `cron`, `timezone`, `enabled`, `next_run_at`, `last_run_at`, `last_scan_id` |
| `scan_artifacts` | `storage_key`, size, sha256, `truncated`, `expires_at` |

### Findings, intel, integrations, reports

| Table | Key columns |
|---|---|
| `findings` | `fingerprint` unique per tenant; `source`, `source_finding_id`, title/description/category/severity/location, CVE/CWE/CVSS/EPSS/KEV/exploit fields, evidence, remediation, references, confidence, first/last seen, `resolved_at`, `occurrence_count`, `missed_count`, `unverified` (third-party report awaiting confirmation — ADR-020), workflow (`status`, `false_positive`, `accepted_until`, `assigned_to`, notes, tags), risk fields |
| `finding_activities` | `activity_type` (detected/resolved/reopened/status/assignment/comment/tags), previous/new, comment, user, scan |
| `vuln_intel` | per CVE: CVSS, EPSS (+percentile, date), KEV (dates, ransomware, vendor/product), exploit flag — global cache |
| `intel_feed_state` | per feed: last success/attempt, error, record count |
| `integrations` | `integration_type`, non-secret `config`, `secret_id`, health fields |
| `notification_policies` | `event_types[]`, `min_severity`, `organization_ids[]`, `integration_ids[]`, `include_baseline`, `throttle_minutes` |
| `notification_deliveries` | event × policy × integration, `status`, `attempts`, `last_error` |
| `reports` | type, format, parameters, status, `storage_key`, size, error |
| `platform_settings` | one row (`CHECK id = 1`): `smtp` (host/port/username/sender/starttls/ssl), `smtp_password_ciphertext`, `updated_by`. Platform admins only, system sessions only; overrides `ASM_SMTP_*` (ADR-021) |
| `user_alert_preferences` | per `(tenant, user)`: `enabled`, `min_severity`, `event_types[]`, `organization_ids[]`, `include_baseline`, `last_sent_at`. No row = enabled for high/critical. Mail goes to the user's **login** address, never a typed one |

### Threat Center

| Table | Scope | Key columns |
|---|---|---|
| `threat_advisories` | global (catalog) | `slug` unique, `status` (draft/published/archived), `published_version`, denormalized title/severity/cves of the *published* version, source dates. RLS: tenants read rows with a published version; only system sessions write |
| `threat_advisory_versions` | global (catalog) | `(advisory_id, version)` unique, `state` draft/published (one draft per advisory, partial unique index), `content` = validated `AdvisoryContent`. RLS: tenants read `state = 'published'` only |
| `threat_checks` | global (catalog) | the approved-check allowlist: `key` unique, `name`, `kind = 'detection_template'` (check constraint), `template_id`, `enabled` |
| `threat_campaigns` | tenant | per `(tenant, advisory)`: `evaluated_version`, `last_evaluated_at` (freshness) |
| `threat_matches` | tenant | unique `(tenant, advisory, asset)`; `basis` (product/finding/third_party), `match_status`, `evidence`, `finding_ids[]` / `unverified_finding_ids[]` (references), `check_outcome` + `check_detail` + `checked_at` + `last_check_run_id`, derived `assessment`, `remediation_status` + `assigned_to` + `remediation_note` |
| `threat_check_runs` | tenant | one per organization per "Check selected assets": `scan_id`, `asset_ids[]`, `check_key`, `status`, `summary`. Partial unique index: one queued/running run per `(tenant, organization, advisory)` |

### Website screenshots

| Table | Key columns |
|---|---|
| `screenshot_captures` | tenant-owned; one row per attempt: `organization_id`, `asset_id`, `url`, `trigger` (manual/scheduled), `status` (queued/running/succeeded/failed/blocked/cancelled), sanitized `error`; job binding `task_id` + `worker_pool` + `dispatched_at`; on success `storage_key` (derived by the platform: `tenants/<tenant>/screenshots/<id>.png`), `size`, `sha256`, `width`, `height`, `captured_at`, `final_url` (no query string), `page_title`, `http_status` |
| `platform_settings.screenshots` | JSONB policy (see `app/screenshots/service.py` `DEFAULT_POLICY`): `available`, `max_concurrent`, per-tenant daily/queued limits, `retention_per_endpoint`, `storage_quota_mb`, capture limits. System sessions only |

## 5.3 Writing a migration

1. Change or add models under `app/models/` and import new modules in `app/models/__init__.py`.
2. Autogenerate against an up-to-date database:
   ```bash
   cd backend
   ASM_DATABASE_URL=postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev alembic revision --autogenerate -m "add widget table"
   ```
3. **Review the file.** Autogenerate misses things (server defaults on existing rows, data
   migrations, trigram/partial indexes).
4. **Add RLS for every new tenant-owned table** — this is not automatic:
   ```python
   from app.db import rls

   def upgrade() -> None:
       op.create_table("widgets", ...)
       for stmt in rls.tenant_isolation("widgets"):
           op.execute(stmt)
   ```
   and add the table name to `TENANT_TABLES` in `app/models/__init__.py`.
   `tests/backend/test_tenant_isolation.py::test_every_tenant_table_has_forced_rls` fails
   if you forget either.
5. Write `downgrade()` and test `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`.
6. The test suite recreates its database from migrations every run, so `pytest` exercises them.

Migrations run with `app.bypass_rls = on` (set in `alembic/env.py`), so data migrations can
touch all tenants.

## 5.4 Query patterns

- Inventory filtering: build an `AssetFilter` and call `assets.queries.build()`; reuse it for
  exports and reports so filters stay consistent.
- Pagination: `schemas.common.paginate(db, stmt, page, page_size)` (count + slice).
- Bulk lookups by natural key: `tuple_(Asset.asset_type, Asset.normalized_value).in_([...])`
  in batches (see `Ingestor._load`).
- JSONB attribute filters: `Asset.meta["asn"].astext == "AS13335"`.
