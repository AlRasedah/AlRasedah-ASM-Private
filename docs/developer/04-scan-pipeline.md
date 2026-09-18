# 4. The scan pipeline, end to end

This chapter follows one scan from the button click to the Wazuh alert, naming the exact
functions involved. Product-level background: [../CHANGE_DETECTION.md](../CHANGE_DETECTION.md).

```text
POST /scans ─► orchestrator.create_scan ─► dispatch.start_scan
                                              │
      ┌───────────────────────────────────────┘
      ▼
tasks.start_scan ─► orchestrator.try_start (concurrency) ─► tasks.advance_scan
                                                              │
      ┌───────────────────────────────────────────────────────┘
      ▼
orchestrator.prepare_next_stage
   build_targets ─► ScopeChecker.check (each target) ─► scope_decisions rows
   seal credentials ─► SensorJob
      │  Celery chain on queue scanners.<pool>
      ▼
asm_sensors.worker.run_sensor ─► runner.execute_job ─► adapter.run()
   validate_configuration → execute (subprocess) → parse_results → normalize
      │  SensorResult (observations + coverage) via result backend
      ▼
tasks.ingest_stage ─► orchestrator.complete_stage
   Ingestor(source=<adapter>).ingest(result)          assets, relations, findings, events
   rules.evaluate(touched) ─► Ingestor(source="asm-rules").ingest(...)
      │
      ▼  tasks.advance_scan (next stage … until none left)
orchestrator.finalize_scan
   status ─► risk.recompute_organization (+ risk events) ─► baseline flag
   scan_completed / scan_failed event ─► metrics.snapshot_organization
      │
      ▼
tasks.dispatch_notifications ─► notifications.dispatch_pending ─► channels (email/webhook/Wazuh/…)
```

## 4.1 Creating the scan — `orchestrator.create_scan`

Checks, in order: organization exists and is active; profile is global or the tenant's own;
at least one enabled stage; the organization has inclusion scope; if any stage is active,
the plan allows active scanning and some scope entry permits it; optional explicit targets
are each authorized (passive check); no other active scan of the same profile for the
organization; daily scan quota.

It then stores a `Scan` with a **snapshot** of the profile's stages (later profile edits do
not affect running scans), one `ScanStage` row per stage (optional flag stored as
`config["_optional"]`), `is_baseline = organization.baseline_completed_at is None`, an audit
entry and a usage record.

## 4.2 Starting — `try_start`

Pending/queued → running if the tenant's plan concurrency and the platform-wide limit allow,
otherwise `queued`. `tasks.dispatch_queued_scans` (every minute) retries queued scans.

## 4.3 Choosing targets — `scans/targets.build_targets`

Stages read their input **from the database**, not from the previous stage's output:

| Stage | Targets |
|---|---|
| subdomain discovery / OSINT | domain scope entries |
| DNS resolution | all in-scope hostnames (active, or inactive but seen in the last 30 days — to detect reappearance) + scope domains |
| IP enrichment | active in-scope/derived IPs |
| port discovery | scope IPs and CIDRs + active **derived** IPs (skipping CDN edges if `skip_cdn_ips`) |
| HTTP discovery | `host:port` for each in-scope hostname × open non-HTTP-excluded ports of its IPs (bare hostname if none known); IP-only ports; scope IPs; plus every known active endpoint (so disappearance is detectable) |
| vulnerability detection | active endpoint URLs |

It also returns `derived_from` (`ip → in-scope hostnames resolving to it`), built from active
`resolves_to` relationships, which the scope checker needs to authorize derived IPs.

## 4.4 Authorizing — `prepare_next_stage` + `ScopeChecker`

For each pending stage in order: build targets → determine whether this configuration is
active (`adapter.is_active(config)`, e.g. Amass `mode=active`) → `checker.check(target,
active=..., derived_from=...)` for every target → bulk insert `scope_decisions` (allowed and
rejected, with the reason and matched entry) → if nothing is allowed mark the stage
**skipped** and continue → otherwise decrypt the tenant's credentials for the adapter's
declared providers, seal them, create the `SensorJob`, mark the stage running.

`ScopeChecker` rules (see `app/scope/checker.py` docstring): exclusions win; hostnames match
domain entries (with/without subdomains); IPs match IP/CIDR entries; unmatched IPs are
*derived* only if an **allowed** in-scope hostname resolves to them and the organization
allows derived scanning; active mode requires `allow_active_scanning` and, when the tenant
requires it, a verified entry. CIDR targets must be inside an inclusion and not overlap an
exclusion.

## 4.5 Executing — the sensor side

In production the job travels as JSON over the broker to a sensor container
(`asm_sensors/worker.py`). `runner.execute_job` creates a temporary directory, unseals
credentials, builds an `ExecutionContext` (timeouts, output caps, `ASM_SCANNER_MAX_RATE`,
deployment settings such as the Nuclei templates path) and calls `adapter.run()`:

1. `check_targets` (kind allowed for this adapter) and `parse_config` (strict model) and
   `apply_limits` (clamp rates).
2. `validate_configuration` (binary present, required settings).
3. `execute` — writes targets to a file, runs the tool with `run_process`, reads its output
   file (falls back to stdout).
4. `parse_results` — tolerant parsing (bad lines skipped).
5. `normalize` — observations + coverage.

If the process failed or timed out, status becomes `partial` (or `failed` with no
observations) and **coverage is dropped**. Any exception becomes a `failed` result with a
sanitized message. The result goes back through the result backend to `tasks.ingest_stage`.

In inline mode `run_inline` does the same by calling `execute_job` directly.

## 4.6 Ingesting — `assets/ingest.Ingestor.ingest`

All in one transaction, serialized per organization with
`pg_advisory_xact_lock(hashtext('ingest:<org>'))`.

1. **Normalize** every observation: `normalize_value(type, value)`; hostnames are classified
   into `root_domain` (a scope root), `domain` (registrable domain), or `subdomain`
   (`asset_type_for`). Invalid values are counted and dropped. Duplicate asset observations
   are merged.
2. **Load** existing assets for all referenced keys in batches of 500
   (`tuple_(asset_type, normalized_value).in_(...)`), plus the IP of every port/service key.
3. **Scope status** (`_compute_statuses`):
   - hostnames → `ScopeChecker.hostname_status`; IPs → `ip_status`, keeping an existing
     *derived* status unless the IP is excluded; CIDRs in scope → in scope;
   - IPs become *derived* when an in-scope hostname `resolves_to` them, or an endpoint of an
     in-scope host is `hosted_on` them;
   - ports/services inherit from their IP, endpoints from their host;
   - context types (technology, certificate, ASN, CIDR, cloud resource) become *derived* if
     connected to an in-scope/derived asset (fixed-point, 3 rounds);
   - out-of-scope hostnames are kept (as `out_of_scope`) only if connected to our assets
     (e.g. a CNAME target, an MX host); unrelated third-party noise is dropped.
4. **Apply assets** (`_apply_asset`, in `AssetType` order so hosts precede their children):
   - new → insert with `first_seen = discovered_at = now`, default approval
     (`root_domain`/in-scope IPs/context types → approved; out-of-scope → third party;
     everything else → **unverified**), then `detector.new_asset(...)` event;
   - existing and observed → `detector.attribute_changes(old_meta, new_attrs)` events (DNS/IP,
     service version, ASN/hosting, TLS protocol), shallow-merge attributes, `last_seen = now`,
     `missed_count = 0`, add the source, reactivate if inactive (`reappeared` event);
   - IPs get `hosting_provider` and `cdn` from their ASN (`cloud.provider_for_asn`).
5. **Platform relations**: `subdomain_of` to the closest scope root (`_structural_relations`);
   cloud resources for CNAME targets/hostnames matching cloud patterns plus `hosted_by`
   (`_cloud_relations`).
6. **Relationships** (`_upsert_relations`): insert new edges, refresh existing ones
   (`last_seen`, `missed_count = 0`, reactivate). Side effects: new `uses_technology` →
   technology detected; changed technology version → technology changed; a new
   `presents_certificate` while another certificate edge from the same endpoint is active and
   not re-observed → old edge deactivated + certificate changed event.
7. **Findings** (`findings_service.upsert_observation`): fingerprint =
   `sha256(tenant | asset | source | rule_id | normalized location)` (query strings dropped).
   New → insert (status `new`), enrich from cached intel (KEV/EPSS/CVSS), `detected` activity,
   vulnerability detected event. Existing → update last seen/evidence, `occurrence_count += 1`,
   `missed_count = 0`; if it was `remediated` → `reopened` + event. Accepted-risk and
   false-positive findings stay as they are.
8. **Coverage**:
   - `LivenessCoverage` → each listed asset not observed gets `missed_count += 1`;
   - `RelationCoverage` → for each parent, active edges of that relation to children of the
     child type that were not re-observed **and fall inside the constraints** (e.g. the
     child port is inside `port_spec`; for CDN IPs only `cdn_port_spec`) get
     `missed_count += 1`; at the relation threshold the edge deactivates (technology removed
     event; an IP left without in-scope names deactivates); ports/services/endpoints also
     get a liveness miss;
   - `FindingCoverage` → open findings from this source on those assets that match the
     severity/tag/rule filter and were not observed → `missed_count += 1`; at threshold →
     `remediated` + resolved event.
   - When an asset's `missed_count` reaches its type's threshold (`settings.inactivity`) →
     `_deactivate`: status inactive, `inactive_since`, disappeared event (not for context
     types), resolve its open findings, and cascade to owned children (hostname → endpoints,
     IP → ports and endpoints, port → services) without extra events.
9. **Observation history**: one `asset_observations` row per observed asset with its
   attributes (the "raw observations" tab).

Every event is written through `_event()`, which skips out-of-scope assets and stamps
`is_baseline` and `scan_id`.

## 4.7 Detection rules — `findings/rules.evaluate`

After each stage, the assets touched by ingestion are evaluated by platform rules (ports:
risky exposed services; endpoints: admin/remote-access interfaces, API documentation, weak
TLS, cleartext login pages, expired/expiring/self-signed/mismatched certificates). The rules
return a normal `SensorResult` with `source="asm-rules"` and a `FindingCoverage` over the
evaluated assets, and are ingested by a second `Ingestor`. Result: rule findings get the
same dedup, history and auto-resolution as scanner findings for free.

## 4.8 Finishing — `complete_stage`, `fail_stage`, `finalize_scan`

- `complete_stage`: failed result → stage `failed` (or `skipped` if optional); otherwise
  ingest + rules, store raw artifacts if the profile retains them, stage `completed` or
  `partial`, merge counters into `scan.stats`, record sensor seconds.
- `fail_stage` (Celery errback / watchdog): stage `failed`/`skipped`.
- `finalize_scan`: scan `failed` if nothing succeeded, `partial` if something failed,
  otherwise `completed` → `risk.recompute_organization` (scores, roll-up, risk
  increased/decreased events) → first successful scan sets
  `organization.baseline_completed_at` → `scan_completed`/`scan_failed` event →
  `metrics.snapshot_organization`.

## 4.9 Notifying — `integrations/notifications.dispatch_pending`

Runs after every scan and every minute. Takes up to 1000 events with `notified = false`
(`FOR UPDATE SKIP LOCKED`), marks them notified, and for each tenant matches events against
enabled policies (`policy_matches`: event types, minimum severity, organizations, baseline
excluded unless allowed, throttling). Matching events are **batched per channel**, delivered
once per channel via `channels.CHANNELS[type].send(config, secret, payloads)`, and logged in
`notification_deliveries`. Failures are retried with exponential back-off up to 5 attempts
(`retry_failed`).

## 4.10 Periodic work (`workers/celery_app.py` beat schedule)

| Task | When | Does |
|---|---|---|
| `dispatch_schedules` | every minute | creates scans for due cron schedules (`maintenance.fire_schedule`) |
| `dispatch_queued_scans` | every minute | retries queued scans |
| `dispatch_notifications` | every minute | as above + retries |
| `watchdog` | every 5 min | fails stages running longer than the stage timeout + 15 min |
| `maintenance` | hourly | age-out (not seen for `max_age_days`), certificate expiry events (30/14/7/1 days, once each), expired risk acceptances reopen, retention purge |
| `refresh_intel` | daily 03:05 UTC | KEV, EPSS (for CVEs in findings), NVD CVSS gaps, re-enrich + rescore |
| `recompute_all_risk` | daily 04:10 UTC | age factors change daily |
| `snapshot_metrics` | daily 00:05 UTC | trend data |

## 4.11 Where to look when…

| Symptom | Look at |
|---|---|
| A stage is skipped with "No authorized targets" | `scope_decisions` for the scan (UI: scan → Authorization log); `build_targets`; `derived_from` |
| A new asset produced no event | it was out of scope (`_event` skips), or it is a context type, or the scan was the baseline (events hidden by default) |
| A port did not close | coverage constraints (`port_spec`, CDN), inactivity threshold, stage status partial/failed (coverage dropped) |
| A finding did not resolve | `FindingCoverage` filter (severity/tags), threshold, finding status accepted/false positive |
| Duplicate findings | location normalization or rule id changed between template versions |
