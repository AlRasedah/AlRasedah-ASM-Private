# Logging

Every Exteriq process (API, core worker, ingestion, scheduler, scanners) writes **one JSON
event per line to stdout**. Nothing in the application writes, rotates or deletes log files.

- **Docker:** Docker's logging driver collects stdout (`docker compose logs`, or your driver).
- **Native (Ubuntu):** systemd-journald stores stdout; **rsyslog is the one collector** that
  files the events into `/var/log/exteriq/` by stream; an hourly timer rotates the files.

```
service stdout ──► journald ──(imjournal, saved cursor)──► rsyslog ──► /var/log/exteriq/*.json
                                                                   └─► errors.json (WARNING+)
```

## Event schema `exteriq.event/1`

```json
{"schema":"exteriq.event/1","ts":"2026-09-25T10:00:00.123Z","event_id":"9f1c…",
 "event":"scan.stage.finished","level":"INFO","stream":"scans","service":"worker",
 "version":"0.1.0","logger":"exteriq.scans","msg":"stage passive_discovery completed",
 "tenant_id":"…","request_id":"…","correlation_id":"…","scan_id":"…","stage_id":"…",
 "job_id":"…","pool":"default","status":"completed","coverage":"complete",
 "queue_wait_ms":1200,"execution_ms":41000,"ingestion_ms":340,"target_count":12,"retries":0}
```

| Field | Meaning |
|---|---|
| `schema` | Always `exteriq.event/1`. A breaking change gets a new version. |
| `ts` | UTC, millisecond precision, `Z` suffix. |
| `event_id` | Unique per event. Exported alerts and audit records use the **source row's id**, so a re-export repeats the same id (deduplicate on it). |
| `event` | Stable dotted name (`scan.stage.finished`, `finding.detected`, `http.request`, `logging.events_dropped`, …). |
| `level` | Operational level: `DEBUG` `INFO` `WARNING` `ERROR` `CRITICAL`. **Never a finding's severity.** |
| `severity` | A finding's severity (alerts stream only). |
| `stream` | `application` (default), `scans`, `alerts`, `audit`. |
| `service`, `version` | Which process and release wrote it. |
| `error_code` | Stable code (table below) on events that describe a failure. |
| context ids | `tenant_id` `organization_id` `user_id` `request_id` `correlation_id` `task_id` `task` `scan_id` `stage_id` `job_id` `pool` |
| measurements | `duration_ms` `queue_wait_ms` `execution_ms` `ingestion_ms` `target_count` `rejected_count` `observation_count` `retries` `attempt` `coverage` `count` `size_bytes` |
| `exc` | Exception type, redacted message and the last frames (never locals). |
| `truncated`, `dropped_fields` | Present when the event was cut to 16 KB, or carried fields outside the allowlist (dropped, only counted). |

### What is never logged

Only allowlisted fields are serialized; everything else attached to a log call is dropped.
The **finished event** is then redacted as a whole (message, exception text, nested values):
URL credentials, secret-looking query parameters, `Authorization`/`Cookie`/`Set-Cookie`
headers, bearer/basic tokens, `key=value` secrets, JWTs and PEM blocks. Request and response
bodies are not logged; `http.request` events carry method, route template, status and
duration only — never the query string. The native nginx access log records the path
without the query string for the same reason (one-time links carry tokens).

### Correlation and tenant identity

- An API request binds `request_id` (the `X-Request-ID` header when it is a safe id, else
  new) and `correlation_id`. `tenant_id`/`user_id` are added **only after authentication**.
- Publishing a Celery task adds header `exteriq_ctx` with `request_id`, `correlation_id` and
  the publish time. A task binds a fresh context from it — **never tenant ids**: tasks add
  `tenant_id`, `scan_id`, … after loading the row they work on.
- Scanners take tenant/scan/stage/job/pool from the authenticated job envelope; result
  ingestion adds them only after the result's HMAC and job binding verify.
- The context is replaced at the start of every request and task and cleared afterwards, so
  nothing carries over from one tenant's work to another's.

### Tenant-facing progress vs. operator diagnostics

Scan progress and stage output that tenants see come from the database (stage rows, the
cleaned stage output). The log streams are operator data: tenants never read them.
Diagnostics & Support shows tenants only their own records (see DIAGNOSTICS.md).

## Streams and files (native)

| File | Contains | Source | Durability |
|---|---|---|---|
| `application.json` | Everything not in another stream; process output that is not JSON is wrapped (`event: process.output`) | all services | Best effort (see below) |
| `errors.json` | Every event with level WARNING or higher (also filed in its stream's file) | all services | Best effort |
| `scans.json` | Scan/stage lifecycle with timing, coverage, retries | worker, ingest, scanners | Best effort; the database is authoritative |
| `alerts.json` | Committed finding changes (`finding.detected`, `finding.resolved`, `finding.status_changed`, …) | worker export task | **At-least-once**, deduplicate on `event_id` |
| `alerts.log` | The same alerts, one human-readable line each | derived by rsyslog from `alerts.json` events | as alerts.json |
| `audit.json` | Export of the hash-chained audit log | worker export task | **At-least-once**, `event_id` = audit row id |

Permissions: `/var/log/exteriq` is `0750 syslog:adm`, files `0640 syslog:adm`.

### Alerts: transactional outbox

A finding change is a `finding_activities` row written in the same transaction as the change,
so a rolled-back change never produces an alert. Every minute the worker exports rows with
`exported_at IS NULL` (locked with `SKIP LOCKED`, oldest first), writes each synchronously to
stdout and sets `exported_at` only after the write succeeded, then commits. A failed write
stops the batch (`ASM-OPS-001`); the rows are exported again next time with the same
`event_id`. A crash between write and commit can repeat events — hence *at-least-once*.
Comment text is never exported.

### Audit: export, not a second audit log

The database audit log stays authoritative and hash-chained (`docs/SECURITY.md`). The export
walks it by id with a cursor (`event_export_state`); ids that were not yet visible when the
cursor passed them (concurrent transactions) are remembered as gaps and exported when they
appear, for up to an hour. Each event carries `chain_seq`, `entry_hash` and the tenant, so a
receiver can check continuity per tenant.

### Where events can be lost, and how you see it

| Point | Behaviour | Visible as |
|---|---|---|
| Process → stdout | Bounded in-memory queue (10 000 lines) and a writer thread: logging never blocks a request or a scan. When stdout stalls the queue fills and further events are **dropped**. | `logging.events_dropped` (`ASM-OPS-003`, `count`) written before the next event that gets through, and on shutdown. |
| Alert/audit export | Written synchronously; never dropped, retried next minute. | `ASM-OPS-001` |
| journald | Per-service rate limit (API/ingest/scanners 20 000, worker 50 000 lines per 30 s). | journald logs "Suppressed N messages" for the unit. |
| journald storage | The system journal's size limits apply (`journalctl --disk-usage`). | journald's own messages. |
| rsyslog down | Events stay in the journal; rsyslog resumes from its saved cursor when it starts (`/var/spool/rsyslog/exteriq-imjournal.state`). Events that aged out of the journal meanwhile are lost. | Gap in file timestamps; `journalctl -u rsyslog`. |
| rsyslog queue | In-memory queue of 50 000 events, spilling to disk (max 256 MB) when the files cannot be written. | `impstats`/rsyslog's own errors in the journal. |
| Disk full | rsyslog suspends the file action and retries; the journal keeps the events meanwhile. | rsyslog errors in the journal; `df` in `exteriqctl diag`. |
| Rotation | `logrotate` with rsyslog HUP (no `copytruncate`): no line is lost or duplicated at rotation. | — |
| Oversized event | Cut to 16 KB with `"truncated": true`; rsyslog accepts up to 64 KB per message. | `truncated` field |

### Rotation and disk bounds (native)

`exteriq-logrotate.timer` runs hourly with its own state file
(`/var/lib/exteriq/logrotate.state`, config `/usr/share/exteriq/logrotate.conf`): each file
rotates daily or at 100 MB, keeps 14 compressed generations, none older than 30 days. The
system-wide daily logrotate does not touch these files.

### Operational database sink

Besides stdout, API, worker, ingest and scheduler keep WARNING+ events in the `ops_events`
table (14 days, at most 50 000 rows) for **Platform diagnostics → Operational events**. It is
buffered (500 events) and flushed every 3 s; if the database is unavailable the buffer is
kept and overflow counted (`ASM-OPS-002`). Disable with `ASM_OPS_EVENTS=false`.

## Error codes

Codes never change meaning; new ones are added, none are reused.

| Code | Meaning |
|---|---|
| `ASM-SCAN-001` | A required stage failed |
| `ASM-SCAN-002` | A stage ran but could not vouch for complete coverage (partial) |
| `ASM-SCAN-003` | A stage hit its time limit |
| `ASM-SCAN-004` | The watchdog failed a stage whose job never reported back |
| `ASM-SCAN-005` | A job could not be published to the scanner queue |
| `ASM-SCAN-006` | A submitted result failed authentication or job binding |
| `ASM-SCAN-007` | Stage output failed authentication or binding |
| `ASM-SCAN-008` | An optional stage failed and was skipped |
| `ASM-SCNR-001` | A job reached a scanner after its start deadline |
| `ASM-SCNR-002` | A scanner engine binary is missing |
| `ASM-SCNR-003` | Detection content is not installed on the scanner |
| `ASM-SCNR-004` | A scanner job failed |
| `ASM-OPS-001` | Alert/audit export could not complete a batch |
| `ASM-OPS-002` | Operational events could not be stored for the UI |
| `ASM-OPS-003` | The log writer dropped events |
| `ASM-OPS-004` | Support bundle generation failed |
| `ASM-OPS-005` | Database unavailable |
| `ASM-OPS-006` | Broker unavailable |
| `ASM-NTF-001` | A notification delivery failed |
| `ASM-INT-001` | A vulnerability intelligence feed could not be refreshed |

## Reading the logs

```bash
journalctl -u 'exteriq-*' -f                       # everything, live
journalctl -u exteriq-worker -p warning --since -1h
jq -c 'select(.scan_id=="<id>")' /var/log/exteriq/scans.json
jq -c 'select(.error_code)' /var/log/exteriq/errors.json | tail
tail -f /var/log/exteriq/alerts.log
```

Forwarding to a SIEM: point your agent (Wazuh, Filebeat, …) at `/var/log/exteriq/*.json`, or
add an rsyslog forwarding action to the `exteriq` ruleset in a separate file.
