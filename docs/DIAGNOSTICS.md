# Diagnostics & Support

Three tools, from inside the product to outside it:

| Tool | Who | Works when |
|---|---|---|
| **Diagnostics & Support** page (`/diagnostics`) | tenant administrators (their tenant only) | the web app is up |
| **Platform diagnostics** page (`/platform/diagnostics`) | platform administrators | the web app is up |
| **Diagnostic CLI** (`exteriqctl diag` native, `docker compose exec asm-api python -m app.diagcli` in Docker) | root on the host | database, broker or web app down |

Nothing is uploaded or sent anywhere. Support bundles and diagnostic archives are files you
download or copy and hand over yourself.

## Tenant view — Diagnostics & Support

Permission `diagnostics:read` (tenant admins, analysts with it); bundles need
`support:bundles` (tenant admins). Every query runs in the caller's tenant session, so
PostgreSQL row-level security decides what exists: another tenant's scans, events and bundles
are not "hidden", they are not visible to the query at all.

- **Overview (7 days):** scans by status, partial/failed stages, timeouts, typical queue wait
  and stage run time (medians), failed notifications, and whether the scanner that runs this
  tenant's scans is reporting and has its detection content. No queue depths, hosts or engine
  names (a shared pool's queue reveals other tenants' activity).
- **Scan timelines (30 days):** per stage — status, coverage (complete/partial/none), targets,
  **queue wait** (dispatched → scanner started), **run time** (scanner start → finish),
  **ingestion** (scanner finish → results stored), retries, time-outs, and the error.
- **Problems (30 days):** failed/partial/skipped stages with their error, failed notification
  deliveries, failed or blocked website screenshots, inconclusive Threat Center checks.

Anything that was not measured is shown as **Unavailable** with the reason (for example
stages that finished before timing was recorded) — never as zero or healthy.

## Platform view — Platform diagnostics

Permission `platform:diagnostics` (platform administrators only; not grantable to tenant
roles). Runs in a system session.

- **Service health:** heartbeats of API, worker, ingestion and scheduler (every 30 s; missing
  for 90 s = unavailable) with versions; each scanner pool's instances, detection content,
  last job and recent errors; broker and database status (server version, schema vs. the
  release's expected schema, size, connections); host load, memory, disk free (data and tmp),
  cgroup OOM kills; on native installs, each systemd unit's state, restarts, last result
  (OOM-killed is flagged) and memory.
- **Queues:** depth and age of the oldest message of `core`, `scanners.<pool>`,
  `results.<pool>`.
- **Operational events (14 days):** WARNING+ events from the `ops_events` table, filterable by
  level, service, error code, tenant; redacted like every log event.
- **Scan timelines** across tenants (tenant id and name shown).

All lists are paginated and bounded on the server (50 per page, at most 20 pages).

## Support bundles

**Generate support bundle** → choose a time window (up to 30 days) and, for a tenant bundle,
up to 20 scans whose cleaned stage output to include → **Preview contents** lists what will
and will never be included, with counts → **Generate**. Generation runs in the background
with progress; when ready, **Review & download** shows every file and its size (and the
archive's SHA-256) before you download.

| | Tenant bundle | Platform bundle |
|---|---|---|
| Who | `support:bundles` in that tenant | `platform:diagnostics` |
| Contains | scan timelines, cleaned stage output of the selected scans, diagnostic events, audit actions (no IP addresses or changed values), scanner availability, versions, allowlisted configuration summary | service/scanner/queue/host health, redacted operational events, scan timelines by tenant id, versions (application, engines, OS, database), allowlisted configuration summary |
| **Never** | environment files, keys and other secrets; database dumps; screenshots; raw finding evidence and request/response bodies; raw HTTP traffic; other tenants' data | same |

Limits: 50 MB, 120 s to build, 5 000 events per file (the manifest lists anything
shortened), one active bundle per tenant and three platform-wide; bundles expire after
**7 days** and are deleted by the retention task. Every create, download and delete is
audited. Ownership is checked at creation, status, download and deletion (a tenant session
only ever sees its own bundles; platform bundles have no tenant and are platform-only).
Archive member names are generated from a strict pattern, so nothing can escape the archive
root. Deleting an organization queues its bundles for deletion; deleting a tenant removes
them with the tenant's stored objects.

## Diagnostic CLI

```bash
sudo exteriqctl diag              # summary + archive in /var/lib/exteriq/diagnostics (0600)
sudo exteriqctl diag --archive    # same; the archive path is printed
sudo exteriqctl status            # units, active release, schema
```

It reads `/etc/exteriq/exteriq.env` (secret values are reported only as "(set)"), then checks
each part on its own with short time-outs: versions, systemd units (state, restarts, OOM),
recent warnings from the journal (redacted), tails of `/var/log/exteriq/*.json`, the database
(reachability, schema vs. expected), the broker (reachability, heartbeats, queue depths), and
disk/memory. A part that cannot be checked is reported as unavailable with the reason; the exit
code is 2 when anything is missing. It never restarts, repairs or deletes anything.
