# Historical state and change detection

## What is stored

| Table | Meaning |
|---|---|
| `assets` | Current state + `first_seen`, `last_seen`, `last_scanned_at`, `status`, `inactive_since`, `missed_count` |
| `asset_observations` | Every sighting of an asset by a sensor, with the attributes observed (raw observation history) |
| `asset_relationships` | Graph edges with their own `first_seen`/`last_seen`/`active`/`missed_count` |
| `asset_events` | The change log: `event_type`, `severity`, `previous_state`, `new_state`, timestamp, related asset/finding, source scan, `is_baseline`, `acknowledged`, `notified` |
| `finding_activities` | Detection, re-detection, automatic resolution, reopening and analyst actions |

Assets are **never deleted** because a scan did not see them.

## How disappearance is decided (coverage)

A sensor only vouches for what it enumerated completely:

- dnsx re-resolves every known in-scope hostname ⇒ a name that stops resolving is *missed*.
- Naabu scanned `port_spec` on these IPs ⇒ an open port inside the spec that is not seen is *missed*;
  port 8443 is untouched by a scan that only probed 80/443.
- httpx probed `host:port` ⇒ endpoints on those host/ports that did not answer are *missed*.
- Nuclei ran severities S / tags T on these endpoints ⇒ open findings of that class not seen are *missed*.

After a configurable number of **consecutive** misses the asset (or relationship, or finding)
changes state:

| Setting (`settings.inactivity`) | Default |
|---|---|
| `subdomain` / `root_domain` / `domain` | 3 |
| `port`, `service`, `http_endpoint` | 2 |
| `relation` | 2 |
| `finding` (automatic resolution) | 2 |
| `max_age_days` (time-based: not seen at all) | 30 |

Failed or partial sensor runs carry no coverage, so outages never produce false
"port closed" / "asset disappeared" / "resolved" events.

Cascades: a hostname that disappears retires its web endpoints; an IP that is no longer
referenced by any in-scope name retires its ports and services; an asset that disappears
auto-resolves its open findings (they re-open if it returns).

## Baseline

The first successful scan of an organization is its **baseline**: everything it finds is
recorded with `is_baseline=true` and never alerted. From the second scan on, events are
real changes.

## Event catalogue

| Event | Trigger | Default severity |
|---|---|---|
| `new_subdomain` | New in-scope hostname | medium (unverified) / low |
| `new_asset` | New IP, domain, cloud resource, certificate, network | low–medium |
| `asset_exposed` | New web endpoint | medium; high for admin/remote-access interfaces |
| `port_opened` | New or re-opened port | by service: high for RDP/SMB/DB/VNC…, critical for Docker API, low for 80/443, medium otherwise |
| `port_closed` | Port missed beyond threshold | low |
| `service_detected` / `service_changed` | Product/version identified or changed | low / medium |
| `ip_changed` / `dns_changed` | A/AAAA set changed / other record types changed | medium / low |
| `hosting_changed` | IP moved to another ASN | medium |
| `certificate_changed` | Endpoint presents a different certificate | low; medium when the issuer changed |
| `certificate_expiring` / `certificate_expired` | 30/14/7/1-day thresholds (daily maintenance) | medium/high |
| `technology_detected` / `technology_changed` / `technology_removed` | Web technology relations | low (medium for admin panels / API docs) / low / info |
| `vulnerability_detected` / `vulnerability_resolved` / `vulnerability_reopened` | Finding lifecycle | finding severity / info / finding severity |
| `risk_increased` / `risk_decreased` | +10 points or level up / level down | high if new level ≥ high |
| `asset_disappeared` / `asset_reappeared` | Liveness | low |
| `ownership_changed` / `approval_changed` | Analyst actions | info |
| `scan_completed` / `scan_failed` | Scan lifecycle | info / medium |

Rules live in `backend/app/changes/detector.py` (pure functions, unit-tested in
`tests/backend/test_detector.py`); the ingestion engine (`backend/app/assets/ingest.py`)
decides when to apply them. Scenario tests: `tests/backend/test_change_detection.py`.

Example (as rendered in notifications):

```text
NEW EXTERNALLY EXPOSED SERVICE
Asset:     vpn.example.com (198.51.100.7)
Previous:  443/tcp
Current:   443/tcp, 10443/tcp
New:       10443/tcp
First seen 2026-09-18 09:42 UTC      Risk: High
```
