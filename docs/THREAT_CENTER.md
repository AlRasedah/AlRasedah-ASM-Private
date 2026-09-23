# Threat Center

The Threat Center answers one question for each tenant:

> A serious vulnerability was announced. Which of our assets may be affected, which have
> been checked, and what remains unresolved?

It is deliberately lean: **curated advisories** written by the platform team, matched
**deterministically** against the inventory the platform has already recorded, with an
optional **approved check** that runs through the ordinary scan pipeline. There is no
intelligence subscription, no language model and no automatic campaign writing.

## For tenants

**Threat Center** (sidebar) lists published advisories with, for your tenant only:

| Column | Meaning |
|---|---|
| May be affected | every asset still on the advisory's list, whatever its state below |
| Confirmed | a **verified** finding (from an active scan or check) names the advisory |
| Not detected | a completed approved check did not detect it — **not proof the asset is safe** |
| Inconclusive | the check failed, was blocked, cancelled, timed out, or could not reach the asset |
| Remediation | how many of those your team marked resolved, accepted or not applicable |
| Assessed | when your inventory was last matched against the current advisory version |

The organization selector at the top narrows everything to one organization.

The **detail page** shows the advisory (summary, affected products and how they are
matched, remediation guidance, reference links, KEV/EPSS/CVSS from the platform's
vulnerability intelligence) and every matched asset with its **evidence** (which product
name and version was seen, where, and why it counts), linked **findings**, the asset
**owner** and business unit, the **last check** and the **remediation** status.

### What each assessment means

| Assessment | Meaning | Counted as "may be affected" |
|---|---|---|
| Confirmed | A verified finding exists on the asset (or the approved check detected the issue) | yes |
| Check running | An approved check was requested and has not finished | yes |
| Checked — not detected | The check completed cleanly on this asset and found nothing. It tested one detection method at one moment | yes |
| Check inconclusive | Failed, partial, blocked by scope or egress policy, cancelled, timed out, or no reachable web endpoint | yes |
| Potentially affected | The product and (where known) version recorded in inventory are inside an affected range | yes |
| Version unknown | The product was seen but no usable version was reported | yes |
| Reported, unverified | Only a third-party exposure database (e.g. Shodan) reported it; nobody tested it | yes |
| Version not affected | The product was seen at a version outside every affected range | no |
| No longer observed | It matched before; the evidence is no longer in inventory (history is kept) | no |

Rules that are enforced in code and tests, not just described:

- A product/version match is **never** "confirmed". Banners can be wrong and vendors
  back-port fixes without changing the version.
- A third-party report stays **unverified** until an independent sensor that actually
  tested the service reports a finding.
- A failed, partial, cancelled or blocked check is **inconclusive**; it never becomes
  "not detected", never closes a finding and never marks anything remediated.
- "Checked — not detected" is still counted as possibly affected and does not change the
  remediation status.
- Findings are **referenced**, never copied: the Threat Center links to the finding that
  the scan pipeline already owns.

### Check selected assets

Analysts and administrators (permission `scans:run`) can tick assets and choose **Check
selected assets** when the advisory names an approved check. One scan per organization is
created through the **normal pipeline**: scope authorization (every target is recorded in the
scan's authorization log), active-scanning permission in scope and plan, the daily scan
quota, tenant and platform concurrency limits, the tenant's scanner pool and the egress
filter all apply. The scan runs only the approved detection, only against the selected
assets' web endpoints, and appears in **Scans** like any other scan.

- A second click while a check for the same advisory and organization is queued or running
  starts nothing (HTTP 409, with the running check's id).
- At most 50 assets per request.
- Assets without a reachable web endpoint (for example a service with no HTTP endpoint)
  come back **inconclusive** with that reason.
- A check never launches a full scan, and no check runs automatically.

### Remediation

Remediation is your team's workflow and is **separate** from what scans report: open, in
progress, resolved, accepted risk, not applicable, with an optional assignee (an active
member of the tenant) and a note. Every change is recorded in the audit log. A confirmed
asset stays confirmed in history after it is fixed; its remediation shows "resolved".

### Notifications

When an evaluation **creates** matches that may be affected, one change event
("*Advisory title*: N assets may be affected") is written per organization and advisory,
with the advisory's severity. It flows through notification policies and personal alerts
like any other event. Re-evaluating the same inventory never emits it again.

### Export

**Export CSV** on the detail page downloads this tenant's assets for the advisory (up to
10 000 rows), with evidence, check outcome, findings, remediation and owner. Exports are
audited (`data.exported`) and neutralize spreadsheet formulas.

## For platform administrators

**Threat Center → Manage advisories** (permission `intel:admin`, platform administrators
only):

- **New advisory** — identifier, title, severity, CVEs, summary, remediation guidance,
  reference links, source publication/update dates, affected products, optional approved
  check. It starts as a **draft**, which tenants cannot see (enforced by PostgreSQL RLS).
- **Affected products** — a display name, the names fingerprinting reports for it
  (technology names, service products, web-server products; compared after lower-casing and
  collapsing spaces/underscores) and version ranges: *from* (inclusive), *fixed in*
  (exclusive) or *up to* (inclusive). No range means every version is affected.
- **Publish** freezes the draft as a new immutable version and matches it against every
  tenant's inventory. Editing a published advisory creates a new draft; tenants keep seeing
  the published version until the draft is published.
- **Archive** stops evaluation and hides the advisory from the default list; tenants keep
  their history and remediation records. **Restore** brings it back.
- **Approved checks** — the allowlist. A check has an identifier, a name, and the id of one
  detection in the deployment's vetted detection-template set. Advisories can only name
  checks from this list; the reference is validated on save, on publish and again when a
  check runs. The check always runs with the scanner's safe defaults (no intrusive or
  denial-of-service classes, no out-of-band callbacks).

Advisory content is **data only**: there is no field for commands, template bodies,
scripts or download locations, and unknown fields are rejected. Reference links must be
plain `http(s)` links without credentials; they are shown to people and never fetched by the
platform.

Every catalog change is recorded in the **platform** audit chain.

## How matching works

Matching reads only what fingerprinting already recorded for the organization's **active,
in-scope or derived** assets:

1. `uses_technology` relationships (technology name + version on the edge) — the asset is the
   web endpoint;
2. service assets (`product`, `version`);
3. web endpoints' `Server` header (`nginx/1.24.0` → `nginx`, `1.24.0`).

Versions are compared with a small, documented rule (numbers as numbers, words as words, a
number outranks a word, missing positions count as 0; `1.0rc1 < 1.0 < 1.0.1`). A value that
does not start with a digit is "unknown", never guessed.

Existing findings whose CVE list contains one of the advisory's CVEs (or whose detection id
is one of its approved checks) link to the match: verified findings confirm, unverified
third-party findings only add a "reported, unverified" row.

Evaluation runs **incrementally**:

| Trigger | Scope |
|---|---|
| A scan of an organization completes (or partially completes) | every published advisory × that organization |
| A version is published or an advisory restored | that advisory × every tenant |
| Daily at 04:40 UTC (`asm.core.threat_evaluate`) | safety net: everything |
| Platform admin → `POST /threat-catalog/evaluate` | everything, now |

Each evaluation of an organization holds a PostgreSQL advisory lock for that organization
and is idempotent: a match is unique per tenant, advisory and asset.

## Limits

| Limit | Value | Where |
|---|---|---|
| Product observations read per organization per evaluation | 20 000 | `app/threats/service.py` `MAX_OBSERVATIONS` |
| Matches per advisory per organization per evaluation | 5 000 | `MAX_MATCHES_PER_ADVISORY` |
| Assets per "Check selected assets" | 50 | `MAX_CHECK_ASSETS` |
| Affected products / version ranges / references / CVEs per advisory | 20 / 20 per product / 20 / 50 | `app/threats/content.py` |
| CSV export rows | 10 000 | `app/api/v1/threats.py` |

Checks additionally consume the tenant's normal scan quota and concurrency.

## Failure behavior and recovery

- Threat Center updates after a scan run inside a database **savepoint**: an error there is
  logged (`Threat Center update failed after scan …`) and never fails the scan, loses its
  results or blocks cancellation.
- If an evaluation fails for one tenant, the others continue; the daily run or
  `POST /threat-catalog/evaluate` repairs it. The "Assessed" column shows how fresh each
  tenant's assessment is; "updating" means a newer version has not been matched yet.
- A check whose scan is cancelled, fails, or is failed by the watchdog is marked
  inconclusive; request it again once the cause is fixed.

## Tenant isolation

The catalog is global, but only **published** advisories and versions are readable by tenant
sessions, and only system sessions (platform administration) can write it — both enforced
by RLS policies (`catalog_read` / `catalog_write`). Matches, check runs and campaign
bookkeeping are tenant-owned tables under the standard `tenant_isolation` policy. Another
tenant's match or check-run id returns 404. See `tests/backend/test_threat_center.py`.

## API

| Endpoint | Permission |
|---|---|
| `GET /threats` (`status=published\|archived\|all`, `q`, `organization_id`) | `findings:read` |
| `GET /threats/{id}` | `findings:read` |
| `GET /threats/{id}/assets` (`assessment=…`, `organization_id`) | `findings:read` |
| `GET /threats/{id}/assets/export.csv` | `findings:read` |
| `POST /threats/{id}/checks` `{match_ids}` / `GET /threats/{id}/checks` | `scans:run` / `findings:read` |
| `PATCH /threats/matches/{id}` `{remediation_status, assigned_to, remediation_note}` | `findings:write` |
| `GET/POST /threat-catalog`, `GET /threat-catalog/{id}`, `PUT /threat-catalog/{id}/draft`, `POST /threat-catalog/{id}/publish\|archive\|restore`, `POST /threat-catalog/evaluate` | `intel:admin` |
| `GET /threat-catalog/checks`, `PUT /threat-catalog/checks/{key}` | `intel:admin` |

## Known limitations

- Matching sees only what fingerprinting recorded. Assets that were never scanned, or whose
  product is not identified by name, cannot match. The empty state says so.
- Version comparison cannot know about distribution back-ports.
- Approved checks run against web endpoints; network-service-only assets are inconclusive.
- A check detection that lands on a different asset than the matched one (for example a
  finding on the web endpoint while the match is on the service) confirms the endpoint's
  row, not the service's.
- No automatic advisory authoring or feed import; curation is manual by design.

## Measured cost

Measured on the development workstation (Windows 11, PostgreSQL 18 in WSL, Python 3.13), one
synthetic organization with 5 000 hostnames, 1 000 IPs, 3 000 ports and 5 000 web endpoints
(≈ 23 000 relationships), one advisory matching `nginx` in a version range, 23 September 2026:

| Operation | Time | Python peak memory |
|---|---|---|
| Read and match 10 000 product observations (no writes) | 0.8 s | 16 MB |
| First evaluation: 5 000 match rows written, 2 500 potentially affected, 1 event | 5.1 s | 52 MB |
| Re-evaluation of the same inventory: 0 new matches, still 1 event | 1.6 s | 44 MB |

This runs in the background (scan finalization or the Celery worker), never in a request.
It grows linearly with matched assets and is capped per advisory and organization (above).
Not measured: many advisories at once, concurrent evaluations, a production-sized database.
