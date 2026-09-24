# Threat Center

The Threat Center answers one question for each tenant:

> A serious vulnerability was announced. Which of our assets may be affected, which have
> been checked, and what remains unresolved?

Advisories are written **automatically** from free public data — every vulnerability in
CISA's Known Exploited Vulnerabilities catalog, with affected products and version ranges
from NVD — and platform administrators can add their own. They are matched
**deterministically** against the inventory the platform has already recorded, with an
**approved check** (by default the community detection for the CVE) that runs through the
ordinary scan pipeline. There is no paid intelligence subscription and no language model.

## Automatic advisories

Every hour the feed asks NVD for vulnerabilities in CISA's Known Exploited Vulnerabilities
catalog that are new or changed since the last run (the first run fetches all of them —
about 1 500 — in one request). For each CVE it writes an advisory:

| Advisory field | From |
|---|---|
| Title, required action | CISA KEV (vulnerability name, required action) |
| Summary, severity, references | NVD (description, CVSS base score → critical ≥ 9, high ≥ 7, medium ≥ 4) |
| Affected products and version ranges | NVD's CPE configurations — only the *vulnerable* entries, applications and operating systems (hardware is never fingerprinted by name) |
| Names matched against inventory | NVD's `vendor product` and `product` (unless too generic, e.g. `http_server`), built-in aliases for common products whose scan names differ (e.g. NVD `apache:http_server` → `apache`, `apache httpd`), the platform's own aliases, and CISA's vendor/product name |
| Approved check | the community detection named after the CVE (`cve-yyyy-nnnn`), unless turned off |

- **Published automatically** for exploited-in-the-wild CVEs by default; other sources wait
  as drafts. Settings: *publish exploited automatically* (default), *publish everything*, or
  *keep everything as drafts*.
- Optionally also **recent critical CVEs** (CVSS 9+, published in the last N days, 30 by
  default) that are not known to be exploited yet — as drafts unless *publish everything*.
- **Changes are followed.** When NVD revises a CVE (new ranges, new products), the next run
  writes a new version; the rules of the previous section apply (a check result stays only
  if the new version asks for the same detection and CVEs).
- **Your advisories win.** The feed never edits an advisory a platform administrator wrote
  for the same CVE (identifier `cve-yyyy-nnnn`), nor one you archived.
- **No flood on day one.** Matches of long-known vulnerabilities (listed more than 30 days
  before import) found during the first day after import do not notify; matches found later
  — a new asset running an exploited product — do.
- **A CVE NVD has not analysed yet** still becomes an advisory: it matches through findings
  that name the CVE until NVD adds products, and is updated then. CISA sometimes lists a CVE
  before NVD flags it; the feed looks those up individually (up to 10 per run).
- **Checks never pretend.** The automatic check names the community detection for the CVE.
  If the scanner's detection set has none, or classifies it intrusive, the scanner refuses
  the run and the check is **inconclusive** with that reason — never "not detected".

Tenants see **Affecting my assets** by default: advisories with at least one asset that may be
affected. **All advisories** lists the whole catalog; the catalog is the same for every
tenant, so it reveals nothing about another tenant's inventory. Advisories from CISA's
catalog carry an **exploited** badge.

**Settings → Threat Center → Manage advisories → Automatic advisories** (platform
administrators): on/off, publishing mode, recent critical CVEs, automatic checks, an
optional free **NVD API key** (write-only, encrypted; it raises NVD's limit from 5 to 50
requests per 30 seconds, which only matters for the first import), and product-name
aliases (`vendor:product = name, name`). **Update now** runs the feed immediately. The card
shows how many CVEs are tracked, published, waiting as drafts or unusable, and the last
error. Each run writes one summary entry to the platform audit chain.

Data sources and terms: CISA KEV and NVD are US-government public-domain data; FIRST EPSS is
free to use with attribution. The platform shows NVD's required notice: *This product uses
the NVD API but is not endorsed or certified by the NVD.* Outbound access needed:
`services.nvd.nist.gov` (the platform already fetches `www.cisa.gov` and `api.first.org`).

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
| Feed: CVEs per NVD page / advisories written per run / time per run | 2 000 / 3 000 / 10 min | `app/threats/feed.py` |
| Feed: KEV entries looked up one by one per run | 10 | `MAX_DIRECT_LOOKUPS` |

Checks additionally consume the tenant's normal scan quota and concurrency.

**When a bound is hit** the evaluation still adds and updates what it saw, but it is
*partial*: it marks nothing "no longer observed" (a bound is not evidence that anything
disappeared), and matches it could not reach keep their previous state. The advisory shows a
**partial** badge and the detail page names the organization and the bound. The next
evaluation that sees everything clears it. Beyond the match bound, assets already tracked
are kept current first.

## Failure behavior and recovery

- Threat Center updates after a scan run inside a database **savepoint**: an error there is
  logged (`Threat Center update failed after scan …`) and never fails the scan, loses its
  results or blocks cancellation.
- If an evaluation fails for one tenant, the others continue; the daily run or
  `POST /threat-catalog/evaluate` repairs it. The "Assessed" column shows how fresh each
  tenant's assessment is; "updating" means a newer version has not been matched yet.
- A check whose scan is cancelled, fails, or is failed by the watchdog is marked
  inconclusive; request it again once the cause is fixed.
- If recording a finished check fails (it runs in that savepoint), the check is not left
  "running": opening the advisory, the daily evaluation or `POST /threat-catalog/evaluate`
  finishes it from its scan's outcome, and a new check can be requested.
- A check's result belongs to what it tested. Each run records the detection and the CVEs
  it was dispatched with, and its result is read against those — never against a newer
  advisory version or a changed check. When a new version asks for a different detection or
  different CVEs, earlier results stop applying ("not yet checked" again; the run stays in
  the history). A version that only rewords the advisory keeps them.

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

This runs in the background (its own Celery job after a scan commits, or the daily run),
never in a request.

At feed scale, same workstation, 24 September 2026, a deliberately heavy synthetic case:
1 400 advisories (random products, about 115 of them for nginx, Apache, IIS, OpenSSH or Exim
with wide ranges) against one organization with 5 000 web endpoints and 3 000 services —
31 682 matches:

| Operation | Time | Python peak memory |
|---|---|---|
| First feed run: 1 400 CVEs from one NVD response, 1 400 advisories written and published | 21 s | 24 MB |
| First evaluation: 29 388 match rows written | 23 s | 213 MB |
| Re-evaluation, nothing changed (the cost after each scan) | 5.2 s | 183 MB |
| Hourly feed run with nothing new | 1.2 s | — |

Times include memory tracing. After a scan, matching runs as its own job once the scan has
committed, so a scan's finalization never waits for it; unchanged matches are not rewritten
(one statement updates their timestamp).
It grows linearly with matched assets and is capped per advisory and organization (above).
Not measured: many advisories at once, concurrent evaluations, a production-sized database.
