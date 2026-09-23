# Website screenshots

A screenshot lets an analyst recognise an exposed application — a VPN portal, a login
page, a default install — without opening every endpoint. It is a picture of what the page
showed an anonymous visitor at one moment. **It is never evidence of a vulnerability** and
never creates or verifies a finding.

The feature is **off until two people turn it on**: a platform administrator, once the
deployment's scanners have the pinned browser (and its sandbox works), and a tenant
administrator, for their tenant.

## For tenants

- **Asset → a web endpoint → Screenshots** shows the latest successful image, when it was
  captured, the page title, the address it finally loaded (without query string), the HTTP
  status and image size, and the last ten attempts with their state.
- **Capture screenshot** (analysts and administrators, permission `scans:run`) queues one
  capture of that endpoint. States: *waiting for a free capture slot* (queued), *capturing*
  (running), *succeeded*, *failed* (unreachable, timed out, not a web page, image or storage
  limit), *blocked* (scope, egress policy or the feature being turned off — nothing was
  fetched), *cancelled*. A failed or blocked attempt never removes the previous image.
- A second click while a capture of the same endpoint is waiting or running reuses it.
- Anyone who can read assets can view images; `assets:write` can delete one (audited).
- **Settings → Website screenshots** (tenant administrators): allow screenshots, and choose
  *on request only* or *weekly, plus on request*. The card shows today's captures against
  the daily limit and the storage used against the quota. When the platform has not enabled
  the capability, the card and the Screenshots tab say so instead of offering the button.

Inventory rows show no thumbnails: every image is fetched through the authenticated API,
so a thumbnail per row would add one request per row to the inventory page. The
Screenshots tab is where images live.

### What a capture does

It visits the endpoint once from **your tenant's scanner**, like a browser with no
cookies, and saves one image of the configured viewport (default 1280×800). It does not
crawl, sign in, fill forms or follow links. Because it contacts the target, it needs the
same **active-scanning authorization in scope** as HTTP discovery, and the plan must allow
active scanning; the endpoint must be active and not out of scope. Authorization is
checked when you click and again when the capture starts.

## For platform administrators

**Settings → Website screenshots — platform** (permission `tenants:admin`):

| Setting | Default | Bounds | Meaning |
|---|---|---|---|
| The scanners have the screenshot browser | off | — | offer the feature to tenants at all |
| Active captures, whole deployment | **1** | 1–8 | enforced in PostgreSQL across every process (see below) |
| Captures per tenant per day | 50 | 1–5000 | rolling 24 h, manual + weekly |
| Waiting captures per tenant | 10 | 1–500 | queued + running |
| Images kept per endpoint | **2** | 1–10 | older successful captures are deleted (object, then record) |
| Storage per tenant (MB) | 200 | 10–100 000 | a capture that would exceed it fails; older images stay |
| Keep failure records (days) | 30 | 1–365 | failed/blocked/cancelled records are purged after this |
| Page load limit (seconds) | 20 | 5–90 | the browser is stopped at this point |
| Viewport width / height (px) | 1280 / 800 | 320–1920 / 240–1200 | one viewport per endpoint, never full-page |
| Largest image (KB) | 2048 | 64–5120 | checked in the scanner **and** again by the platform |

Fixed limits (code): at most 5 redirects, 5 MB per response, 20 MB per capture, 300
connections per capture, 15 s idle per connection, ports 80/443/8080/8443 plus the
endpoint's own port, one image per job, 5 MB hard ceiling on the image in the broker
message.

## How it works

```text
Capture screenshot ─► request_capture (tenant session): feature on? endpoint web + active + in scope?
                      scope check (active) · daily and queue limits ─► capture row: queued
asm.core.screenshot_dispatch (every minute, and at once after a request or a result)
   system session: pg_advisory_xact_lock ─► fail lost captures ─► count running ─► reserve free slots
   (oldest first, one per tenant first) ─► running
   tenant session: authorize again (tenant active, feature on, scope, the tenant's own scanner pool)
   ─► SensorJob(adapter=screenshot, one URL, policy limits, scope exclusions) sealed and bound like
      any sensor job ─► scanners.<tenant pool>
tenant's scanner: pool lease "screenshot-browser" ─► reap stale browsers ─► egress proxy up
   ─► preflight (redirects followed by us, each hop through the proxy) ─► Chromium (fresh profile,
      no network of its own, sandbox on) ─► PNG checks ─► result envelope on results.<pool>
asm-ingest: MAC with the pool key · binding to the capture (tenant, id, job id, pool, still running)
   ─► re-validate the image (base64, size, checksum, PNG, dimensions) ─► quota ─► private object
      storage tenants/<tenant>/screenshots/<capture id>.png ─► retention ─► succeeded
```

### Why not the HTTP fingerprinter's own headless mode

The pinned HTTP fingerprinter can take screenshots, and reusing it was the first option
considered. It was not used because: a capture would run inside discovery, so a capture
problem could fail or slow discovery; its browser library downloads a browser at run time
unless told otherwise (not a pinned dependency); it disables the browser sandbox when run as
root; it captures full pages by default (unbounded image height); and it offers no way to
decide each connection the browser makes. The scanner image has never been built on the
machine this feature was developed on, so the fingerprinter's flags at the pinned version
could not be verified either. The adapter therefore drives the distribution's Chromium
directly, pinned in the image, as its own job.

### Destination control during browsing

The browser gets no network of its own. Its resolver maps every name to NOTFOUND except
the proxy's address, UDP (QUIC, WebRTC) is disabled, and every request — the page,
redirects, frames, scripts, images, fonts, WebSockets — goes through a per-job proxy on
127.0.0.1 that, for each connection:

1. accepts only `CONNECT host:port` or plain `http://` on an allowed port;
2. refuses hostnames excluded from scope, and browser-vendor background services;
3. resolves the name itself and refuses it if **any** address is loopback, private,
   carrier-grade NAT, link-local or cloud metadata (169.254.0.0/16, fe80::/10,
   fd00:ec2::254, 100.100.100.200 — refused even in lab mode), unspecified, multicast,
   reserved, or in the scope's excluded ranges — including IPv4 embedded in IPv6
   (mapped, 6to4, Teredo, NAT64);
4. connects to the exact address it checked. A name that resolves differently a moment
   later (DNS rebinding) is checked again on its next connection and refused.

Refused destinations are recorded as `host:port: reason` — never a path or query string.

### Isolation and cleanup

- A fresh browser profile directory per capture, inside the job's temporary directory,
  deleted with it: no cookie, credential, cache or history is shared between captures or
  tenants. The browser never receives tenant credentials.
- The job runs in the **tenant's own scanner pool** (ADR-025), so one tenant's captures never
  share a scanner with another tenant's.
- The sandbox stays on. Flags that would disable it are refused by the adapter
  (`FORBIDDEN_FLAGS`, including the GPU process's own sandbox); a container without the
  sandbox's prerequisites fails the capture with a message saying so. The GPU shader disk
  cache is off: Alpine's Chromium 152 writes it with a syscall (`pwritev2`) that its own
  GPU-process seccomp policy forbids, which crashed every capture on the first install.
- The browser runs in its own process group with a hard time limit; a cancelled or
  timed-out job kills the group. On Linux it is also started under
  `setpriv --pdeathsig KILL` (util-linux's, which the image installs; BusyBox's applet lacks
  the option and is never used), so it dies with its worker. Before each capture, while holding
  the pool's browser lease, the adapter kills any browser left behind by a worker that was
  killed outright.
- One browser per pool at a time (a lease in the broker, per pool), and at most the
  configured number of captures across the deployment (PostgreSQL).

### The deployment-wide limit

Every dispatcher — in every worker and container — takes the same PostgreSQL advisory lock,
fails captures that never reported back (not dispatched within 10 minutes, or no result
within 3 × page limit + 10 minutes), counts `running` rows and reserves only the free slots,
all in one transaction. Nothing depends on a process's memory, so restarting or scaling
workers cannot overlap captures beyond the limit.

## Failure behavior and recovery

| Situation | Result | What to do |
|---|---|---|
| Page slow or hanging | failed: did not finish loading within N seconds; browser killed | raise the page load limit, or accept |
| Endpoint unreachable, not a web page, image too large | failed, with the reason | — |
| Redirects to an internal or excluded address, or scope withdrawn | blocked | expected: the policy worked |
| Tenant storage quota full | failed: quota full; existing images kept | raise the quota or lower retention |
| Browser missing on the tenant's scanner | failed: not installed | build the scanner image with the browser (DEPLOYMENT.md §5b) |
| Browser sandbox unavailable | failed: sandbox unavailable | seccomp profile / user namespaces (§5b), then `browser-selftest` |
| Scanner crashed or killed | the watchdog fails the capture and frees the slot; the next capture on that pool reaps the stray browser | — |
| Screenshots break discovery? | never: they are separate jobs, dispatched separately | — |

## Storage and retention

Images are PNG files in the platform's private object store (local volume or S3-compatible)
under `tenants/<tenant id>/screenshots/<capture id>.png`. The key is derived by the platform;
no API accepts a storage key, and images are served only by
`GET /assets/{asset}/screenshots/{capture}/image`, which looks both up in the caller's
tenant session and requires the capture to belong to that asset (`no-store`, `nosniff`).

Retention runs after every successful capture and hourly (maintenance): the newest N
successful captures per endpoint are kept; failure records go after the configured days.
Deletion removes the object first and then the record; if the object cannot be deleted,
the record stays and the next run tries again. Deleting an organization deletes its images
before its records cascade.

## Resource measurements

Reproduce with `scripts/measure_screenshots.py` (real adapter, real browser, real egress
proxy, local fixture page; nothing leaves the machine):

```bash
docker compose -f docker-compose.yml -f docker-compose.screenshots.yml run --rm asm-scanner \
    python /opt/asm/measure_screenshots.py --runs 10
```

It prints per capture the wall time, the browser process tree's peak RSS and CPU time, the
image size, refused destinations and **every external destination the browser contacted**,
then a summary with derived estimates.

**Measured** on the development workstation (Windows 11, Google Chrome 153 — *not* the
deployment's Alpine Chromium), 8 captures of a ~40 KB fixture page at 1280×800, 23 September 2026:

| Metric | min | median | max |
|---|---|---|---|
| Wall time per capture (proxy start → image) | 0.47 s | 0.48 s | 0.57 s |
| Browser process-tree peak RSS (sum over processes; shared pages counted more than once) | 551 MB | 556 MB | 560 MB |
| Browser CPU time (user + system, all processes) | 1.05 s | 1.27 s | 1.48 s |
| Image size | 83 KB | 83 KB | 83 KB |
| Destinations refused per capture (metadata, excluded iframe, 2 vendor services) | 4 | 4 | 4 |

External destinations contacted besides the fixture: `www.google.com:443` and
`www.gstatic.com:443` — background requests of the *branded* Chrome build that pages also
use legitimately, so they are not refused. Distribution Chromium ships without Google's
service keys; check the list on your image with the script above.

**Estimates (not measured)**, from the numbers above:

- Queue delay: at the default limit of 1, a burst of 10 requests finishes its last capture
  after about 9 × capture time — ≈ 4–5 s on this page; real sites take longer (the page load
  limit, 20 s, is the ceiling per capture, so ≤ ≈ 3 minutes for 10), plus broker latency.
- Storage: retained bytes ≈ endpoints × images kept × mean image size — e.g. 500 endpoints ×
  2 × 83 KB ≈ 81 MB. Real pages are usually larger PNGs (0.1–1.5 MB at 1280×800 is typical
  for content-heavy pages), i.e. 100–1500 MB for 500 endpoints; the per-tenant quota caps it.
- Memory: plan ≈ 0.6 GB per concurrent capture on the scanner on top of the other sensors;
  the scanner service is capped at 2 GB.

Not measured here: the Alpine Chromium image, container memory accounting, queue delay
through a real broker, S3 latency. Run the script on the deployed image to replace these
estimates.

## Security notes

- Captures are unauthenticated only. Tenant credentials, sign-in values and cookies are
  never given to the browser.
- The proxy's refusals cover the browser's whole session; the runner's egress filter still
  checks the endpoint before the job starts, and the deployment's egress firewall remains the
  network-level control (DEPLOYMENT.md).
- Nothing about a capture is logged with a query string; stored URLs are stripped of query
  and fragment.
- TLS certificate errors are ignored for rendering (self-signed internal-looking sites are
  common on attack surfaces); nothing secret is sent, and the capture is labelled as what it
  is — a picture.
