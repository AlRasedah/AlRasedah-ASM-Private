# Sensors (scanner adapters)

Scanners are *sensors*: they observe and report. The platform decides what to do with
what they saw. All sensor code lives in `workers/asm_sensors` and has no dependency on the
platform or its database.

## Built-in adapters

| Adapter | Stage | Active? | Tool / source | Coverage emitted |
|---|---|---|---|---|
| `subfinder` | subdomain discovery | passive | ProjectDiscovery Subfinder | none (passive enumeration is incomplete by nature) |
| `crtsh` | subdomain discovery | passive | crt.sh JSON | none |
| `amass` | subdomain discovery | passive (active mode optional) | OWASP Amass v4 graph output (v3 JSON also parsed) | none |
| `bbot` | discovery / OSINT | passive (optional) | BBOT JSON events | none |
| `spiderfoot` | OSINT / discovery | passive use case (optional) | SpiderFoot HTTP API | none |
| `dnsx` | DNS resolution | passive | ProjectDiscovery dnsx | liveness of every queried name; `resolves_to`, `cname` |
| `asnlookup` | network ownership | passive | Team Cymru DNS | `belongs_to_asn` |
| `naabu` | port discovery | **active** | ProjectDiscovery Naabu (connect scan) | `has_port` within the exact port spec (CDN IPs: 80/443 only) |
| `httpx` | web fingerprinting | **active** | ProjectDiscovery httpx | `serves` per probed host:port; `uses_technology`; `presents_certificate` |
| `nuclei` | exposure / vulnerability detection | **active** | ProjectDiscovery Nuclei | finding coverage for the configured severities/tags |
| `shodan` | IP enrichment | passive (queries Shodan, never the target) | Shodan host lookups (`/shodan/host/<ip>`) with the tenant's API key | finding coverage for its own (Shodan-tagged) reports only; **historical**, so no liveness/relation coverage |
| `zap_spider` | web crawling (+ passive scanning) | **active** (optional) | OWASP ZAP daemon (spider / AJAX spider / passive scanner) over REST | finding coverage for passive alerts on the crawled endpoints |
| `zap_active` | vulnerability detection | **active** (optional) | OWASP ZAP daemon (active scanner) over REST | finding coverage for active-scan alerts on the scanned endpoints |

User-facing labels come from the adapter's `display_name`, which is the **capability**
("Certificate transparency", "Deep subdomain enumeration", "Web service discovery").
Engine names never leave the backend: the API identifies an engine by an opaque
per-deployment token and labels everything else, and stage errors are rewritten as advice
(developer handbook ADR-022, chapter 4.11). Two consequences when you add an adapter:

- `display_name` is product copy. It is what a customer reads on the Pipeline, so it must
  distinguish this engine from the others on the same stage — otherwise two stages look like
  one stage listed twice.
- Raise `ConfigurationError("<capability> is not enabled in this deployment")` rather than
  letting an exception escape, and add a mapping to `backend/app/scans/messages.py` for any
  failure the tool reports in its own words.

## Adding a scanner

1. Create `workers/asm_sensors/adapters/<name>/__init__.py`:

```python
from pydantic import Field
from ...base import AdapterConfig, ExecutionContext, RawOutput, ScannerAdapter, StageType, iter_json_lines, read_output_file, write_targets_file
from ...execution import minimal_env, resolve_binary, run_process
from ...observations import NormalizedOutput, ObservedType, RelationCoverage, RelationType
from ...registry import register
from ...targets import Target, TargetKind
from .._common import ObservationSet, clean_hostname

class MyToolConfig(AdapterConfig):          # extra="forbid": only these options exist
    rate_limit: int = Field(default=100, ge=1, le=2000)

@register
class MyToolAdapter(ScannerAdapter):
    name = "mytool"
    display_name = "Something useful"
    stage_types = frozenset({StageType.HTTP_DISCOVERY})
    target_kinds = frozenset({TargetKind.HOSTNAME})
    active = True
    binaries = ("mytool",)
    config_model = MyToolConfig

    async def execute(self, targets, config, ctx):
        binary = resolve_binary("mytool", self.binaries)
        tfile = write_targets_file(ctx.workdir, targets)       # never put targets on the command line
        out = ctx.workdir / "out.jsonl"
        proc = await run_process([binary, "-l", str(tfile), "-json", "-o", str(out), "-rl", str(config.rate_limit)],
                                 timeout=ctx.timeout_seconds, cwd=str(ctx.workdir), env=minimal_env(home=str(ctx.workdir)))
        return RawOutput(process=proc, files={"out.jsonl": read_output_file(out, ctx.max_output_bytes)})

    async def parse_results(self, raw):
        return list(iter_json_lines(raw.primary))

    async def normalize(self, parsed, targets, config):
        obs = ObservationSet()
        for rec in parsed:
            host = clean_hostname(rec.get("host"))
            if host:
                obs.add(ObservedType.HOSTNAME, host, {"example": rec.get("x")})
        # Declare what you enumerated completely — or nothing.
        return NormalizedOutput(observations=obs.all(), coverage=[])
```

2. Add the module to `BUILTIN_MODULES` in `asm_sensors/registry.py` (or ship it as a separate
   package exposing the `asm_sensors.adapters` entry point).
3. Install the binary in `docker/scanner/Dockerfile`.
4. Add recorded output to `tests/sensors/fixtures/` and parser tests.
5. Add the tool and its license to `THIRD_PARTY_LICENSES.md`.
6. Use it in a scan profile (`{"stage": "http_discovery", "engine": "mytool", "config": {...}}`).

### Rules for adapters

- Never build shell strings; always `run_process([...])` with the allowlisted binary.
- Configuration is a strict pydantic model — **no** free-form "extra arguments".
- Treat tool output as untrusted: validate every value (`clean_hostname`, `clean_ip`, …).
- Only declare coverage for what the run enumerated *completely* (respect port sets, filters).
  When unsure, declare none: the platform then never infers disappearance from this sensor.
- `run()` automatically discards coverage from failed/partial runs. A run is partial when
  the process failed/timed out, when output was truncated (read tool output with
  `tool_output(...)` and pass its flag to `RawOutput(truncated=...)`), and whenever
  `RawOutput.errors` is non-empty — so API-based adapters **must** record every failed call,
  missed deadline, unfinished pagination or hit result limit there. Never swallow an error
  that means part of the target set was not examined.
- Shared, stateful services (like a ZAP daemon) must be used under
  `ctx.coordinator.lease(...)` and left clean for the next job.
- Credentials arrive decrypted in `ctx.credentials` only for providers listed in
  `credential_providers`; write them to files with `0600` inside `ctx.workdir` and delete them.
- HTTP requests take their headers from `identity.user_agent(ctx.settings)` and
  `identity.identity_header(ctx.settings)` — never a hardcoded user agent or product header.
- Set `historical=True` on the result if the data describes what a third party saw, not what
  this run saw; the platform then refuses to let it refresh, revive or close anything.
- Run the tool in **verbose mode** (its `-v`/`--verbose` flag, never `-silent`) and keep results
  in files: whatever the tool writes to stderr becomes the stage's output on the scan page
  (below). Adapters without a process (API clients, the web application scanner) narrate
  progress with `stagelog.note("…")`.

## Stage output (verbose mode)

Every stage runs its engine in verbose mode, and the scan page shows the output per stage
(**Pipeline → Show output**, updated every few seconds while the stage runs, with a
download). The output never names the engine behind a capability (ADR-022):

1. **In the scanner** (`asm_sensors/stagelog.py`), each stderr line is cleaned as it is read:
   colour codes, ASCII-art banners, version announcements and lines that are only a vendor's
   site are dropped; engine and project names become "engine"; install paths become
   `[path]`; content-set names and vendor links are replaced; `Authorization`/cookie/API-key
   values, `key=`/`token=`-style query values and every credential the job carried are
   redacted. Log levels (`[INF]`, `[WRN]`, `[ERR]`, …) become info/warning/error/debug.
2. **Bounded** whatever the engine prints: the first 2 000 lines and the last 2 000, with a
   count of the lines in between that were not kept. While a stage runs only the latest 200
   tail lines travel every 5 seconds; the full tail comes with the final chunk.
3. **Sent** on the pool's result queue as its own envelope kind (`kind: "log"`), signed with
   a key derived separately from the result key, so a log chunk can never be taken for a
   result. `asm-ingest` still registers exactly one task.
4. **On arrival** the platform accepts a chunk only from the job it dispatched for that stage,
   from that pool, while the stage runs or up to 15 minutes after it ended; it cleans every
   line again (the scanner is not trusted to have done it) and enforces the same bounds.

Output is stored per stage (`scan_stage_outputs`, tenant-isolated by RLS), deleted with the
scan, readable with `scans:read`, and each download is audited (`data.exported`).

## Tool notes

- **Amass v4** changed its output to graph lines (`name (FQDN) --> a_record --> ip (IPAddress)`);
  both that and the v3 JSON format are parsed. `-passive` is the default in v4 and is not passed.
- **httpx** name clash: the Python `httpx` package installs a CLI of the same name; the sensor
  image sets `ASM_BIN_HTTPX=/opt/asm/bin/httpx` so the ProjectDiscovery binary is used.
- **Naabu** runs connect scans (`-s c`) so the container needs no `NET_RAW` capability; port
  sets are explicit (`web`, `common`, `extended`, `full`, `custom`), never "top N".
- **Nuclei** runs with `-ni` (no interactsh), `-omit-raw`, `-duc`, severity/tag filters from the
  profile; info-level `tech` detections become technology observations.
- **SpiderFoot** endpoints used (`/startscan`, `/scanstatus`, `/scanexportjsonmulti`) match
  SpiderFoot 4.x — verify against the deployed version.
- **OWASP ZAP** (`zap_spider`, `zap_active`) is driven over its REST API (`/JSON/spider/*`,
  `/JSON/ajaxSpider/*`, `/JSON/pscan/*`, `/JSON/ascan/*`, `/JSON/context/*`, `/JSON/core/*`),
  matching ZAP 2.14+/2.15. The daemon URL and API key are deployment settings (`ASM_ZAP_URL`,
  `ASM_ZAP_API_KEY`), never scan-profile input, so a profile can never point ZAP at an
  arbitrary URL (no SSRF) and the key never enters the broker. Each target gets its own ZAP
  *context* (named after the job) whose anchored inclusion regex matches exactly the
  authorized `scheme://host[:port]`, sites are seeded without following redirects, and the
  scanners run `inScopeOnly` / `subtreeOnly` within that context, so ZAP never leaves the
  origin it was pointed at. A job holds a pool-wide lease on the daemon for its whole run and
  works in a fresh session (`core/action/newSession`) that is replaced again afterwards;
  contexts and Replacer rules are removed, unfinished scans are stopped, alerts are filtered
  to the target's origin, and deadlines or the `max_alerts` limit make the run partial. The active
  scanner is intrusive — mark `zap_active` stages `optional` so deployments without ZAP skip
  them cleanly (a missing `zap_url` makes the stage fail, and an optional failed stage is
  skipped). Verify API paths and default scan policies against the version you deploy.
  **Authenticated scanning:** a tester can paste a session cookie (or token) in the *Start a scan* dialog for one
  scan — it is encrypted on the scan row, bound to it by AAD, delivered in the sealed job envelope and erased when the
  scan ends — or store a `zap_auth` credential (a logged-in session cookie, or a
  bearer token) and both engines crawl/attack as that user — the secret is injected into every
  in-scope request via a ZAP Replacer rule scoped to the authorized origin (never leaks
  off-host) and cleaned up after each target. `auth_header_name` selects the header (`Cookie`
  by default, or `Authorization`). This is session/token auth; automatic form login is a
  future enhancement.
- **Shodan** (`shodan`) reports what Shodan's database last saw for each authorized IP: open ports, products and
  versions, TLS certificates, reverse DNS names, ASN/organization and the CVEs Shodan associates with those versions.
  It is the same data Nmap's `shodan-api` script shows, kept as inventory. The account is checked once
  (`/api-info`) before any lookup, so a rejected key fails the stage with one clear error instead of silently
  producing nothing, and lookups are rate limited and capped per scan (`max_lookups`). The key only ever travels as a
  query parameter, so the adapter never logs URLs. Because the data is historical, the result is flagged
  `historical`: ingestion adds what is new but never refreshes "last seen", revives an inactive asset or closes
  anything, and every port/service keeps Shodan's own observation date (`shodan_last_seen`). Records older than
  `max_age_days` (default 180) are ignored. Its CVEs are stored as **unverified** findings (tag `unverified`), which
  stay out of the main findings list, risk scores, reports and alerts until a scanner confirms them.
- **BBOT** 2.x output (`-om json` → `output.json`) — verify the CLI flags against the installed version.

Verification status: parsers are tested against recorded output in `tests/sensors/fixtures`.
The adapters have **not** yet been exercised against live tool binaries in this repository's
CI; run `docker compose run --rm asm-scanner versions` and a Passive Discovery scan against
a domain you own after the first build.
