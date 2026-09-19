# 6. Sensor framework

The practical guide to adding a scanner is in [../SENSORS.md](../SENSORS.md). This chapter
explains the framework's internals and the reasoning behind each adapter.

## 6.1 Why a separate package

`workers/asm_sensors` has no dependency on the platform: no SQLAlchemy, no database, no
FastAPI. The sensor container installs only this package and the tool binaries, receives a
`SensorJob`, and returns a `SensorResult`. This gives three properties:

1. **Replaceability** — swapping Amass for another enumerator touches one adapter.
2. **Isolation** — a compromised or misbehaving tool cannot reach tenant data.
3. **Testability** — parsers are pure functions over recorded output.

The platform depends on `asm_sensors` only for the schema (observations, targets, jobs,
enums, port helpers) and, in inline mode, for `runner.execute_job`.

## 6.2 The adapter lifecycle (`base.ScannerAdapter.run`)

```python
targets = self.check_targets(targets)                  # kinds accepted by this adapter
config = self.apply_limits(self.parse_config(raw), ctx) # strict model + global rate cap
await self.validate_configuration(config, ctx)          # binaries/settings present
raw = await self.execute(targets, config, ctx)          # the only step that runs the tool
parsed = await self.parse_results(raw)                  # tolerant: skip bad lines
normalized = await self.normalize(parsed, targets, config)
if process failed or timed out: status = partial (failed if nothing parsed); coverage = []
```

`apply_limits` clamps any config field named `rate_limit`, `rate`, `threads` or
`concurrency` to `ctx.max_rate` — name new rate options accordingly and the cap applies
automatically.

`is_active(config)` tells the platform whether this configuration contacts targets. Adapters
with a passive/active switch override it (Amass `mode`, SpiderFoot `use_case`, BBOT
`passive_only`).

## 6.3 Execution safety (`execution.run_process`)

- `asyncio.create_subprocess_exec` (no shell), every argument a `str` without NUL.
- `resolve_binary(name, allowed)` — the name must be in the adapter's `binaries` tuple; the
  path comes from `PATH` or `ASM_BIN_<NAME>`.
- `minimal_env(home=workdir)` — only PATH/HOME/locale/temp variables; tools write their
  config into the per-job temp directory.
- Output capped (`ASM_SCANNER_MAX_OUTPUT_MB`), stderr capped at 1 MiB, streams drained even
  past the cap so the child never blocks.
- Timeout → kill the whole process group (`start_new_session=True` on POSIX).
- Targets are written to a file (`write_targets_file`) rather than passed as arguments —
  this removes argument injection as a class of bug (a hostname like `-oG x` can never
  become a flag), in addition to the validators refusing leading dashes.

## 6.4 Observations and coverage — the contract

Assets (`AssetObservation`) carry `attributes` that are merged into `assets.metadata`.
Keep attribute names stable; the change detector and UI read specific keys:

| Asset | Attributes read by the platform |
|---|---|
| hostname | `dns` (dict of record type → sorted list), `resolves`, `discovery_sources` |
| ip_address | `asn`, `as_name`, `country`, `cdn`, `cdn_name` |
| port | `port`, `protocol`, `ip`, `state` |
| service | `name`, `product`, `version`, `banner`, `tls`, `detection` |
| http_endpoint | `url`, `scheme`, `host`, `port`, `ip`, `status_code`, `title`, `webserver`, `technologies`, `tls_version`, `tls_cipher`, `cdn`, `favicon_hash`, `location`, `final_url` |
| certificate | `subject_cn`, `sans`, `issuer_cn`, `issuer_org`, `not_before`, `not_after`, `self_signed`, `wildcard`, `serial` |
| technology | `name` (display name) |

Coverage semantics are described in chapter 4.6 step 8. The rule of thumb: **declare
coverage only for what the tool enumerated exhaustively for the inputs you gave it, under
the constraints you applied.** Passive discovery tools declare none.

## 6.5 Adapter notes (why each is written the way it is)

- **amass** — Amass v4 removed JSON output and prints graph lines. The parser accepts
  graph lines, v3 JSON lines and bare names, strips ANSI colours, ignores `in-addr.arpa`
  pseudo-names, and derives `ip → asn` from `netblock contains ip` + `asn announces netblock`.
  Each run uses its own `-dir` so no graph database is shared between tenants.
- **subfinder** — provider keys are written to a `0600` provider-config YAML in the job
  directory and deleted after the run; `-cs` records which source found each name.
- **crtsh** — pure Python HTTP; wildcard names are reduced to their base and flagged;
  results outside the queried roots are discarded; retries with back-off (crt.sh is flaky).
- **dnsx** — the liveness sensor. It always requests A records; hosts missing from JSON
  output (NXDOMAIN) are what liveness coverage turns into "no longer resolves".
- **asnlookup** — Team Cymru DNS TXT (`<reversed-ip>.origin.asn.cymru.com`, then
  `AS<n>.asn.cymru.com` for the name). Only IPs that answered are covered, so a DNS hiccup
  never produces "moved to another network".
- **naabu** — connect scans (no `NET_RAW`); explicit port sets; both historical JSON shapes
  (`port` as int or object) parsed; CIDR targets reported via `parent_cidrs`; `-ec` (skip
  full scans of CDN IPs) mirrored in coverage via `cdn_port_spec`.
- **httpx** — targets with explicit ports and bare hosts are run as two invocations (only
  the latter gets `-p`); `-fhr` follows redirects **only on the same host** (never off-scope);
  per-host probed ports become the coverage `port_spec`; the ProjectDiscovery binary is
  selected via `ASM_BIN_HTTPX` because the Python `httpx` package installs a CLI of the same
  name.
- **nuclei** — safe defaults enforced in the config model (`dos` can never be removed from
  exclusions); `-ni` (no out-of-band callbacks), `-omit-raw`, `-duc`; info `tech` results
  become technology observations; findings map to the most specific asset (endpoint →
  host:port on a known IP → hostname); finding coverage mirrors the severities/tags used.
- **spiderfoot** — driven over its web API from a separate container; the URL is deployment
  configuration (not user input, avoiding SSRF); only the `passive` use case is non-active.
- **bbot** — GPL-3.0, optional and executed only as a program; output read from the scan
  directory's `output.json`.
- **zap_spider / zap_active** — OWASP ZAP's DAST capabilities (the ZAP proxy's spider, AJAX
  spider, passive scanner and active scanner) exposed as two adapters that share one module
  (`adapters/zap/__init__.py`): the client, the alert→finding mapper and both classes live
  together so there is a single ZAP API surface. Like SpiderFoot, ZAP runs in its own
  container (`--profile dast`) and is a deployment setting (`zap_url` + `zap_api_key`), never
  user input — the key travels in the `X-ZAP-API-Key` header, not the URL. Both adapters are
  `active=True`. `zap_spider` implements the new `web_crawl` stage: it seeds a per-target ZAP
  *context* whose inclusion regex matches only the authorized origin, runs the spider (and,
  optionally, the AJAX spider), turns every crawled URL into an `http_endpoint` observation
  (so the crawl grows the surface the later stages test) and drains the passive scanner into
  findings. `zap_active` runs the active scanner over the known endpoints as a
  `vulnerability_detection` engine alongside Nuclei. Findings carry a stable `zap:<alertRef>`
  rule id; ZAP's `High` risk is the ceiling (it never becomes `critical`). Both emit
  `FindingCoverage` over the scanned endpoints so a fixed issue auto-resolves, and both are
  scope-safe: the scanners run `inScopeOnly`/`subtreeOnly` and never leave the host.
  **Authenticated scanning** uses the `zap_auth` credential provider (`credential_providers`),
  so the tenant's session secret is sealed and delivered through the normal credential channel
  (`ctx.credentials`, `auth_secret()`). When present, each target adds a ZAP Replacer rule
  (`replacer/action/addRule`, `matchType=REQ_HEADER`) that injects the header
  (`auth_header_name`, default `Cookie`) into every request whose URL matches the origin regex,
  then removes it in a `finally`. The `url`-scoping keeps the secret on the authorized origin
  only; CRLF in the value is rejected to prevent header injection.

## 6.6 Credentials flow

```text
tenant saves key ─► secrets (AES-256-GCM, AAD tenant+name)
prepare_next_stage ─► scanner_credentials(tenant, adapter.credential_providers)  (decrypt)
                   ─► seal_credentials(creds, job_id, transport_key)  (AES-GCM, AAD job_id)
broker ─► sensor ─► unseal_credentials ─► ctx.credentials ─► 0600 file in temp dir ─► deleted
```
