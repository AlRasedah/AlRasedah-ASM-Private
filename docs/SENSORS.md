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

User-facing labels come from the stage (e.g. "Web service fingerprinting"); engine names are
implementation details shown only in advanced profile views.

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
- `run()` automatically discards coverage from failed/partial runs.
- Credentials arrive decrypted in `ctx.credentials` only for providers listed in
  `credential_providers`; write them to files with `0600` inside `ctx.workdir` and delete them.

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
- **BBOT** 2.x output (`-om json` → `output.json`) — verify the CLI flags against the installed version.

Verification status: parsers are tested against recorded output in `tests/sensors/fixtures`.
The adapters have **not** yet been exercised against live tool binaries in this repository's
CI; run `docker compose run --rm asm-scanner versions` and a Passive Discovery scan against
a domain you own after the first build.
