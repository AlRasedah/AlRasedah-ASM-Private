# Third-party components and licenses

Exteriq ASM is an independent platform. It does **not** fork or embed the
source code of SpiderFoot, reNgine, BBOT or any other attack-surface product.
Reconnaissance and vulnerability tools are integrated as *sensors*: separate
programs (or network services) executed in dedicated sensor containers and
driven through the adapter interface in `workers/asm_sensors`. The platform
consumes only the normalized observation schema, never tool source code.

> **Legal review required.** Architectural separation (separate processes,
> containers, or network APIs) is a common way to respect copyleft boundaries,
> but it does **not automatically resolve** licensing obligations. Distribution
> of container images that *contain* third-party binaries is itself
> distribution of those binaries and carries the corresponding obligations
> (license texts, notices, and — for copyleft components — source offers).
> Items marked ⚠ below need specific review before commercial distribution or
> SaaS operation.

## Sensors (executed as separate programs/services)

| Component | Role | License | Integration | Notes |
|---|---|---|---|---|
| [OWASP Amass](https://github.com/owasp-amass/amass) | Subdomain enumeration / network mapping | Apache-2.0 | Binary built from upstream source in the `asm-scanner` image; invoked via subprocess | Keep NOTICE file when redistributing the image |
| [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery | MIT | Binary; subprocess | |
| [ProjectDiscovery dnsx](https://github.com/projectdiscovery/dnsx) | DNS resolution | MIT | Binary; subprocess | |
| [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) | HTTP probing & fingerprinting | MIT | Binary; subprocess | Not to be confused with the Python `httpx` library (BSD-3) |
| [ProjectDiscovery Naabu](https://github.com/projectdiscovery/naabu) | TCP port discovery | MIT | Binary; subprocess | Dynamically links **libpcap** (BSD-3) |
| [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability / exposure detection | MIT | Binary; subprocess | |
| [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) | Detection content | MIT | Downloaded at runtime to a volume | ⚠ Individual templates reference third-party advisories; review attribution requirements |
| [SpiderFoot](https://github.com/smicallef/spiderfoot) | Optional OSINT enrichment | MIT | Separate container (`--profile osint`), driven over its HTTP API | Many SpiderFoot modules call third-party services with their own terms |
| [BBOT](https://github.com/blacklanternsecurity/bbot) | Optional recursive OSINT | ⚠ **GPL-3.0** | Not installed by default. Optional install (`INSTALL_BBOT=true`) into the sensor image; executed only as a separate program | Distributing an image containing BBOT distributes GPL-3.0 software: provide license text and corresponding source. The platform never imports BBOT code |

**Not used:** Nmap is intentionally *not* integrated: the Nmap Public Source
License (NPSL) restricts redistribution in commercial products. Service
identification uses httpx banners and port heuristics instead.

## Data sources and services

| Source | Used for | Terms | Notes |
|---|---|---|---|
| crt.sh (Sectigo) | Certificate transparency search | Free public service, no formal API SLA | ⚠ Review acceptable-use for commercial/SaaS volume; URL is configurable (`ASM_CRTSH_URL`) |
| Team Cymru IP-to-ASN DNS service | IP → ASN enrichment | Free service subject to Team Cymru terms | ⚠ Review terms for commercial use; can be replaced with an offline IP-to-ASN dataset |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | KEV status | U.S. Government work | Cached locally; mirror URL configurable |
| [FIRST EPSS](https://www.first.org/epss/) | Exploit prediction scores | Free; FIRST requests attribution | ⚠ Include attribution ("EPSS scores provided by FIRST.org") in reports/UI for commercial use |
| [NVD API](https://nvd.nist.gov/developers) | CVSS where sensors provide none | Public | Required notice: *"This product uses the NVD API but is not endorsed or certified by the NVD."* |
| Subfinder passive sources (SecurityTrails, Shodan, VirusTotal, Censys, …) | Passive DNS | Each provider's terms | Tenants supply their own API keys and are responsible for complying with provider terms |

## Platform runtime dependencies (Python)

| Package | License |
|---|---|
| FastAPI | MIT |
| Starlette | BSD-3-Clause |
| Pydantic, pydantic-settings, pydantic-core | MIT |
| Uvicorn | BSD-3-Clause |
| Gunicorn | MIT |
| SQLAlchemy | MIT |
| Alembic | MIT |
| psycopg 3 (`psycopg[binary]`) | ⚠ **LGPL-3.0** — used unmodified as a dynamically imported library; binary wheels bundle libpq (PostgreSQL License) |
| Celery, Kombu, Billiard | BSD-3-Clause |
| redis-py | MIT |
| argon2-cffi | MIT |
| PyJWT | MIT |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| httpx / httpcore | BSD-3-Clause |
| dnspython | ISC |
| tldextract | BSD-3-Clause (bundles a snapshot of the Mozilla Public Suffix List, MPL-2.0) |
| croniter | MIT |
| Jinja2, MarkupSafe | BSD-3-Clause |
| python-multipart | Apache-2.0 |
| pyotp | MIT |
| email-validator | The Unlicense |
| WeasyPrint (PDF reports) | BSD-3-Clause (uses Pango/HarfBuzz system libraries, LGPL/MIT) |
| boto3 / botocore (optional S3) | Apache-2.0 |

## Web UI dependencies (JavaScript)

| Package | License |
|---|---|
| React, React DOM | MIT |
| React Router | MIT |
| TanStack Query | MIT |
| Recharts (and D3 sub-modules) | MIT / ISC |
| lucide-react | ISC |
| clsx | MIT |
| IBM Plex Sans Arabic (font files in `frontend/src/fonts`) | SIL OFL 1.1 |
| Inter (font file in `frontend/src/fonts`) | SIL OFL 1.1 |
| Vite, @vitejs/plugin-react, TypeScript (build only) | MIT / Apache-2.0 |
| Vitest, Testing Library, jsdom (test only) | MIT |

## Container images

| Image | License | Notes |
|---|---|---|
| PostgreSQL 16 | PostgreSQL License | |
| Valkey 8 | BSD-3-Clause | Chosen instead of Redis ≥ 7.4, which is dual-licensed RSALv2/SSPLv1 (⚠ incompatible with offering the platform as a service without a commercial license) |
| nginx (nginxinc/nginx-unprivileged) | BSD-2-Clause | |
| python:3.12-slim / -alpine | PSF + distribution package licenses | |
| node:22-alpine (build stage only) | MIT + distribution package licenses | Not shipped in the runtime web image |
| golang (build stage only) | BSD-3-Clause | Not shipped |
| MinIO (optional `--profile s3`) | ⚠ **AGPL-3.0** | Development convenience only; use the hosting provider's S3-compatible storage in production |
| Mailpit (optional `--profile dev`) | MIT | Development only |
| Fonts: DejaVu, Noto (in platform image) | Bitstream Vera/DejaVu license, SIL OFL-1.1 | |

## Maintenance

Update this file whenever a sensor, data source or dependency is added. Pin
tool versions via the `asm-scanner` build arguments and record them in release
notes so the exact third-party versions in each release are known.
