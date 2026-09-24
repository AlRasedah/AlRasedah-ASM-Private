# Exteriq ASM

**Continuous External Attack Surface Management** for discovering, monitoring and
prioritizing internet-facing assets and exposures.

Exteriq ASM continuously answers:

- What internet-facing assets belong to this organization — and who owns them?
- What changed since the previous scan (new subdomains, IPs, ports, services, certificates, technologies, vulnerabilities)?
- Which assets are unknown — potential shadow IT?
- Which findings present the highest *practical* risk (not just CVSS)?
- How has the attack surface changed over time?

The platform owns the asset database, orchestration, scheduling, normalization,
historical state, change detection, risk scoring, workflows, reporting,
integrations and UI. Open-source reconnaissance tools (Amass, Subfinder, dnsx,
httpx, Naabu, Nuclei, optionally SpiderFoot and BBOT) are **replaceable
sensors** running in isolated worker containers with no database access.

---

## Contents

- [Quick start](#quick-start-docker-compose)
- [First steps](#first-steps)
- [Architecture at a glance](#architecture-at-a-glance)
- [Repository layout](#repository-layout)
- [Development](#development)
- [Testing](#testing)
- [Documentation](#documentation)
- [Status](#status)

## Quick start (Docker Compose)

Requirements: Docker Engine 24+ with Compose v2, 4 CPU / 8 GB RAM for a small deployment.
No Kubernetes and no cloud-provider services are required; the stack runs entirely
on your own infrastructure (e.g. in-Kingdom hosting, OCI Jeddah/Riyadh, Google Cloud Dammam,
or on-premises).

```bash
git clone <your-repository-url> exteriq-asm && cd exteriq-asm
python scripts/generate_env.py        # creates .env with strong random secrets (or: sh scripts/generate-env.sh)
docker compose up -d
```

The first start builds four images (platform, sensors, web UI, and pulls PostgreSQL /
Valkey / nginx). The sensor image compiles the scanner tools from upstream source, which
takes several minutes. When the stack is healthy:

- Web UI: <http://localhost:8080>
- API documentation (OpenAPI): <http://localhost:8080/api/docs>
- Sign in as `ASM_BOOTSTRAP_ADMIN_EMAIL` with the password printed by `generate_env.py`
  (also stored in `.env`). Change it after the first login and enable two-factor authentication.

```bash
docker compose ps                              # all services healthy?
docker compose logs -f asm-worker asm-scanner  # watch a scan
docker compose run --rm asm-api cli --help     # administrative CLI (in the platform image)
```

Serve over HTTPS before exposing the UI beyond localhost — see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (TLS proxy config, `ASM_COOKIE_SECURE=true`).

## First steps

1. **Organizations & scope** — create an organization and add its authorized scope:
   root domains, IP addresses and CIDR ranges you own or are authorized to test.
   Add exclusions for anything that must never be touched. Active scanning is only
   ever performed against in-scope targets that permit it; every decision is logged.
2. **Scan** — start a *Passive Discovery* scan (no traffic to your hosts beyond DNS), then a
   *Standard ASM* scan. The first scan of an organization is the **baseline**: it builds the
   inventory without alerting.
3. **Schedule** — add a daily *Standard ASM* schedule (and optionally a frequent
   *Exposure Monitoring* schedule). From now on every scan is compared with history and
   changes appear under **Changes**.
4. **Review** — classify discovered assets under **Shadow IT** (approved, expected, third
   party, unauthorized, decommissioned), assign owners and criticality, and triage
   **Findings** (investigate, remediate, accept risk with justification, false positive).
5. **Alert** — add notification channels (email, webhook, Wazuh, Slack, Teams) and alert
   policies under **Integrations**.
6. **Respond to announcements** — the **Threat Center** shows which assets an advisory (written automatically for every vulnerability CISA lists as exploited, or by you)
   may affect, what approved checks found and what remediation is open; the **Exposure map**
   shows how domains, addresses, services, web applications and findings relate; optional
   **website screenshots** show what each web endpoint looks like.
7. **Report** — generate executive, technical, inventory, vulnerability, change and risk-trend
   reports (HTML/PDF/CSV).

To explore the UI without scanning anything, load demo data (replayed recorded tool output):

```bash
docker compose run --rm -v "$PWD:/src:ro" -w /src asm-api python scripts/seed_demo.py
```

This creates a *Demo Holding* tenant with sign-in `admin@demo.local` / `Demo-Passw0rd!`
(override with `--email/--password`). Do not run it on a production instance.

## Architecture at a glance

```text
 Browser ──HTTPS──> reverse-proxy (nginx) ──> asm-web (static React SPA)
                                   └───────> asm-api (FastAPI, REST /api/v1)
                                                   │
          ┌────────────────────────────────────────┼──────────────────────────────┐
          │                 data network (internal)│                              │
     PostgreSQL 16  <── RLS tenant isolation ──  asm-worker (Celery "core")   asm-scheduler (beat)
     (assets, graph,                             orchestration, ingestion,   schedules, maintenance,
      history, events)                           change detection, risk,     intel refresh
          │                                      notifications, reports
        Valkey (broker) <──────────── sensors network (internal) ─────────────┐
                                                                               │
                                               asm-scanner (Celery "scanners.<pool>")
                                               Amass · Subfinder · crt.sh · dnsx · ASN lookup
                                               Naabu · httpx · Nuclei · (SpiderFoot · BBOT)
                                               ── no database credentials; egress to targets ──
```

Key design points (details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)):

- **Sensors are replaceable.** Each tool is wrapped by an adapter implementing
  `validate_configuration → execute → parse_results → normalize`, emitting a
  scanner-independent observation schema (assets, relationships, findings) plus
  **coverage** statements that make disappearance detection reliable.
- **History is first-class.** Assets are never deleted because they were missed once;
  `first_seen`/`last_seen`, observation history, relationship graph and an
  `asset_events` change log with previous/new state drive the timeline and alerts.
- **Multi-tenant from day one.** Every tenant-owned row carries `tenant_id`, enforced by
  PostgreSQL Row-Level Security (forced, non-superuser app role) in addition to
  application checks.
- **Safe by default.** Scope authorization before any active traffic, safe Nuclei template
  classes only, no free-form tool arguments, strict target validation, no shell execution,
  rate/concurrency limits, non-root read-only containers.

## Repository layout

```text
backend/            FastAPI platform (Python 3.12+)
  app/api/          REST routers (/api/v1/...), auth dependencies
  app/auth/         authentication, sessions, MFA, RBAC permissions
  app/assets/       normalization, cloud detection, ingestion engine, inventory queries
  app/changes/      change detection rules + security knowledge (risky ports, admin panels)
  app/findings/     finding lifecycle, platform detection rules
  app/risk/         risk engine and recomputation
  app/scans/        profiles, target builder, orchestrator, schedules
  app/scope/        scope checker (authorization) and scope management
  app/intel/        CISA KEV / FIRST EPSS / NVD enrichment
  app/integrations/ notification engine and channels (email, webhook, Wazuh, Slack, Teams)
  app/reporting/    HTML/PDF/CSV reports
  app/tenants/      tenants, plans/quotas, usage, settings, bootstrap
  app/models/       SQLAlchemy 2.x models
  app/workers/      Celery app, tasks, dispatch facade
  alembic/          database migrations (incl. RLS policies)
workers/            sensor framework (package `asm_sensors`)
  asm_sensors/adapters/{amass,subfinder,crtsh,dnsx,asnlookup,naabu,httpx,nuclei,spiderfoot,bbot,zap}
frontend/           React + TypeScript (Vite) web UI
docker/             Dockerfiles, nginx configs, PostgreSQL init
docs/               architecture, deployment, security, sensors, integrations
tests/              backend, sensor parser and integration tests
scripts/            env generation, dev database, demo data, dev server
```

## Development

```bash
# Python 3.12+ and a PostgreSQL 14+ you can reach
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e "./workers[worker]" -e "./backend[dev]"
python scripts/dev_db.py --admin-url postgresql://postgres:postgres@localhost:5432/postgres --database asm_dev
(cd backend && ASM_DATABASE_URL=postgresql+psycopg://asm:asm@localhost:5432/asm_dev alembic upgrade head)
python scripts/seed_demo.py                            # optional demo tenant (admin@demo.local / Demo-Passw0rd!)
python scripts/dev_api.py                              # API on http://127.0.0.1:8000 (inline sensors, no Redis needed)
cd frontend && npm install && npm run dev              # UI on http://localhost:5173 (proxies /api)
```

`ASM_SENSOR_MODE=inline` runs sensors inside the API/worker process — convenient for
development, never for production (the sensor containers are the security boundary).

## Testing

```bash
ASM_TEST_ADMIN_URL=postgresql://postgres:postgres@localhost:5432/postgres pytest   # backend + sensors
cd frontend && npm test && npm run typecheck                                      # UI smoke tests + types
```

The backend suite needs a PostgreSQL superuser connection to create an isolated
test database and a **non-superuser** role, so Row-Level Security is genuinely exercised.
No test touches the internet: scanner behaviour is covered with recorded tool output
(`tests/sensors/fixtures`). CI: [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Documentation

| Document | Contents |
|---|---|
| [docs/developer/](docs/developer/README.md) | **Developer handbook**: setup, codebase tour, internals, scan pipeline walk-through, data model, recipes, testing, design decisions, build log |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, data model, pipeline, tenancy, SaaS readiness |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Installation, TLS, scaling sensors, backups, upgrades, air-gapped/in-Kingdom notes |
| [docs/SECURITY.md](docs/SECURITY.md) | Threat model and controls |
| [docs/SENSORS.md](docs/SENSORS.md) | Sensor adapter contract, adding a scanner, tool-specific notes |
| [docs/CHANGE_DETECTION.md](docs/CHANGE_DETECTION.md) | Coverage model, inactivity rules, event catalogue |
| [docs/RISK_SCORING.md](docs/RISK_SCORING.md) | Risk model and tuning |
| [docs/integrations/wazuh.md](docs/integrations/wazuh.md) | Wazuh forwarding, decoders and rules |
| [docs/API.md](docs/API.md) | REST API overview, authentication, pagination |
| [docs/THREAT_CENTER.md](docs/THREAT_CENTER.md) | Automatic advisories (CISA KEV + NVD) and your own, matched against your inventory; approved checks, remediation |
| [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) | Website screenshots: isolation, limits, retention, measurements |
| [docs/EXPOSURE_MAP.md](docs/EXPOSURE_MAP.md) | External exposure map: what it shows, bounds, and why it is not attack-path analysis |
| [docs/MILESTONES.md](docs/MILESTONES.md) | Delivery status per milestone and roadmap |
| [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) | Integrated projects and licenses (with items flagged for legal review) |

## Status

Milestones 1–8 of the initial plan are implemented; see [docs/MILESTONES.md](docs/MILESTONES.md)
for exactly what is complete, what was verified and how, and what remains.

This product is intended **only for authorized security monitoring** of assets you own or
are explicitly permitted to assess.

This product uses the NVD API but is not endorsed or certified by the NVD. EPSS scores are
provided by FIRST.org.
