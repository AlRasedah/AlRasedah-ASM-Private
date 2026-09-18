# 1. Setting up a development environment

## Prerequisites

| Tool | Version | Used for |
|---|---|---|
| Python | 3.12+ (developed on 3.13) | backend, sensor framework, tests |
| Node.js | 20+ (developed on 24) | web UI |
| PostgreSQL | 14+ (developed on 18) | database; **required** for backend tests (RLS) |
| Docker + Compose v2 | optional for development | building/running the real stack and scanner tools |
| Redis/Valkey | optional for development | only needed to run Celery workers locally |

You do **not** need the scanner binaries (Amass, Nuclei, …) for development or tests: tests
replay recorded tool output, and `ASM_SENSOR_MODE=inline` runs the pipeline in-process.

## 1. Python environment

```bash
python -m venv .venv
. .venv/bin/activate                 # Windows PowerShell: .\.venv\Scripts\Activate.ps1
pip install -e "./workers[worker]" -e "./backend[dev]"
```

Two packages are installed in editable mode:

- `workers/` → package `asm_sensors` (sensor framework; depends only on pydantic, httpx, dnspython)
- `backend/` → package `app` (the platform; depends on `asm-sensors`)

## 2. PostgreSQL

Any PostgreSQL you control works. Options:

- **Docker**: `docker run -d --name asm-pg -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:16-alpine`
- **Native install** on Linux/macOS.
- **Windows without Docker** (how this project was developed): user-space PostgreSQL inside
  WSL, no root required:

  ```bash
  wsl -- bash scripts/dev-postgres-wsl.sh      # starts 127.0.0.1:55432, user postgres / postgres
  ```

  It downloads the distribution's PostgreSQL `.deb` packages with `apt-get download`,
  extracts them under `~/asm-pg`, fetches missing shared libraries (libnuma, liburing),
  initialises a cluster with `fsync=off` and starts it. WSL forwards localhost, so Windows
  tools connect to `127.0.0.1:55432`.

Create the development database and a **non-superuser** application role (superusers
bypass Row-Level Security, so the app must never connect as one):

```bash
python scripts/dev_db.py --admin-url postgresql://postgres:postgres@127.0.0.1:55432/postgres \
       --role asm --password asm --database asm_dev
cd backend && ASM_DATABASE_URL=postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev alembic upgrade head && cd ..
```

## 3. Demo data (optional but recommended)

```bash
ASM_DATABASE_URL=postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev python scripts/seed_demo.py
```

`seed_demo.py` bootstraps plans and built-in profiles, creates tenant *Demo Holding*, user
`admin@demo.local` / `Demo-Passw0rd!` (platform admin), organization *Example Corp* with
scope `example.com` (and exclusion `dev-api.example.com`), then runs **two real inline
scans** whose sensor execution is replaced by the recorded tool output in
`tests/sensors/fixtures` (see `tests/backend/sensors_fake.py`). The second scan adds ports
5900 and 8443 so the Changes view has non-baseline events. Nothing is scanned.

## 4. Run the API and UI

```bash
python scripts/dev_api.py                 # http://127.0.0.1:8000  (docs: /api/docs)
cd frontend && npm install && npm run dev # http://localhost:5173  (proxies /api to :8000)
```

`scripts/dev_api.py` sets development defaults (inline sensors, insecure cookies for plain
HTTP, `asm_dev` database, a dev secret key, temp storage directory). Every value can be
overridden with the matching `ASM_*` environment variable. Vite's port comes from `PORT`
when set (`frontend/vite.config.ts`); the API target from `ASM_API_URL`.

An editor launch configuration with `asm-api` and `asm-web` entries is kept alongside the
repository for tools that understand it (not part of the product).

Without Redis the rate limiter falls back to in-process windows (logged once per 30 s) and
`/health/ready` reports `redis: unavailable` — expected in development.

## 5. Running Celery locally (optional)

To exercise the asynchronous path instead of inline mode you need a broker:

```bash
docker run -d -p 6379:6379 valkey/valkey:8-alpine
export ASM_SENSOR_MODE=celery ASM_REDIS_URL=redis://localhost:6379/0
celery -A app.workers.celery_app worker -Q core --loglevel INFO          # from backend/
celery -A app.workers.celery_app beat --loglevel INFO                    # scheduler
ASM_CELERY_BROKER_URL=redis://localhost:6379/0 celery -A asm_sensors.worker worker -Q scanners.default
```

The sensor worker needs the real tool binaries on `PATH` (or `ASM_BIN_<TOOL>` overrides).
In practice it is easier to run sensors via `docker compose up asm-scanner`.

## 6. Full stack with Docker

```bash
python scripts/generate_env.py && docker compose up -d
```

See [../DEPLOYMENT.md](../DEPLOYMENT.md).

## 7. Everyday commands

| Task | Command |
|---|---|
| All backend + sensor tests | `pytest -q` (repo root; needs `ASM_TEST_ADMIN_URL`, default `postgresql://postgres:postgres@127.0.0.1:55432/postgres`) |
| One test | `pytest tests/backend/test_pipeline.py::test_standard_scan_end_to_end -q` |
| Lint | `cd backend && ruff check app ../workers/asm_sensors` (add `--fix` for safe autofixes) |
| New migration | `cd backend && alembic revision --autogenerate -m "describe change"` then **review and add RLS** (see chapter 5) |
| Apply migrations | `cd backend && alembic upgrade head` |
| UI type-check / tests / build | `cd frontend && npm run typecheck && npm test && npm run build` |
| Ship a UI change into the Docker stack | `docker compose up -d --build asm-web` (then hard-refresh; `down`/`up` alone reuses the old image) |
| Ship a report/backend change into the Docker stack | `docker compose up -d --build asm-api asm-worker` |
| Admin CLI | `python -m app.cli --help` (from `backend/`, with `ASM_DATABASE_URL` set) |

## Environment variables you will meet

All settings live in `backend/app/core/config.py` (`Settings`, prefix `ASM_`). The ones that
matter most in development:

| Variable | Dev value | Meaning |
|---|---|---|
| `ASM_ENV` | `development` / `test` | `production` refuses placeholder secrets; `test` makes Argon2 cheap |
| `ASM_DATABASE_URL` | `postgresql+psycopg://asm:asm@…/asm_dev` | must be a non-superuser role |
| `ASM_SECRET_KEY` | any 32+ chars | JWT signing, token hashing |
| `ASM_ENCRYPTION_KEYS` | unset → dev key derived from secret key | `k1:<base64url 32 bytes>[,k0:…]` |
| `ASM_SENSOR_MODE` | `inline` | run sensors in-process (never in production) |
| `ASM_ALLOW_NON_PUBLIC_SCOPE` | `true` in dev/tests | allows documentation/private IPs in scope entries |
| `ASM_COOKIE_SECURE` | `false` on plain HTTP | refresh cookie `Secure` flag |
