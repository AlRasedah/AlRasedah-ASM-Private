# Exteriq ASM — demo environment

This branch (`demo`) is set up for **customer demonstrations**. It adds an easy way to
stand up a demo on the cloud and an easy way to wipe the demo data — without touching any
real tenant.

Everything here is deployment tooling; the product itself is unchanged. Two admin commands
do the work:

| Command | What it does |
|---|---|
| `demo-seed` | Create (idempotently) a demo tenant, a platform-admin login, an organization and its authorized scope. No scanning. |
| `demo-reset` | Delete the demo tenant and **all** of its data (organizations, assets, findings, scans, events, scope, integrations, profiles, memberships) and any users that belonged only to it. Idempotent. |

Default demo login: **`admin@demo.local`** / **`Demo-Passw0rd!`** (override with `ASM_DEMO_EMAIL` / `ASM_DEMO_PASSWORD` / `ASM_DEMO_TENANT`).

---

## Run a demo on the cloud (Docker)

The demo overlay (`docker-compose.demo.yml`) seeds the demo automatically after the database
is migrated, so the stack comes up with a ready login.

```bash
# 1. Configure (once): copy .env.example to .env and generate secrets.
cp .env.example .env && python scripts/generate_env.py   # or: sh scripts/generate-env.sh

# 2. Bring up the stack + seed the demo.
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d
```

Open the app (the reverse proxy publishes it, `https://<host>:8443` by default) and sign in
with the demo login above.

### Populate it with data

`demo-seed` creates an empty, scoped organization. Populate it the way a real customer would:

1. In the app go to **Scans → New scan** and run **Standard ASM** (or **Web Application
   Scan (DAST)** for the ZAP-powered web testing) against the demo organization.
2. Because the full stack includes the scanner image, this produces **real** discovery and
   findings. The default demo scope uses IANA's documentation domain `example.com`; point it
   at a domain you own (Organizations & scope) for a richer, realistic demo.

> Tip: to demo the active web-application testing (DAST) engine, also start the ZAP profile:
> `docker compose --profile dast -f docker-compose.yml -f docker-compose.demo.yml up -d`
> and set `ASM_ZAP_URL` / `ASM_ZAP_API_KEY` (see `docs/DEPLOYMENT.md`).

### Wipe the demo data

```bash
# Delete just the demo tenant and all its data (keeps the deployment running):
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm asm-demo-reset

# …or tear the whole environment down, including volumes (removes EVERYTHING):
docker compose -f docker-compose.yml -f docker-compose.demo.yml down -v
```

To re-seed a fresh demo afterwards, run the seed one-shot again:

```bash
docker compose -f docker-compose.yml -f docker-compose.demo.yml run --rm asm-demo-seed
```

---

## Run a demo locally (no Docker)

For a laptop demo you can use the dev API plus the CLI:

```bash
# Seed the demo tenant/admin/org/scope into the dev database:
ASM_DATABASE_URL=postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev \
  python -m app.cli demo-seed

# Wipe it again:
ASM_DATABASE_URL=postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev \
  python -m app.cli demo-reset
```

For a local demo with **rich, pre-populated data** (assets, findings and changes generated
through the real pipeline from recorded scanner output — no scanning, no network),
`scripts/seed_demo.py` is the best option:

```bash
ASM_DATABASE_URL=postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev \
ASM_SENSOR_MODE=inline python scripts/seed_demo.py
```

(That script depends on the test fixtures and is intended for local labs; it is not part of
the deployed container image, which is why the cloud demo uses real scans instead.)

---

## Notes

- **Safety:** `demo-reset` only deletes the named tenant (default `Demo Holding`); it never
  touches other tenants. It is idempotent — safe to run when nothing is there.
- **Audit log:** the reset removes the demo tenant's audit entries too, and leaves the
  append-only audit protection intact for everything else.
- **Real data:** to show a customer their *own* attack surface, don't use `demo-seed` — just
  create their organization, add the scope they authorize, verify ownership, and scan.
