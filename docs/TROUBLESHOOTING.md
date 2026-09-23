# Troubleshooting (Docker Compose deployment)

Practical fixes for the issues most commonly hit when deploying Exteriq ASM with
`docker compose`. For the happy-path install and TLS setup, see
[DEPLOYMENT.md](DEPLOYMENT.md).

## How configuration is applied (read this first)

Most "my change didn't take effect" problems come from this:

- **`.env` drives Docker Compose**, not the local dev server. `docker compose`
  reads `.env` to interpolate `${VAR}` in `docker-compose.yml` and to fill
  `env_file` for the platform containers.
- **A running container keeps the config it was created with.**
  `docker compose restart` does **not** re-read `.env` — it restarts the same
  container. You must **recreate** the service:
  ```bash
  docker compose up -d               # recreates services whose config changed
  docker compose up -d --force-recreate <service>   # force a specific one
  ```
- **Published ports** (`ASM_HTTP_PORT`, `ASM_HTTPS_PORT`) change the container's
  port bindings, so they need a recreate of `reverse-proxy`, not a restart.
- **Some values are baked in on first init of a volume** and are *not* re-read on
  later starts — notably the database passwords (see the DB-auth item below).
- **See exactly what Compose will use** (with your `.env` interpolated):
  ```bash
  docker compose config
  ```

> Note: the local dev server (`python scripts/dev_api.py`) is a different path —
> it uses its own built-in defaults plus real environment variables and does
> **not** honor most `.env` keys. Everything below is about the Docker stack.

## Quick diagnostics

```bash
docker compose ps                     # all services running/healthy? (asm-migrate should be Exited(0))
docker compose logs --tail=50 <service>   # e.g. asm-migrate, asm-api, reverse-proxy
docker compose config                 # effective, interpolated configuration
curl -s  http://localhost:${ASM_HTTP_PORT:-8080}/healthz    # proxy up (HTTP)
curl -sk https://localhost:${ASM_HTTPS_PORT:-8443}/healthz  # proxy up (HTTPS)
```

---

## Issues

### 1. I edited `.env` but nothing changed
You almost certainly ran `docker compose restart` (or nothing). Recreate instead:
```bash
docker compose up -d
```
For a port change: `docker compose up -d --force-recreate reverse-proxy`.
For `ASM_PUBLIC_URL` / cookie / app settings: `docker compose up -d --force-recreate asm-api`.
Confirm the value is what you expect with `docker compose config`.

### 2. `docker compose up` fails: "required variable X is missing a value"
A secret or required variable is unset. Generate/fill `.env`:
```bash
python scripts/generate_env.py        # fills every CHANGE_ME, collapses duplicate keys, warns on leftovers
```
Duplicate keys in `.env` are legal but confusing — the **last** one wins (both for
Compose and for `generate_env.py`). Keep one line per key.

### 3. `asm-migrate` exits 1: `password authentication failed for user "asm"`
The Postgres data volume was initialised with a different `ASM_DB_PASSWORD` than
`.env` has now. The app role's password is only set on **first** init of the
volume, so later `.env` edits don't change it.
- Fresh deploy (no data to keep):
  ```bash
  docker compose down -v && docker compose up -d
  ```
- Keep existing data — change the role password to match `.env`:
  ```bash
  docker compose exec postgres psql -U postgres -c "ALTER ROLE asm PASSWORD '<ASM_DB_PASSWORD from .env>';"
  ```
The `asm-migrate` log now prints this hint before the stack trace.

### 4. `address already in use` / port clash
Another process holds that host port. Find it, then either stop it or pick a free
port:
```bash
sudo ss -ltnp | grep -E ':8080|:8443'         # what is using the port
```
```bash
docker compose up -d                           # after setting free ports in .env
```
Only the **left** side of the mapping is yours to change (`ASM_HTTP_PORT`,
`ASM_HTTPS_PORT`); containers always listen on 8080/8443 internally.

### 5. HTTP works but HTTPS port refuses connections
The proxy is running the plain (HTTP-only) config — TLS isn't enabled. Enable it:
```bash
sh scripts/gen-tls-cert.sh <hostname>          # or drop a real cert at docker/proxy/certs/tls.crt|tls.key
```
Then in `.env`: `ASM_PROXY_CONF=./docker/proxy/nginx-tls.conf`, `ASM_COOKIE_SECURE=true`,
`ASM_PUBLIC_URL=https://<host>:<port>`, and recreate:
```bash
docker compose up -d --force-recreate reverse-proxy asm-api
docker compose logs --tail=20 reverse-proxy    # look for an [emerg] line
```

### 6. Proxy `[emerg] cannot load certificate key ... Permission denied`
The unprivileged nginx user (uid 101) can't read a root-owned `0600` key. Fix
ownership/permissions:
```bash
chown 101:101 docker/proxy/certs/tls.crt docker/proxy/certs/tls.key && chmod 640 docker/proxy/certs/tls.key
```
```bash
docker compose up -d --force-recreate reverse-proxy
```
(If you can't `chown`, `chmod 644 docker/proxy/certs/tls.key` as a fallback.)
`scripts/gen-tls-cert.sh` does this for you.

### 7. HTTP redirects to the wrong site (e.g. lands on another service on :443)
On a non-standard HTTPS port, the redirect must target that port. It defaults to
`ASM_HTTPS_PORT`; set `ASM_PUBLIC_HTTPS_PORT` only if an external load balancer
terminates TLS on a different public port than the one published here. Then
recreate `reverse-proxy`. (Browsing `https://<host>:<port>` directly always works.)

### 8. Can't log in / CSRF or cookie errors
- `ASM_PUBLIC_URL` must **exactly** match the address you use in the browser
  (scheme, host, and port), or CSRF/cookie checks fail.
- Over HTTPS set `ASM_COOKIE_SECURE=true`; over plain HTTP it must be `false`
  (Secure cookies are dropped on HTTP).
- Recreate `asm-api` after changing either: `docker compose up -d --force-recreate asm-api`.

### 9. What are my admin credentials?
The first admin is created by `bootstrap` from `.env`:
```bash
grep -E '^ASM_BOOTSTRAP_ADMIN_EMAIL|^ASM_BOOTSTRAP_ADMIN_PASSWORD' .env
```
`generate_env.py` also prints them when it generates the password. To create
another admin, pass the **exact** name of the tenant they should work in:
```bash
docker compose run --rm asm-api cli create-admin --email you@example.com --tenant "Your Org" --platform-admin
```
The name must match exactly. If it does not, the command refuses and lists the
tenants that exist — `--create-tenant` starts a new, empty one on purpose. (It
used to create one silently, which produced issue 15 below.)

### 10. The login page shows old branding / a port I didn't configure
That is almost always a **separate, older instance** running outside this stack
(e.g. a bare `uvicorn` left on the host), not the Compose deployment. Find and stop
it:
```bash
sudo ss -ltnp | grep :<port>                   # identify the process/PID
```
Then stop its service (`systemctl stop <unit>`) or the process, and confirm the
port is free. The current stack only serves on the ports you set in `.env`.

### 11. A scan stage is "skipped — no authorized targets"
Nothing in scope matched that stage. Add the scope, permit active scanning, and
(if required) verify domain ownership. Use the scan's **Authorization log** tab and
the **Scope checker** (Organizations & scope) to see why targets were rejected.

### 12. A scan runs but finds nothing / active stages fail
Active discovery needs the scanner tools, which live in the `asm-scanner` image.
Confirm the sensor container is up and healthy:
```bash
docker compose ps asm-scanner
docker compose logs --tail=50 asm-scanner
docker compose run --rm asm-scanner versions   # prints installed tool versions
```
(The local `dev_api.py` mode runs sensors inline **without** the tool binaries, so
real discovery only happens in the Docker stack.)

### 13. Web Application Scan (DAST) does nothing / stage skipped
The ZAP engine is optional. Start it and configure the key:
```bash
docker compose --profile dast up -d
```
Set `ASM_ZAP_URL=http://zap:8090` and a random `ASM_ZAP_API_KEY` in `.env` (the ZAP
service starts with that same key). Targets must be in scope with active scanning
permitted.

### 14. A stage failed and the message doesn't name a tool

By design: the interface names capabilities, not engines, and stage errors are rewritten as
advice (developer handbook ADR-022). The raw output is in the sensor log —
`docker compose logs asm-scanner` — keyed by the stage id that the message came from. The
mapping back, for operators:

| What the user sees | What actually happened | Do |
|---|---|---|
| "Detection content is not installed yet. It downloads when the scanner starts (about 1 GB)…" | Nuclei has no templates | Give the scanner internet access on start-up (the entrypoint runs `-update-templates` into `ASM_NUCLEI_TEMPLATES_DIR`), or mount a populated templates directory; then rescan |
| "This capability is not installed in the scanner deployed here." | the engine's binary is missing from the image | `docker compose run --rm asm-scanner versions`; rebuild the scanner image |
| "The web application scanner is not enabled in this deployment." | `ASM_ZAP_URL`/`ASM_ZAP_API_KEY` unset, or the ZAP container is down | issue 13 above |
| "Open-source intelligence enrichment is not enabled in this deployment." | `ASM_SPIDERFOOT_URL` unset or that container is down | `docker compose --profile enrichment up -d` |
| "No API key is stored for this data source…" / "…was rejected" | a tenant data-source credential is missing or invalid | Integrations → Data-source API keys → **Test** |
| "A data source did not answer, so its results are incomplete." | an upstream HTTP error (crt.sh is the usual one) | usually transient; check egress and rescan |
| "This stage ran out of time before it finished…" | the stage hit its budget | raise it in a custom profile, or narrow the scope |
| "<Capability> did not finish successfully." | no mapping for this failure | read `asm-scanner` logs, then add the case to `backend/app/scans/messages.py` |

Errors stored by scans that ran **before** this change keep their original raw text.

### 15. A user I added sees none of my data

Visibility is tenant-wide: there is no per-user or per-organization restriction,
so a member of your tenant sees every asset, finding and scan in it. Empty pages
mean the **session is in a different tenant**, and every page now says so
("<Tenant> has no data yet") instead of rendering an empty table. Two causes:

- **They were created in a tenant of their own.** `create-admin --tenant` used to
  create the tenant when the name did not match exactly, so `"Acme"` for
  *"Acme Corp"* silently made a second, empty tenant with that admin in it. The
  command now refuses unknown names; existing strays are still out there.
- **Their account already existed.** Adding an existing email to a tenant does not
  repoint the tenant they sign in to, by design. They land in their old one and
  pick yours from the tenant selector in the top bar (it appears once an account
  belongs to more than one). `create-admin` now prints a note when this applies.

What is actually where:
```bash
docker compose exec postgres psql -U postgres -d asm -c "SELECT t.name AS tenant, t.id, count(DISTINCT s.id) AS scans, string_agg(DISTINCT u.email, ', ') AS members FROM tenants t LEFT JOIN scans s ON s.tenant_id=t.id LEFT JOIN tenant_memberships m ON m.tenant_id=t.id LEFT JOIN users u ON u.id=m.user_id GROUP BY t.id, t.name ORDER BY t.name;"
```

Fix without SQL: as an admin of the tenant that holds the data, **Users → Add
user** with the same email. That adds the missing membership; they then pick the
right tenant from the selector. Delete the stray tenant from Platform → Tenants.

To move them outright, with the ids from the query above:
```bash
docker compose exec postgres psql -U postgres -d asm -c "UPDATE tenant_memberships SET tenant_id='<real>' WHERE user_id=(SELECT id FROM users WHERE email='them@example.com'); UPDATE users SET default_tenant_id='<real>' WHERE email='them@example.com';"
```

### 16. Certificate/KEV/EPSS intel not updating (air-gapped)
Point the feeds at mirrors (`ASM_INTEL_*_URL`) or disable auto-refresh
(`ASM_INTEL_REFRESH_ENABLED=false`) and import offline — see DEPLOYMENT.md §6.

---

## Catch-all resets

Re-read `.env` and recreate everything (keeps data):
```bash
docker compose down && docker compose up -d
```

Full wipe — deletes **all** data and volumes (use when DB/redis passwords changed
or you want a clean slate):
```bash
docker compose down -v && docker compose up -d
```

## Where to look

| Symptom | Log / view |
|---|---|
| Startup / migrations fail | `docker compose logs asm-migrate` |
| API 5xx, auth issues | `docker compose logs asm-api` |
| TLS / redirect / ports | `docker compose logs reverse-proxy` |
| Scans stuck or empty | `docker compose logs asm-worker` and `asm-scanner` |
| Scheduled scans not firing | `docker compose logs asm-scheduler` |
| Why a target was rejected | UI → Scan → **Authorization log** |
| Effective config | `docker compose config` |
