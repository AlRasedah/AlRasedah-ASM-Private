# Deployment guide

## 1. Sizing

| Deployment | Assets | CPU / RAM | Sensor replicas |
|---|---|---|---|
| Small (single organization) | < 5 000 | 4 vCPU / 8 GB | 1 (concurrency 2) |
| Medium (MSSP, several orgs) | < 50 000 | 8 vCPU / 16 GB | 2–4 |
| Large | > 50 000 | Split sensors onto separate hosts | per pool |

PostgreSQL storage grows mainly with `asset_observations` (one row per asset sighting);
`ASM_OBSERVATION_RETENTION_DAYS` (default 365) bounds it.

## 2. Install

```bash
python scripts/generate_env.py      # or: sh scripts/generate-env.sh  (never commit .env)
$EDITOR .env                        # ASM_PUBLIC_URL, SMTP, admin email, ports
docker compose up -d
docker compose ps
```

`asm-migrate` runs database migrations and the idempotent bootstrap (plans, built-in scan
profiles, first administrator) on every start before the API and workers start.

## 3. TLS

1. Provide a certificate at `docker/proxy/certs/tls.crt` (chain) and `tls.key`.
   - Real cert: copy your CA/Let's Encrypt `fullchain.pem` → `tls.crt` and `privkey.pem` → `tls.key`.
   - Testing: `sh scripts/gen-tls-cert.sh <hostname>` generates a self-signed pair **with the
     right permissions** (see below).
2. In `.env`: `ASM_PROXY_CONF=./docker/proxy/nginx-tls.conf`, `ASM_COOKIE_SECURE=true`,
   `ASM_PUBLIC_URL=https://asm.example.com:<port>`. Choose published ports with
   `ASM_HTTPS_PORT` / `ASM_HTTP_PORT` (any free ports — 443/80 if available, else e.g. 9443/9080).
3. `docker compose up -d --force-recreate reverse-proxy asm-api`, then check
   `docker compose logs --tail=20 reverse-proxy` for a clean start and
   `curl -sk https://localhost:<port>/healthz`.

**Certificate file permissions.** The proxy runs as the unprivileged nginx user (uid 101), so
the private key must be readable by it — a root-owned `0600 tls.key` fails with
`cannot load certificate key ... Permission denied`. `gen-tls-cert.sh` handles this; for a
cert you supplied yourself run `chown 101:101 docker/proxy/certs/tls.*` (or `chmod 644 tls.key`
if you cannot chown).

**Ports and the HTTP redirect.** Only the host side of the port mapping changes; containers
always listen on 8080/8443. The TLS config's HTTP listener redirects to HTTPS on the standard
port (443). If you publish HTTPS on a non-standard host port (`ASM_HTTPS_PORT` != 443), browse
`https://<host>:<port>` directly — the plain-HTTP port is only a convenience redirect and is not
needed once you use HTTPS (cookies are `Secure`, so HTTP can't be used to sign in anyway).

Behind an external load balancer that terminates TLS, keep the default proxy config, set
`ASM_COOKIE_SECURE=true` and make sure the balancer sets `X-Forwarded-Proto: https`.

## 3a. Troubleshooting first deploy

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for the full guide (config precedence,
`.env` changes not applying, HTTPS/cert/port issues, scans finding nothing, resets).
The most common first-deploy failures:

- **`asm-migrate` exits 1 with `password authentication failed for user "asm"`** — the Postgres
  volume was initialised with a different `ASM_DB_PASSWORD` than `.env` has now (the role
  password is only set on first init). Fresh deploy: `docker compose down -v && docker compose up -d`.
  Keep data: `docker compose exec postgres psql -U postgres -c "ALTER ROLE asm PASSWORD '<value>';"`.
- **`docker compose up` fails on a missing variable** — run `python scripts/generate_env.py`
  (it fills every `CHANGE_ME`, collapses duplicate keys, and warns about anything still unset).
- **`address already in use`** — another service holds that host port; pick a free one with
  `ASM_HTTP_PORT` / `ASM_HTTPS_PORT` and re-run `docker compose up -d`.
- **HTTPS port refuses connections** — the proxy is still on the plain config; ensure
  `ASM_PROXY_CONF=./docker/proxy/nginx-tls.conf` is set (uncommented) and the cert is readable
  (see above), then `docker compose up -d --force-recreate reverse-proxy`.

## 4. Email

Configure the mail server in the web interface: **Settings → Email delivery** (platform
administrators), which also sends a test message. The settings are stored encrypted in the
database, take effect immediately (no restart) and override the environment.

`ASM_SMTP_HOST`, `ASM_SMTP_PORT`, credentials and `ASM_SMTP_FROM` remain as a bootstrap
default — useful when you want mail working before anyone signs in. Without either,
password resets and invitations fall back to one-time links shown to administrators, and
email deliveries fail visibly in the delivery log.

Users switch on alerts to their own login address under **Your account → Email alerts**
(on by default for high and critical changes); no mail-server access is needed for that.

## 5. Sensors

- **Pools**: `tenants.worker_pool` (default `default`) routes a tenant's sensor jobs to queue
  `scanners.<pool>`; results come back on `results.<pool>`. A pool is also a trust boundary
  (its own broker user and key — see ARCHITECTURE.md §2), so tenants that must not share
  scanners get their own pool — and with `ASM_SCANNER_ISOLATION=per_tenant` (the default)
  the platform **refuses to dispatch** a scan whose pool another tenant also uses, rather
  than trusting that an operator read this section. `cli scanner-pool <pool>` prints the
  whole block below ready to paste. To add pool `bank-a` by hand:
  1. Copy the redis service's `--user scanner-default …` block in `docker-compose.yml`,
     replacing every `default` with `bank-a` (queue, bookkeeping and binding keys,
     `asm.pool.bank-a.*`, `*.asm-bank-a.pidbox`, `&/0.asm-bank-a.pidbox`) and giving it its
     own password variable.
  2. Add a scanner service like `asm-scanner` with `ASM_SENSOR_POOL: bank-a`, the new broker
     user in `ASM_CELERY_BROKER_URL`, and `ASM_SCANNER_TRANSPORT_KEY` set to the output of
     `docker compose run --rm asm-api cli scanner-pool-key bank-a`. Never give sensor
     containers the platform's `ASM_SCANNER_TRANSPORT_KEY` or `ASM_REDIS_PASSWORD`.
  3. Add the pool to `ASM_WORKER_POOLS` (e.g. `default,bank-a`) and restart `asm-ingest`.
  4. If the pool runs DAST, give it its own ZAP daemon (`ASM_ZAP_URL`).
- **Egress firewall (required for untrusted scope)**: the platform refuses to actively scan
  non-public addresses, and sensors re-check every resolved destination just before
  connecting, but a hostname can change its DNS answer between that check and the tool's own
  lookup. Enforce the rule at the network layer too: drop traffic from the `egress` network
  of scanner/ZAP containers to loopback, RFC 1918, link-local (incl. `169.254.169.254`
  metadata), CGNAT and your own infrastructure — e.g. rules in the host's `DOCKER-USER`
  iptables chain, or a cloud security group on a dedicated scanning host.
  `ASM_ALLOW_NON_PUBLIC_SCOPE` / `ASM_SCANNER_ALLOW_NON_PUBLIC` are for labs only.
- **Broker redelivery**: `ASM_BROKER_VISIBILITY_TIMEOUT` (default 6 h) must exceed
  `ASM_STAGE_TIMEOUT_SECONDS` + 900 s and be the same for every service (the platform refuses
  to start otherwise). Sensor workers also ignore a redelivered job they already claimed.
- **Placement**: sensors only need the broker and internet egress. They can run on separate
  hosts/regions (e.g. a dedicated scanning egress IP that customers allow-list) with
  `ASM_CELERY_BROKER_URL` pointing at the broker over a private network or TLS tunnel.
- **Rates**: `ASM_SCANNER_MAX_RATE` caps any rate/threads option; per-stage rates come from
  scan profiles. `ASM_SENSOR_CONCURRENCY` limits simultaneous jobs per sensor container.
  `ASM_MAX_CONCURRENT_SCANS_GLOBAL` and each plan's `max_concurrent_scans` limit scans.
- **Tool versions**: pinned via build args in `docker/scanner/Dockerfile`
  (`docker compose build --build-arg NUCLEI_VERSION=vX.Y.Z asm-scanner`).
  Check with `docker compose run --rm asm-scanner versions`.
- **Detection templates** live in the `nuclei-templates` volume and update on sensor start
  (`ASM_NUCLEI_AUTO_UPDATE`). Offline: populate the volume from a mirror and set
  `ASM_NUCLEI_AUTO_UPDATE=false`.
- **Optional OSINT**: `docker compose --profile osint up -d` and set
  `ASM_SPIDERFOOT_URL=http://spiderfoot:5001`. BBOT: build the sensor image with
  `ASM_INSTALL_BBOT=true` (GPL-3.0 — see THIRD_PARTY_LICENSES.md).
- **Optional DAST (OWASP ZAP)**: `docker compose --profile dast up -d`, then set
  `ASM_ZAP_URL=http://zap:8090` and `ASM_ZAP_API_KEY=<random>` (the same key the `zap`
  service is started with). This enables the `zap_spider` (web crawling + passive scanning)
  and `zap_active` (active vulnerability scanning) engines and the built-in **Web Application
  Scan (DAST)** profile. Active scanning is intrusive: it only runs against scope with
  active-scanning authorization, and ZAP is confined per target to exactly the authorized
  origin (anchored regex, no seeding redirects). One job uses a daemon at a time (a
  pool-wide lease) in a fresh session that is wiped afterwards, so parallel DAST stages queue
  for the daemon; deploy one daemon per pool for tenant isolation and throughput.
  For **authenticated scanning**, store a `zap_auth` credential (Integrations → Data-source
  API keys) — a logged-in session cookie (default header `Cookie`, e.g.
  `PHPSESSID=…; security=low`) or a bearer token (set the stage's `auth_header_name` to
  `Authorization`). ZAP then crawls and attacks as that user; the secret is injected only on
  the authorized origin.
- **Egress identification**: scans send **no identifying header by default**, and the
  platform's own API calls use a neutral user agent, so traffic does not advertise the
  product or the engines behind it. Set `ASM_SCANNER_IDENTITY` when a customer's SOC should
  recognise authorized scanning — a value (`acme-pentest` → `X-Scanner: acme-pentest`) or a
  complete header line (`X-Audit: ticket-4711`). `ASM_SCANNER_USER_AGENT` overrides the user
  agent. Profiles can still switch the header off per stage (`identify_scanner`).

## 5b. Website screenshots (optional)

Screenshots run in each tenant's **own scanner** (the pool's scanner service) with a pinned
Chromium. Nothing is offered to tenants until a platform administrator enables it in the UI,
and that should happen only after the self-test below passes. Product behavior, limits and
measurements: [SCREENSHOTS.md](SCREENSHOTS.md).

1. **Host prerequisite — unprivileged user namespaces.** Chromium's sandbox needs them.
   Check the current values (a key your kernel does not have is reported as unknown — that
   one does not apply):
   ```bash
   sysctl kernel.apparmor_restrict_unprivileged_userns kernel.unprivileged_userns_clone
   ```
   Debian-family kernels need `kernel.unprivileged_userns_clone=1`; Ubuntu 23.10+ also needs
   `kernel.apparmor_restrict_unprivileged_userns=0` (or an AppArmor profile allowing `userns`
   for `/usr/lib/chromium/chromium`). Set them persistently, so they survive a reboot:
   ```bash
   printf 'kernel.apparmor_restrict_unprivileged_userns=0\nkernel.unprivileged_userns_clone=1\n' \
     > /etc/sysctl.d/99-asm-browser.conf && sysctl --system
   ```
   This relaxes a host-wide hardening default; it is what lets the browser keep its own
   sandbox, which the platform insists on.
2. **Seccomp profile.** Docker's default profile refuses the sandbox's namespace syscalls to a
   container without `CAP_SYS_ADMIN` (the scanner has no capabilities at all). Derive a
   profile from *your engine's* default that adds exactly `clone`, `unshare`, `setns` and
   `chroot`. Docker 29 renamed its release tags (`docker-v29.x.y`) and moved the file, so this
   picks the right source for the installed engine:
   ```bash
   V=$(docker version --format '{{.Server.Version}}')
   if [ "${V%%.*}" -ge 29 ]; then
     U="https://raw.githubusercontent.com/moby/moby/docker-v$V/vendor/github.com/moby/profiles/seccomp/default.json"
   else
     U="https://raw.githubusercontent.com/moby/moby/v$V/profiles/seccomp/default.json"
   fi
   curl -fsSLo /tmp/default.json "$U"
   python3 scripts/make_browser_seccomp.py /tmp/default.json > docker/scanner/seccomp-browser.json
   ```
   A 404 means the version string did not match a release tag (e.g. a distribution-patched
   engine); use the nearest upstream release of the same major version.
   Do **not** use `seccomp=unconfined`, and never add `--no-sandbox` anywhere: the adapter
   refuses to run the browser without its sandbox.
3. **Pin and build.** Choose the exact `chromium` package version for the scanner's Alpine
   base (`docker run --rm python:3.12-alpine sh -c 'apk update >/dev/null && apk policy chromium'`)
   and record it in `.env`, so every later build uses the same one (the build fails without
   it):
   ```bash
   echo 'ASM_CHROMIUM_VERSION=<exact version>' >> .env
   docker compose -f docker-compose.yml -f docker-compose.screenshots.yml build asm-scanner
   docker compose -f docker-compose.yml -f docker-compose.screenshots.yml up -d asm-scanner
   ```
   Alpine's repository keeps only the newest build of each package, so a pin eventually stops
   resolving. The build then fails with `breaks: world[chromium=<old version>]` and prints the
   version the repository offers; put that version in `ASM_CHROMIUM_VERSION` and build again.
   **From now on, always pass both files** when building or starting the scanner, including
   during upgrades (§9). A plain `docker compose up -d` recreates the scanner from
   `docker-compose.yml` alone — without the browser — and captures then fail with "not
   installed". To avoid typing it, put `COMPOSE_FILE=docker-compose.yml:docker-compose.screenshots.yml`
   in `.env`; plain `docker compose` commands then include the override.
   The override builds its own image tag (`asm-scanner:<version>-screenshots`), so a plain build
   never overwrites it; check the browser is really in it with
   `docker compose -f docker-compose.yml -f docker-compose.screenshots.yml run --rm asm-scanner versions`
   ("screenshot browser: Chromium …").
   Repeat the override's block for every per-tenant scanner service (`asm-scanner-<pool>`).
   The override adds the seccomp profile (`no-new-privileges` stays), 256 MB `/dev/shm` and
   a PID limit; the base file's 2 CPU / 2 GB cap still applies.
4. **Self-test** (no network needed): prints JSON and exits non-zero on failure.
   ```bash
   docker compose -f docker-compose.yml -f docker-compose.screenshots.yml run --rm asm-scanner browser-selftest
   ```
   `"ok": true` means the pinned browser started **with its sandbox** and produced an image.
   "sandbox is unavailable" means steps 1–2 are not in effect.
   `"dies_with_worker": true` means util-linux `setpriv` is in the image, so a browser cannot
   outlive a killed worker (BusyBox's `setpriv` cannot do this and is not used).
5. **Measure** on the deployed image (optional, recommended before raising limits):
   `... run --rm asm-scanner python /opt/asm/measure_screenshots.py --runs 10`. It also lists
   every external destination the browser contacted.
6. **Enable**: Settings → *Website screenshots — platform* → tick "The scanners have the
   screenshot browser". Keep "Active captures, whole deployment" at 1 on small hosts; each
   concurrent capture needs about 0.6 GB on its scanner (see the measurements).

Screenshots use the existing object storage (`asm-storage` volume or S3) under
`tenants/<id>/screenshots/`, and the existing egress firewall recommendation applies to the
scanner unchanged. To withdraw the feature, untick it; images are removed by retention or
with the organization.

## 6. In-Kingdom / air-gapped operation

Nothing in the platform requires a foreign cloud service. External calls are limited to:

| Call | Purpose | Configure / replace |
|---|---|---|
| Passive DNS/CT sources (Subfinder, crt.sh, Amass, SpiderFoot) | Discovery | Disable per profile; `ASM_CRTSH_URL` for a mirror |
| Team Cymru DNS | IP → ASN | Remove the `ip_enrichment` stage from profiles |
| CISA KEV, FIRST EPSS, NVD | Vulnerability intelligence | `ASM_INTEL_*_URL` mirrors, or `ASM_INTEL_REFRESH_ENABLED=false` + offline import: `docker compose run --rm -v "$PWD/intel:/intel:ro" asm-api cli intel-import --kev /intel/kev.json --epss /intel/epss_scores-current.csv.gz` |
| Nuclei template updates | Detection content | Volume populated from an internal mirror |

Object storage: local volume by default; any S3-compatible service (e.g. OCI Object Storage
in a Saudi region, Ceph) via `ASM_STORAGE_BACKEND=s3` and `ASM_S3_*`.

## 7. Backups and restore

```bash
docker compose exec -T postgres pg_dump -U postgres -Fc asm > asm-$(date +%F).dump
docker run --rm -v exteriq-asm_asm-storage:/data -v "$PWD":/backup alpine tar czf /backup/storage-$(date +%F).tgz -C /data .
```

Docker prefixes volume names with the Compose project name, which is the install folder's
name (`exteriq-asm` when cloned as in the README). For an install in another folder, check
`docker volume ls` and adjust the prefix.

Back up `.env` separately and securely: it contains the encryption keys. **Without
`ASM_ENCRYPTION_KEYS`, stored credentials and MFA secrets cannot be decrypted.**

Restore: stop the stack, `pg_restore -U postgres -d asm --clean` into a fresh volume, restore
the storage volume, start the stack.

## 8. Key rotation

- `ASM_ENCRYPTION_KEYS=k2:<new>,k1:<old>` — new secrets use `k2`, old ones still decrypt.
  Re-save credentials (or re-run a rotation job) before removing `k1`.
- `ASM_SECRET_KEY` rotation signs everyone out (JWTs and hashed refresh/reset tokens).
- `ASM_SCANNER_TRANSPORT_KEY` is the platform's master key; each pool's sensor containers get
  only their derived pool key (`ASM_SCANNER_POOL_KEY` for `default`, `cli scanner-pool-key
  <pool>` for others). Rotate the master key while no scans are running, then re-derive and
  redeploy every pool key (`python scripts/generate_env.py` refreshes the default one).

## 9. Upgrades

```bash
git pull && docker compose build && docker compose up -d   # asm-migrate applies migrations first
```

Upgrade from `main`. A checkout that was cloned with a single branch (for example a feature
branch, `git clone --branch <name> --single-branch`) does not know `main`: `git checkout main`
fails with "pathspec 'main' did not match". Add it once, then switch:

```bash
git remote set-branches --add origin main
git fetch origin
git checkout -b main --track origin/main
```

If website screenshots are enabled (§5b), build and start with both compose files, or set
`COMPOSE_FILE` in `.env` as described there.

Your data is in Docker **volumes** (`pg-data`, `asm-storage`, …), not in the checkout, so
pulling, rebuilding and restarting never touches it. `docker compose down` is safe;
**`docker compose down -v` deletes every volume** and is the one command that loses data.
Take the §7 backup before any upgrade anyway, and let running scans finish first.

Read release notes for tool version changes (new detection behaviour can change findings).

**Upgrading to tenant-isolated scanners.** `ASM_SCANNER_ISOLATION` now defaults to
`per_tenant`: a tenant whose scanner pool is shared with another tenant cannot scan, and
the scan is cancelled with a message naming the fix. A single-tenant deployment is
unaffected — one tenant alone on `default` shares with nobody. Adding a second customer
does require a pool for them:

```bash
docker compose run --rm asm-api cli scanner-pool t-globex
```

That prints the broker password, the Valkey ACL block, the derived transport key and the
scanner service (including its own ZAP daemon, since a ZAP session is global state). Add
the pool to `ASM_WORKER_POOLS` so `asm-ingest` consumes its results. An in-house
deployment where every tenant is the same organization can set
`ASM_SCANNER_ISOLATION=shared` instead — deliberately, and knowing what it gives up.

Tenant-managed **file exports** now write to `ASM_INTEGRATION_EXPORT_DIR/<tenant-id>/`;
point each collector's `localfile` at its tenant's directory.

**Upgrading to the Threat Center / screenshots / exposure map release (migrations 0008,
0009).** Take the §7 backup, then the usual three commands: `asm-migrate` applies both
migrations and `bootstrap` adds the internal Threat Center check profile. Nothing changes for
existing scans, profiles, findings, integrations or notification preferences, and no new
environment variable is required. New and visible afterwards:
- **Threat Center** in the sidebar, empty until a platform administrator publishes an
  advisory (Threat Center → Manage advisories). Publishing matches every tenant's inventory
  in the background and may send one "advisory may affect assets" alert per organization.
- **Exposure map** in the sidebar and on asset pages; read-only, no configuration.
- **Website screenshots** stay **off** — see §5b; tenants see why until you enable them.
- New beat tasks: `asm.core.threat_evaluate` (daily 04:40 UTC), `asm.core.screenshot_dispatch`
  (every minute), `asm.core.screenshot_schedule` (daily 02:30 UTC). They run in the existing
  `asm-scheduler`/`asm-worker`; `asm-ingest` now also accepts screenshot results.

Rollback: `alembic downgrade 0007` removes the new tables (catalog, assessments, capture
records — export first if needed); stored screenshot images are not deleted by a downgrade
(`tenants/*/screenshots/` in the object store).

**Upgrading within the current release line** (capability naming, idle sessions): nothing to
do beyond the three commands. No migration was added, and every new setting has a default —
`ASM_SESSION_IDLE_TTL_MINUTES` (30), `ASM_SCANNER_IDENTITY` (empty), `ASM_SCANNER_USER_AGENT`.
Expect two visible changes: anyone idle longer than the timeout is signed out once, and
stages recorded by *older* scans keep their original error text (only new scans are
sanitized).

**Upgrading to the sensor trust-boundary release (migration 0003).** Run
`python scripts/generate_env.py` first: it adds `ASM_SCANNER_POOL_KEY` (derived from your
existing master key) and `ASM_SCANNER_REDIS_PASSWORD`, and drops the obsolete
`ASM_SENSOR_QUEUES` (a scanner container now serves one pool, `ASM_SENSOR_POOL`). Let running
scans finish first: in-flight results from the old pipeline are not accepted and those stages
are failed by the watchdog. Redis must be recreated to pick up the ACL users
(`docker compose up -d --force-recreate redis`), and the new `asm-ingest` service must run.
MFA enrollment now asks for the account password.

## 10. Operations

- Health: `GET /api/v1/health` (liveness), `GET /api/v1/health/ready` (database + broker).
- Logs are JSON on stdout (`ASM_LOG_JSON=true`), with secrets redacted.
- Audit trail: UI → Audit log, or `docker compose run --rm asm-api cli verify-audit --tenant <id>`.
- Demo data (non-production): `docker compose run --rm -v "$PWD:/src:ro" -w /src asm-api python scripts/seed_demo.py`.
