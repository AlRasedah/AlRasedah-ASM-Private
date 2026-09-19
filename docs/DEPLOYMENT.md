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
always listen on 8080/8443. The TLS config redirects HTTP to HTTPS on `ASM_PUBLIC_HTTPS_PORT`
(defaults to `ASM_HTTPS_PORT`), so the redirect stays correct on a non-standard port instead of
sending browsers to `:443` (which may be another service). Set `ASM_PUBLIC_HTTPS_PORT` only when
an external load balancer terminates TLS on a different public port than the one published here.

Behind an external load balancer that terminates TLS, keep the default proxy config, set
`ASM_COOKIE_SECURE=true` and make sure the balancer sets `X-Forwarded-Proto: https`.

## 3a. Troubleshooting first deploy

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

Set `ASM_SMTP_HOST`, `ASM_SMTP_PORT`, credentials and `ASM_SMTP_FROM`. Without SMTP,
password resets and user invitations fall back to one-time links shown to administrators,
and email notification channels fail visibly in the delivery log.

## 5. Sensors

- **Pools**: `tenants.worker_pool` (default `default`) routes a tenant's sensor jobs to queue
  `scanners.<pool>`. Run additional sensor workers for dedicated pools:
  `ASM_SENSOR_QUEUES=scanners.bank-a docker compose up -d --scale asm-scanner=2`, or add a
  second service with a different `ASM_SENSOR_QUEUES`.
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
  active-scanning authorization, and ZAP is confined per target to the authorized origin.
- **Egress identification**: the web and vulnerability sensors send
  `X-ASM-Scanner: Exteriq-ASM` by default (`identify_scanner` in profiles) so customers can
  recognise authorized scanning in their logs.

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
- `ASM_SCANNER_TRANSPORT_KEY` must be identical on platform and sensor containers; rotate
  both together while no scans are running.

## 9. Upgrades

```bash
git pull && docker compose build && docker compose up -d   # asm-migrate applies migrations first
```

Read release notes for tool version changes (new detection behaviour can change findings).

## 10. Operations

- Health: `GET /api/v1/health` (liveness), `GET /api/v1/health/ready` (database + broker).
- Logs are JSON on stdout (`ASM_LOG_JSON=true`), with secrets redacted.
- Audit trail: UI → Audit log, or `docker compose run --rm asm-api cli verify-audit --tenant <id>`.
- Demo data (non-production): `docker compose run --rm -v "$PWD:/src:ro" -w /src asm-api python scripts/seed_demo.py`.
