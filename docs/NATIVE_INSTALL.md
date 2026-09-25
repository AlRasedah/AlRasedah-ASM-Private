# Native installation (Ubuntu 26.04 LTS, amd64) — without Docker

The Docker deployment (`docs/DEPLOYMENT.md`) is unchanged and remains supported. This guide
covers the native packages: the same application, run by systemd on one Ubuntu host.

**Supported:** Ubuntu 26.04 LTS, amd64, booted with systemd. Other distributions and
architectures are refused by the installer.

## What gets installed

| Package | Contents |
|---|---|
| `exteriq-release-<version>` | `/opt/exteriq/releases/<version>/`: prebuilt web app, platform virtualenv, scanner virtualenv, scanner engines (built natively for Ubuntu 26.04 with a pinned Go toolchain, checksummed), database migrations, `MANIFEST.sha256` of every file, `BUILDINFO` |
| `exteriq` | `exteriqctl`, systemd units, rsyslog collector config, log rotation, nginx site template |
| from Ubuntu | PostgreSQL 18, Valkey 9, nginx, rsyslog, logrotate, Python 3.14, libpcap, fonts |

No compilers, Node.js or Go are needed on the server. Releases install side by side (like
kernel packages); `/opt/exteriq/current` points at the active one.

| Path | What | Owner / mode |
|---|---|---|
| `/opt/exteriq/releases/<v>/` | immutable release | root, read-only for services |
| `/opt/exteriq/current` | symlink to the active release | root |
| `/etc/exteriq/exteriq.env` | platform configuration **and secrets** | `root:exteriq 0640` |
| `/etc/exteriq/scanner/<pool>.env` | a pool's broker user and key only | `root:exteriq-scanner 0640` |
| `/etc/exteriq/valkey.conf`, `valkey-users.acl` | broker config, ACL users (hashed passwords) | `root:exteriq-valkey 0640` |
| `/etc/exteriq/tls/` | certificate and key | `root 0750`, key `0600` |
| `/var/lib/exteriq/storage`, `exports` | reports, stored outputs, file exports | `exteriq 0750` |
| `/var/lib/exteriq/valkey` | broker data (AOF) | `exteriq-valkey 0750` |
| `/var/lib/exteriq/scanner/<pool>/` | scanner home and detection content | `exteriq-scanner` |
| `/var/lib/exteriq/backups`, `diagnostics` | backups (hold secrets), diagnostic archives | `root 0700` |
| `/var/log/exteriq/` | categorized JSON logs (docs/LOGGING.md) | `syslog:adm 0750` |

## Services and isolation

| Unit | Account | Listens | Network | Limits |
|---|---|---|---|---|
| `exteriq-api` | exteriq | 127.0.0.1:8000 | egress (DNS checks, SMTP) | 1 GB, 2 CPU |
| `exteriq-worker` | exteriq | — | egress (feeds, webhooks, SIEM, mail) | 2 GB, 2 CPU |
| `exteriq-ingest` | exteriq | — | localhost only | 2 GB, 2 CPU |
| `exteriq-scheduler` | exteriq | — | localhost only | 256 MB, 0.5 CPU |
| `exteriq-scanner@<pool>` | exteriq-scanner | — | egress (scanning) | 2 GB, 2 CPU |
| `exteriq-valkey` | exteriq-valkey | 127.0.0.1:6380, ::1 | localhost only | 1 GB |
| `nginx` (system) | www-data | 80, 443 (configurable) | — | — |
| `postgresql` (system) | postgres | localhost:5432 (Ubuntu default) | — | — |

Every Exteriq unit runs without capabilities, with `NoNewPrivileges`, `ProtectSystem=strict`,
private `/tmp` and devices, kernel/cgroup/clock protection, `MemoryDenyWriteExecute`, a
system-call allowlist (`@system-service` minus privileged calls) and restricted address
families. Platform units cannot see scanner keys, TLS keys or backups; scanner units cannot
see the platform configuration, stored data, the database socket, backups or logs, and hold
**no database credentials**. The application database role is `NOSUPERUSER NOBYPASSRLS
NOCREATEROLE NOCREATEDB`; tables force row-level security. Each scanner pool has its own
broker ACL user limited to its own queues and keys.

Check a unit's hardening: `systemd-analyze security exteriq-api`.

## Install

On the server, in the directory with the two `.deb` files, `install.sh` and `SHA256SUMS`:

```bash
sudo sh install.sh --hostname asm.example.com
```

1. **Validate** the host: Ubuntu 26.04, amd64, systemd, packages, ≥5 GB free in /var/lib,
   ports 80/443/8000/6380 free (or used by nginx/Exteriq itself).
2. **Verify** the files against `SHA256SUMS` (and `SHA256SUMS.asc` when present and the
   release key is installed at `/usr/share/keyrings/exteriq-release.gpg`), then every
   release file against its build manifest.
3. **Install** the packages with apt (dependencies from the host's Ubuntu repositories or
   mirror) and activate the release.
4. **Generate secrets** (session key, encryption keys, transport key, database and broker
   passwords, one broker user per pool) into root-owned files. They are never printed.
5. **Database and broker:** create the `exteriq` role and database in the local PostgreSQL
   (an existing database of that name owned by someone else stops the installer; nothing
   else in PostgreSQL is touched), start Exteriq's own Valkey instance (the distribution's
   `valkey-server` service is left as it is), run migrations, seed built-in profiles.
6. **TLS:** a self-signed certificate for the hostname and the host's addresses, until you
   install yours (below). The nginx site is added next to existing sites; other sites are not
   modified.
7. **Logging:** journald → rsyslog → `/var/log/exteriq`, hourly rotation.
8. **Start** everything and check readiness: every unit active, API health and the web app
   through nginx, schema equals the release's, heartbeats from every service and scanner
   pool.
9. **Show the URL and a one-time setup link**
   (`https://<host>/setup#token=…`, single use, expires in 30 minutes). Open it to create the
   first platform administrator. There are no default passwords. A new link:
   `sudo exteriqctl setup-link`.

### Scanner pools: one per tenant

With per-tenant scanner isolation (`ASM_SCANNER_ISOLATION=per_tenant`, the default) every
tenant — including the first one, created on the setup page — gets a worker pool of its own
(`t-<tenant-slug>`), and the platform refuses to dispatch a tenant's scans until that pool has
a scanner (the scan is cancelled with that reason). After creating tenants, run:

```bash
sudo exteriqctl sync-pools
```

It gives every active tenant's pool its own broker user, key and `exteriq-scanner@<pool>`
service, updates `ASM_WORKER_POOLS`, and repairs any pool configuration that drifted. Each
scanner is limited to 2 GB / 2 CPU. For a single-organization deployment where all tenants are
the same company, `ASM_SCANNER_ISOLATION=shared` in `/etc/exteriq/exteriq.env` makes every
tenant use the `default` pool instead (see SECURITY.md before choosing it).

If a step fails, the installer says what to do and stops; after fixing the cause, run
`sudo exteriqctl install` again — completed steps are recognised and skipped. On a readiness
failure it prints what is not ready and how to see why (`exteriqctl diag`).

Options: `--https-port`, `--http-port` (default 443/80), `--pools a,b` (scanner pools; default
`default`).

### Your certificate

```bash
sudo exteriqctl tls install --cert /path/fullchain.pem --key /path/privkey.pem
```

It checks that the key matches the certificate and that it is valid for at least a day, keeps
the previous pair in `/etc/exteriq/tls/previous-<time>/`, and reloads nginx only if
`nginx -t` accepts the result. Renewals (e.g. certbot `--deploy-hook`) can call the same
command.

## Offline and network features

The packages install without internet access when the host's apt source (e.g. a local Ubuntu
mirror) provides the Ubuntu dependencies. These features need outbound network access:

| Feature | Needs |
|---|---|
| Scanning customer targets (all active and passive stages) | egress to the targets and passive sources |
| Detection content (vulnerability templates) | download at scanner start (`ASM_NUCLEI_AUTO_UPDATE`); offline, the scanner reports "detection content missing" and vulnerability stages are skipped |
| Threat Center feeds (CISA KEV, NVD, EPSS) | egress to those feeds or your mirrors (`ASM_INTEL_*_URL`) |
| Notifications, webhooks, SIEM, e-mail | egress to those endpoints |

### Not included in native installs (this release)

- **Website screenshots** (need a sandboxed Chromium; Ubuntu ships Chromium only as a snap,
  which is not supported here). The feature reports itself as unavailable. Use the Docker
  deployment's screenshot profile if you need it.
- **OWASP ZAP (DAST)** and **SpiderFoot** are not packaged. To use an existing ZAP daemon,
  set `ASM_ZAP_URL`/`ASM_ZAP_API_KEY` in `/etc/exteriq/scanner/<pool>.env` and restart that
  scanner.

## Operate

```bash
sudo exteriqctl status                 # units, active release, schema
sudo exteriqctl diag                   # diagnostic report + archive (works during outages)
sudo exteriqctl stop | start
sudo exteriqctl sync-pools             # a scanner pool for every tenant that lacks one
sudo exteriqctl add-pool <name>        # a pool by name (own broker user and key)
journalctl -u 'exteriq-*' -f
```

Configuration changes: edit `/etc/exteriq/exteriq.env`, then
`sudo systemctl restart exteriq.target`.

## Backups

```bash
sudo exteriqctl backup            # database (pg_dump), /etc/exteriq incl. keys, stored files
sudo exteriqctl backup --no-storage
```

Backups go to `/var/lib/exteriq/backups/<time>-<release>-<label>/` (0700, files 0600) with a
`MANIFEST.json` of checksums. **They contain the encryption keys**: without
`/etc/exteriq/exteriq.env` the stored integration credentials cannot be decrypted. Copy them
off the host.

Restore (verifies checksums, takes a safety backup of the current state first, replaces the
database and configuration, switches to the backup's release if installed, starts and checks
readiness):

```bash
sudo exteriqctl restore <backup-dir-name> --yes
```

## Upgrade

```bash
sudo apt install ./exteriq-release-<new>_amd64.deb ./exteriq_<new>_amd64.deb   # installs alongside; nothing restarts
sudo exteriqctl upgrade
```

`upgrade` runs, in order:

1. **Pre-checks:** verifies the new release's files; checks the database's current schema is
   one the new release knows how to migrate from.
2. **Backup** of database, configuration and keys (always; stored files are not changed by an
   upgrade and are not included).
3. **Drain:** stops the scheduler and API (no new scans or requests), waits up to
   `--drain-timeout` (600 s) for queued/running stages to finish, then stops workers and
   scanners with a warm shutdown (running jobs may finish within the stop timeout).
   Work still queued stays in the broker and resumes after the upgrade; a job interrupted
   mid-run is redelivered after the broker visibility timeout.
4. **Migrate** with the new release. All migrations run in one transaction: if one fails,
   PostgreSQL rolls everything back. The upgrade then **restarts the previous release** and
   reports the failure. If the schema did change (a non-transactional migration), services
   stay stopped and the message gives the exact `restore` command.
5. **Switch** `/opt/exteriq/current` atomically, reload units.
6. **Start and verify** readiness. If the new release is not healthy, the message says
   whether switching back is safe (schema unchanged) or a restore is needed.

## Rollback — what is and is not possible

- `sudo exteriqctl rollback` switches back to the previous release **only if the database
  schema is exactly what that release expects** (for example an upgrade without migrations,
  or one that failed and rolled back). It refuses otherwise.
- **Changing the application symlink cannot undo a database migration.** After a migration,
  going back means restoring the backup taken before the upgrade
  (`exteriqctl restore <pre-upgrade backup> --yes`). Data written since that backup is lost.
- Keep at least the previous release installed: `exteriqctl prune` removes older release
  packages and keeps the active and the previous one.

## Uninstall

```bash
sudo apt remove exteriq 'exteriq-release-*'
```

Stops and disables the services and removes the program files. **Data is kept:** the
`exteriq` database, `/etc/exteriq` (secrets and keys), `/var/lib/exteriq` (data, backups) and
`/var/log/exteriq`. To delete everything deliberately, before removing the packages:

```bash
sudo exteriqctl backup                        # if you may need it
sudo exteriqctl purge-data --yes-delete-all-data
```

## Resource use

Measured on the Ubuntu 26.04 test system at idle with two scanner pools (memory in use per
unit):

| Unit | Memory |
|---|---|
| exteriq-api (4 workers) | 413 MB |
| exteriq-worker | 385 MB |
| exteriq-ingest | 208 MB |
| exteriq-scheduler | 88 MB |
| exteriq-scanner@<pool> | ~116 MB each (up to 2 GB while scanning) |
| exteriq-valkey | 4 MB |
| PostgreSQL, nginx, rsyslog | 39 / 21 / 9 MB |
| **Total** | **~1.4 GB** |

The unit limits cap Exteriq's own services at 1 + 2 + 2 + 0.25 + 1 GB plus 2 GB per scanner
pool. Disk: ~590 MB per installed release (keep the active and the previous one), ~85 MB of
detection content per scanner pool, logs bounded by rotation (docs/LOGGING.md); data grows
with assets, stored outputs (raw output retention 30 days) and backups.
