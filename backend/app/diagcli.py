"""Local diagnostics for server administrators, for when the web interface, the database or
the broker is down.

    sudo exteriqctl diag [--since 2h] [--out /var/lib/exteriq/diagnostics] [--no-archive]
    docker compose run --rm asm-api python -m app.diagcli          # Docker

Read-only: it never restarts, repairs or deletes anything. Every source is tried on its
own with a short timeout; one that cannot be read is reported as missing, with the reason,
and the rest is still collected. The archive (0600) contains the same redacted, allowlisted
data the report prints — no secrets, no database contents beyond counts and versions.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

CONFIG = Path(os.environ.get("EXTERIQ_CONFIG", "/etc/exteriq/exteriq.env"))
LOG_DIR = Path(os.environ.get("EXTERIQ_LOG_DIR", "/var/log/exteriq"))
UNITS = ("exteriq-api", "exteriq-worker", "exteriq-ingest", "exteriq-scheduler", "exteriq-valkey",
         "exteriq-scanner@default", "postgresql", "nginx", "rsyslog")
SECRET_KEY = re.compile(r"(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL|DSN|URL)", re.I)
SAFE_URL_KEYS = {"ASM_PUBLIC_URL"}


def _redact(text: str) -> str:
    from asm_sensors.eventlog import redact_text

    return redact_text(text)


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)  # noqa: S603
        return p.returncode, (p.stdout + p.stderr)
    except FileNotFoundError:
        return 127, f"{argv[0]} is not installed"
    except subprocess.TimeoutExpired:
        return 124, f"{argv[0]} did not answer within {timeout}s"


def load_config() -> dict[str, Any]:
    """Put the installation's settings into the environment; report which keys exist (values of
    secret-looking keys are never shown)."""
    if not CONFIG.exists():
        return {"status": "missing", "reason": f"{CONFIG} does not exist (Docker install, or not installed)"}
    try:
        lines = CONFIG.read_text(encoding="utf-8").splitlines()
    except PermissionError:
        return {"status": "missing", "reason": f"{CONFIG} is not readable by this user (run as root)"}
    shown: dict[str, str] = {}
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)
        shown[k] = v if (k in SAFE_URL_KEYS or not SECRET_KEY.search(k)) else "(set)"
    return {"status": "ok", "path": str(CONFIG), "keys": shown}


def versions() -> dict[str, Any]:
    out: dict[str, Any] = {"python": platform.python_version(), "kernel": platform.release(),
                           "machine": platform.machine()}
    with contextlib.suppress(Exception):
        from app import __version__
        from app.db.migrations import expected_head

        out["application"], out["expected_schema"] = __version__, expected_head()
    with contextlib.suppress(OSError):
        osr = platform.freedesktop_os_release()
        out["os"] = osr.get("PRETTY_NAME")
    release = Path("/opt/exteriq/current")
    if release.exists():
        out["installed_release"] = os.path.realpath(release)
    return out


def services() -> dict[str, Any]:
    if not shutil.which("systemctl"):
        return {"status": "missing", "reason": "systemctl is not available (not a systemd host or a container)"}
    out = {}
    for unit in UNITS:
        rc, text = _run(["systemctl", "show", unit if "@" in unit or unit.endswith(".service") else f"{unit}.service",
                         "--property=ActiveState,SubState,NRestarts,Result,ActiveEnterTimestamp,MemoryCurrent"])
        props = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        out[unit] = props if rc == 0 else {"status": "missing", "reason": text.strip()[:200]}
    return out


def journal(since: timedelta) -> dict[str, Any]:
    if not shutil.which("journalctl"):
        return {"status": "missing", "reason": "journalctl is not available"}
    minutes = int(since.total_seconds() // 60)
    rc, text = _run(["journalctl", "--no-pager", "-o", "cat", "-p", "warning", "--since", f"-{minutes}min",
                     "-n", "500", *[a for u in UNITS for a in ("-u", u if "@" in u else f"{u}.service")]], timeout=20)
    if rc != 0:
        return {"status": "missing", "reason": text.strip()[:300] or "journalctl failed (run as root or in adm)"}
    return {"status": "ok", "lines": [_redact(line) for line in text.splitlines()[-500:]]}


def log_files() -> dict[str, Any]:
    if not LOG_DIR.is_dir():
        return {"status": "missing", "reason": f"{LOG_DIR} does not exist"}
    out: dict[str, Any] = {"files": {}}
    for f in sorted(LOG_DIR.glob("*.json")):
        try:
            st = f.stat()
            with f.open("rb") as fh:
                fh.seek(max(0, st.st_size - 256 * 1024))
                tail = fh.read().decode("utf-8", "replace").splitlines()[-200:]
            out["files"][f.name] = {"bytes": st.st_size, "modified": datetime.fromtimestamp(st.st_mtime, UTC)
                                    .isoformat(), "tail": [_redact(x) for x in tail] if f.name == "errors.json" else None}
        except PermissionError:
            out["files"][f.name] = {"status": "missing", "reason": "not readable by this user"}
    stats = LOG_DIR / "collector-stats.json"
    if stats.exists():
        with contextlib.suppress(OSError):
            out["collector_stats_tail"] = stats.read_text(errors="replace").splitlines()[-5:]
    return out


def database() -> dict[str, Any]:
    url = os.environ.get("ASM_DATABASE_URL", "")
    if not url:
        return {"status": "missing", "reason": "ASM_DATABASE_URL is not configured"}
    try:
        import psycopg

        dsn = url.replace("postgresql+psycopg://", "postgresql://")
        with psycopg.connect(dsn, connect_timeout=5) as conn:
            conn.execute("SET statement_timeout = 5000")
            conn.execute("SELECT set_config('app.bypass_rls', 'on', false)")
            q = lambda sql: conn.execute(sql).fetchone()[0]  # noqa: E731
            return {"status": "ok", "server_version": q("SHOW server_version"),
                    "schema": q("SELECT version_num FROM alembic_version"),
                    "running_scans": q("SELECT count(*) FROM scans WHERE status = 'running'"),
                    "queued_scans": q("SELECT count(*) FROM scans WHERE status IN ('pending', 'queued')"),
                    "errors_last_hour": q("SELECT count(*) FROM ops_events WHERE ts > now() - interval '1 hour' "
                                          "AND level IN ('ERROR', 'CRITICAL')")}
    except Exception as exc:  # noqa: BLE001
        return {"status": "missing", "reason": _redact(f"{type(exc).__name__}: {exc}")[:300]}


def broker() -> dict[str, Any]:
    url = os.environ.get("ASM_CELERY_BROKER_URL") or os.environ.get("ASM_REDIS_URL", "")
    if not url:
        return {"status": "missing", "reason": "no broker URL configured"}
    try:
        import redis

        from app.observability import health

        client = redis.Redis.from_url(url, socket_timeout=3, socket_connect_timeout=3)
        client.ping()
        pools = [p.strip() for p in os.environ.get("ASM_WORKER_POOLS", "default").split(",") if p.strip()]
        return {"status": "ok", "queues": health.queues(client, pools), "services": health.services(client),
                "scanners": health.scanners(client, pools)}
    except Exception as exc:  # noqa: BLE001
        return {"status": "missing", "reason": _redact(f"{type(exc).__name__}: {exc}")[:300]}


def resources() -> dict[str, Any]:
    from app.observability import health

    with contextlib.suppress(Exception):
        return health.host()
    return {"status": "missing", "reason": "host resources could not be read"}


def collect(since: timedelta) -> dict[str, Any]:
    started = time.monotonic()
    report: dict[str, Any] = {"schema": "exteriq.diag/1", "collected_at": datetime.now(UTC).isoformat()}
    report["config"] = load_config()
    for name, fn in (("versions", versions), ("services", services), ("resources", resources),
                     ("database", database), ("broker", broker), ("log_files", log_files),
                     ("journal", lambda: journal(since))):
        try:
            report[name] = fn()
        except Exception as exc:  # noqa: BLE001 - one broken source must not stop the rest
            report[name] = {"status": "missing", "reason": _redact(f"{type(exc).__name__}: {exc}")[:300]}
    report["missing"] = {k: v.get("reason") for k, v in report.items()
                         if isinstance(v, dict) and v.get("status") == "missing"}
    report["seconds"] = round(time.monotonic() - started, 1)
    return report


def summary(r: dict[str, Any]) -> str:
    lines = [f"Exteriq diagnostics  {r['collected_at']}"]
    v = r.get("versions", {})
    lines.append(f"  version        {v.get('application', '?')}  schema expected {v.get('expected_schema', '?')}  "
                 f"os {v.get('os', '?')}")
    db = r.get("database", {})
    lines.append(f"  database       {db.get('status')}  schema {db.get('schema', '-')}  running scans "
                 f"{db.get('running_scans', '-')}  errors/1h {db.get('errors_last_hour', '-')}"
                 + (f"  ({db.get('reason')})" if db.get("status") == "missing" else ""))
    br = r.get("broker", {})
    lines.append(f"  broker         {br.get('status')}" + (f"  ({br.get('reason')})" if br.get("status") == "missing"
                                                          else ""))
    if br.get("status") == "ok":
        for q, info in br.get("queues", {}).items():
            lines.append(f"    queue {q:22} depth {info.get('depth')}  oldest {info.get('oldest_age_seconds')}s")
    svc = r.get("services", {})
    if isinstance(svc, dict) and svc.get("status") != "missing":
        for unit, props in svc.items():
            state = props.get("ActiveState", props.get("status"))
            lines.append(f"  {unit:25} {state}  restarts {props.get('NRestarts', '-')}  result "
                         f"{props.get('Result', props.get('reason', '-'))}")
    for name, reason in r.get("missing", {}).items():
        lines.append(f"  MISSING {name}: {reason}")
    return "\n".join(lines)


def write_archive(report: dict[str, Any], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = out_dir / f"exteriq-diag-{datetime.now(UTC):%Y%m%d-%H%M%S}.tar.gz"
    data = json.dumps(report, indent=2, default=str).encode()
    old = os.umask(0o077)
    try:
        with tarfile.open(path, "w:gz") as tar:
            info = tarfile.TarInfo("exteriq-diag/report.json")
            info.size, info.mtime, info.mode = len(data), int(time.time()), 0o600
            tar.addfile(info, io.BytesIO(data))
    finally:
        os.umask(old)
    os.chmod(path, 0o600)
    return path


def _duration(text: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([mhd])", text.strip())
    if not m:
        raise argparse.ArgumentTypeError("use e.g. 30m, 2h or 1d")
    n = int(m.group(1))
    return {"m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[m.group(2)]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="exteriqctl diag", description=__doc__.split("\n\n")[0])
    ap.add_argument("--since", type=_duration, default=timedelta(hours=2), help="journal window (default 2h)")
    ap.add_argument("--out", type=Path, default=Path(os.environ.get("EXTERIQ_DIAG_DIR",
                                                                     "/var/lib/exteriq/diagnostics")))
    ap.add_argument("--no-archive", action="store_true")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = ap.parse_args(argv)
    os.environ.setdefault("ASM_OPS_EVENTS", "false")
    report = collect(args.since)
    print(json.dumps(report, indent=2, default=str) if args.json else summary(report))
    if not args.no_archive:
        try:
            print(f"\narchive: {write_archive(report, args.out)}")
        except OSError as exc:
            print(f"\narchive not written: {exc}", file=sys.stderr)
    return 0 if not report["missing"] else 2


if __name__ == "__main__":
    sys.exit(main())
