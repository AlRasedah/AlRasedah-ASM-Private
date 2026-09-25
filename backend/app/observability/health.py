"""Service heartbeats and the health picture shown on the Diagnostics page.

Every platform process writes ``asm.health.<service>.<host>-<pid>`` on the broker every
30 s (expires after 90 s); scanners write ``asm.pool.<pool>.health.*`` (asm_sensors.health).
The collector reads those, the database, the broker's queues, the host's /proc and — on a
native install — systemd's own unit properties (restarts, OOM kills) through
``systemctl show``, which needs no privileges. It never reads log files or the journal.

Anything that cannot be measured is reported as ``{"status": "unavailable", "reason": …}``
— never as zero, and never as healthy.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time
from datetime import UTC, datetime
from typing import Any

from asm_sensors.health import engine_problems

from app import __version__

INTERVAL = 30
TTL = 90
UNITS = ("exteriq-api", "exteriq-worker", "exteriq-ingest", "exteriq-scheduler", "exteriq-valkey", "postgresql",
         "nginx", "rsyslog")
_started = datetime.now(UTC).isoformat()


def unavailable(reason: str) -> dict[str, Any]:
    return {"status": "unavailable", "reason": reason}


def _redis() -> Any:
    import redis

    from app.core.config import get_settings

    return redis.Redis.from_url(get_settings().broker_url, socket_timeout=3, socket_connect_timeout=3)


# --------------------------------------------------------------- heartbeats
_threads: dict[int, threading.Thread] = {}


def start_heartbeat(service: str) -> None:
    """Idempotent per process (and restarted in forked children by the caller's signal)."""
    pid = os.getpid()
    if pid in _threads and _threads[pid].is_alive():
        return

    def run() -> None:
        key = f"asm.health.{service}.{socket.gethostname()}-{pid}"
        while True:
            with contextlib.suppress(Exception):
                _redis().set(key, json.dumps({"service": service, "version": __version__, "pid": pid,
                                              "host": socket.gethostname(), "started": _started,
                                              "ts": datetime.now(UTC).isoformat()}), ex=TTL)
            time.sleep(INTERVAL)

    t = threading.Thread(target=run, name="exteriq-heartbeat", daemon=True)
    t.start()
    _threads[pid] = t


# ----------------------------------------------------------------- collection
def _scan_keys(client: Any, pattern: str, limit: int = 500) -> list[dict[str, Any]]:
    out = []
    for key in client.scan_iter(match=pattern, count=200):
        if len(out) >= limit:
            break
        raw = client.get(key)
        with contextlib.suppress(ValueError, TypeError):
            if raw:
                out.append(json.loads(raw))
    return out


def _age_seconds(iso: str | None) -> float | None:
    if not iso:
        return None
    with contextlib.suppress(ValueError):
        return (datetime.now(UTC) - datetime.fromisoformat(iso)).total_seconds()
    return None


def services(client: Any) -> dict[str, Any]:
    beats = _scan_keys(client, "asm.health.*")
    by: dict[str, list[dict[str, Any]]] = {}
    for b in beats:
        by.setdefault(str(b.get("service")), []).append(b)
    out: dict[str, Any] = {}
    for name in ("api", "worker", "ingest", "scheduler"):
        items = by.get(name, [])
        out[name] = ({"status": "ok", "instances": len(items), "versions": sorted({i.get("version") for i in items}),
                      "last_seen_seconds": min(_age_seconds(i.get("ts")) or 0 for i in items)}
                     if items else unavailable("no heartbeat in the last 90 seconds"))
    return out


def scanners(client: Any, pools: list[str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for pool in pools:
        items = _scan_keys(client, f"asm.pool.{pool}.health.*", limit=50)
        if not items:
            out[pool] = unavailable("no scanner of this pool reported in the last 2 minutes")
            continue
        rules = [i.get("detection_rules") or {} for i in items]
        broken = sorted({p for i in items for p in engine_problems(i.get("engines") or {})})
        out[pool] = {
            "status": "ok" if all(r.get("available") for r in rules) and not broken else "degraded",
            "problems": broken + (["detection content is not installed on at least one scanner"]
                                  if not all(r.get("available") for r in rules) else []),
            "instances": [{k: i.get(k) for k in ("host", "pid", "version", "engines", "detection_rules", "browser",
                                                 "last_job", "ts")} for i in items],
            "recent_errors": sorted((e for i in items for e in (i.get("recent_errors") or [])),
                                    key=lambda e: str(e.get("ts")), reverse=True)[:20],
        }
    return out


def queues(client: Any, pools: list[str]) -> dict[str, Any]:
    names = ["core", *(f"scanners.{p}" for p in pools), *(f"results.{p}" for p in pools)]
    out: dict[str, Any] = {}
    for q in names:
        depth = client.llen(q)
        oldest = client.lindex(q, -1) if depth else None
        age = None
        if oldest:
            with contextlib.suppress(ValueError, TypeError, KeyError):
                published = json.loads(oldest)["headers"].get("exteriq_ctx", {}).get("published")
                age = round(time.time() - float(published), 1) if published else None
        out[q] = {"depth": depth, "oldest_age_seconds": age,
                  "age_note": None if age is not None or not depth else "published before queue ages were recorded"}
    return out


def database(db: Any) -> dict[str, Any]:
    from sqlalchemy import text

    try:
        version = db.execute(text("SHOW server_version")).scalar()
        schema = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        size = db.execute(text("SELECT pg_database_size(current_database())")).scalar()
        conns = db.execute(text("SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()")).scalar()
    except Exception as exc:  # noqa: BLE001
        return unavailable(f"database query failed: {type(exc).__name__}")
    from app.db.migrations import expected_head

    head = expected_head()
    return {"status": "ok" if schema == head else "degraded", "server_version": version, "schema_version": schema,
            "expected_schema": head, "size_bytes": size, "connections": conns}


def host() -> dict[str, Any]:
    """What this process's host (or container) looks like, from /proc and statvfs."""
    out: dict[str, Any] = {"hostname": socket.gethostname(), "cpus": os.cpu_count()}
    try:
        with open("/proc/loadavg") as fh:
            out["load"] = [float(x) for x in fh.read().split()[:3]]
    except OSError:
        out["load"] = unavailable("/proc/loadavg is not readable")
    try:
        mem: dict[str, int] = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, v = line.split(":", 1)
                mem[k] = int(v.split()[0]) * 1024
        out["memory"] = {"total_bytes": mem.get("MemTotal"), "available_bytes": mem.get("MemAvailable")}
    except (OSError, ValueError):
        out["memory"] = unavailable("/proc/meminfo is not readable")
    from app.core.config import get_settings

    disks = {}
    for label, path in (("data", get_settings().storage_local_path), ("tmp", "/tmp")):  # noqa: S108 (read-only statvfs)
        try:
            du = shutil.disk_usage(path)
            disks[label] = {"path_label": label, "total_bytes": du.total, "free_bytes": du.free}
        except (OSError, TypeError):
            disks[label] = unavailable(f"{label} storage is not accessible from this process")
    out["disks"] = disks
    try:
        with open("/sys/fs/cgroup/memory.events") as fh:
            ev = dict(line.split() for line in fh if line.strip())
        out["cgroup_oom_kills"] = int(ev.get("oom_kill", 0))
    except (OSError, ValueError):
        out["cgroup_oom_kills"] = unavailable("no cgroup v2 memory events for this process")
    return out


def units() -> dict[str, Any]:
    """Native install only: restarts and last result per unit (``systemctl show``, unprivileged)."""
    if not os.environ.get("EXTERIQ_NATIVE") or not shutil.which("systemctl"):
        return unavailable("not a native install (systemd unit data is available on native installs only)")
    out: dict[str, Any] = {}
    for unit in UNITS:
        try:
            p = subprocess.run(["systemctl", "show", f"{unit}.service", "--property=ActiveState,SubState,"  # noqa: S603,S607
                                "NRestarts,Result,ActiveEnterTimestamp,MemoryCurrent,ExecMainStatus"],
                               capture_output=True, text=True, timeout=5, check=False)
            props = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        except (OSError, subprocess.SubprocessError):
            out[unit] = unavailable("systemctl did not answer")
            continue
        if props.get("ActiveState") in (None, "", "inactive") and props.get("SubState") == "dead" \
                and props.get("NRestarts") in (None, "", "0") and not props.get("ActiveEnterTimestamp"):
            out[unit] = unavailable("not installed or never started")
            continue
        out[unit] = {"active": props.get("ActiveState"), "sub": props.get("SubState"),
                     "restarts": int(props.get("NRestarts") or 0), "last_result": props.get("Result"),
                     "oom_killed": props.get("Result") == "oom-kill", "since": props.get("ActiveEnterTimestamp"),
                     "memory_bytes": int(props["MemoryCurrent"]) if props.get("MemoryCurrent", "").isdigit()
                     else None}
    return out


def collect_platform(db: Any) -> dict[str, Any]:
    from app.core.config import get_settings

    pools = list(get_settings().worker_pools)
    out: dict[str, Any] = {"collected_at": datetime.now(UTC).isoformat(), "version": __version__,
                           "database": database(db), "host": host(), "units": units()}
    try:
        client = _redis()
        client.ping()
        out["broker"] = {"status": "ok"}
        out["services"] = services(client)
        out["scanners"] = scanners(client, pools)
        out["queues"] = queues(client, pools)
    except Exception as exc:  # noqa: BLE001
        reason = f"broker unavailable: {type(exc).__name__}"
        out["broker"] = unavailable(reason)
        out["services"] = {n: unavailable(reason) for n in ("api", "worker", "ingest", "scheduler")}
        out["scanners"] = {p: unavailable(reason) for p in pools}
        out["queues"] = unavailable(reason)
    return out


def tenant_view(pool: str, shared: bool) -> dict[str, Any]:
    """What a tenant may know about the scanner that runs its scans: whether it is there and
    has its detection content. No queues (a shared pool's depth shows other tenants' work),
    no engines, no hosts."""
    try:
        client = _redis()
        items = _scan_keys(client, f"asm.pool.{pool}.health.*", limit=50)
    except Exception:  # noqa: BLE001
        return {"scanner": unavailable("the platform cannot reach its message broker right now")}
    if not items:
        return {"scanner": unavailable("no scanner for your scans reported recently")}
    rules_ok = all((i.get("detection_rules") or {}).get("available") for i in items)
    # Whether every scan capability can run — never which engine could not (tenants never see engines).
    capable = not any(engine_problems(i.get("engines") or {}) for i in items)
    return {"scanner": {"status": "ok" if rules_ok and capable else "degraded", "instances": len(items),
                        "detection_content": "installed" if rules_ok else "missing on at least one scanner",
                        "capabilities": "all available" if capable else "some scan capabilities cannot run; "
                                                                        "your platform operator has been told",
                        "dedicated": not shared}}
