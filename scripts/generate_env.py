#!/usr/bin/env python3
"""Create .env from .env.example, replacing every CHANGE_ME with a strong random value.

Uses only the Python standard library. Existing values in .env are preserved;
re-running never rotates secrets that are already set.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def b64key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def pool_key(master_b64: str, pool: str = "default") -> str:
    """HKDF-SHA256 (RFC 5869, no salt, 32 bytes) — identical to asm_sensors.jobs.pool_key."""
    master = base64.urlsafe_b64decode(master_b64 + "=" * (-len(master_b64) % 4))
    prk = hmac.new(b"\x00" * 32, master, hashlib.sha256).digest()
    okm = hmac.new(prk, f"exteriq-asm/scanner-pool/v1/{pool}".encode() + b"\x01", hashlib.sha256).digest()
    return base64.urlsafe_b64encode(okm).decode().rstrip("=")


GENERATORS = {
    "ASM_SECRET_KEY": lambda: secrets.token_urlsafe(48),
    "ASM_ENCRYPTION_KEYS": lambda: f"k1:{b64key()}",
    "ASM_SCANNER_TRANSPORT_KEY": b64key,
    "ASM_BOOTSTRAP_ADMIN_PASSWORD": lambda: secrets.token_urlsafe(12) + "-Aa1!",
}


def main() -> int:
    example = ROOT / ".env.example"
    target = ROOT / ".env"
    existing: dict[str, str] = {}
    dupes: list[str] = []
    if target.exists():
        for line in target.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                k = k.strip()
                if k in existing:
                    dupes.append(k)  # a later occurrence wins, matching docker compose
                existing[k] = v
    out, generated, emitted = [], [], set()
    for line in example.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            out.append(line)
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        emitted.add(key)
        if key in existing and "CHANGE_ME" not in existing[key]:
            out.append(f"{key}={existing[key]}")
        elif "CHANGE_ME" in value:
            new = GENERATORS.get(key, lambda: secrets.token_urlsafe(32))()
            out.append(f"{key}={new}")
            generated.append(key)
        else:
            out.append(line)
    # The default pool's key is always derived from the master transport key, never random.
    master = next((ln.split("=", 1)[1] for ln in out if ln.startswith("ASM_SCANNER_TRANSPORT_KEY=")), "")
    if master and "CHANGE_ME" not in master:
        derived = pool_key(master)
        for i, ln in enumerate(out):
            if ln.startswith("ASM_SCANNER_POOL_KEY=") and ln != f"ASM_SCANNER_POOL_KEY={derived}":
                out[i] = f"ASM_SCANNER_POOL_KEY={derived}"
                generated.append("ASM_SCANNER_POOL_KEY")
    # Preserve any keys the user added that are not in the template (emitted once).
    extra = [k for k in existing if k not in emitted and k != "ASM_SENSOR_QUEUES"]  # replaced by ASM_SENSOR_POOL
    if extra:
        out.append("")
        out.append("# --- extra settings (kept from your existing .env) ---")
        out.extend(f"{k}={existing[k]}" for k in extra)
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    if dupes:
        print(f"note: collapsed duplicate keys (kept the last value of each): {', '.join(sorted(set(dupes)))}")
    left = [line.split('=', 1)[0] for line in out if '=' in line and 'CHANGE_ME' in line and not line.lstrip().startswith('#')]
    if left:
        print(f"WARNING: these still contain CHANGE_ME — set them before ASM_ENV=production: {', '.join(left)}")
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    print(f"wrote {target}")
    if "ASM_BOOTSTRAP_ADMIN_PASSWORD" in generated:
        pw = next(line.split("=", 1)[1] for line in out if line.startswith("ASM_BOOTSTRAP_ADMIN_PASSWORD="))
        email = next(line.split("=", 1)[1] for line in out if line.startswith("ASM_BOOTSTRAP_ADMIN_EMAIL="))
        print(f"initial administrator: {email} / {pw}  (change it after first login)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
