#!/usr/bin/env python3
"""Create .env from .env.example, replacing every CHANGE_ME with a strong random value.

Uses only the Python standard library. Existing values in .env are preserved;
re-running never rotates secrets that are already set.
"""

from __future__ import annotations

import base64
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def b64key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


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
    if target.exists():
        for line in target.read_text(encoding="utf-8").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                existing[k.strip()] = v
    out, generated = [], []
    for line in example.read_text(encoding="utf-8").splitlines():
        if "=" not in line or line.lstrip().startswith("#"):
            out.append(line)
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in existing and "CHANGE_ME" not in existing[key]:
            out.append(f"{key}={existing[key]}")
        elif "CHANGE_ME" in value:
            new = GENERATORS.get(key, lambda: secrets.token_urlsafe(32))()
            out.append(f"{key}={new}")
            generated.append(key)
        else:
            out.append(line)
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
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
