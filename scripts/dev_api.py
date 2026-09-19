#!/usr/bin/env python3
"""Run the API locally for development (inline sensors, no Redis required).

    python scripts/dev_api.py            # http://127.0.0.1:8000/api/docs

Override any setting with ASM_* environment variables.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Run this checkout's source (backend + sensor framework), ahead of any editable
# install — important when developing from a git worktree.
sys.path.insert(0, str(ROOT / "workers"))
sys.path.insert(0, str(ROOT / "backend"))

DEFAULTS = {
    "ASM_ENV": "development",
    "ASM_DATABASE_URL": "postgresql+psycopg://asm:asm@127.0.0.1:55432/asm_dev",
    "ASM_SECRET_KEY": "dev-secret-key-please-change-0123456789abcdef",
    "ASM_SENSOR_MODE": "inline",
    "ASM_COOKIE_SECURE": "false",
    "ASM_LOG_JSON": "false",
    "ASM_PUBLIC_URL": "http://localhost:5173",
    "ASM_STORAGE_LOCAL_PATH": str(Path(tempfile.gettempdir()) / "asm-dev-storage"),
    "ASM_ALLOW_NON_PUBLIC_SCOPE": "true",
}

if __name__ == "__main__":
    for k, v in DEFAULTS.items():
        os.environ.setdefault(k, v)
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=int(os.environ.get("ASM_DEV_PORT", "8000")),
                reload=False, proxy_headers=False)
