"""Which schema version this code expects (the Alembic head shipped with it)."""

from __future__ import annotations

import os
import re
import sys
from functools import lru_cache
from pathlib import Path

_REV = re.compile(r'^revision(?::\s*str)?\s*=\s*"([^"]+)"', re.M)
_DOWN = re.compile(r'^down_revision(?::\s*[^=]+)?\s*=\s*"?([^"\n]+)"?', re.M)


def versions_dir() -> Path | None:
    """Where this deployment's migration scripts are. The ``app`` package is installed into
    site-packages, so its own location says nothing about them:

    * ``ASM_ALEMBIC_DIR`` when set;
    * the source tree (``backend/alembic``) in development and tests;
    * ``/app/alembic`` in the container image;
    * ``<release>/platform/alembic`` next to the virtualenv in a native release.
    """
    candidates = [os.environ.get("ASM_ALEMBIC_DIR"),
                  Path(__file__).resolve().parents[2] / "alembic",
                  "/app/alembic",
                  Path(sys.prefix).parent / "alembic"]
    for c in candidates:
        if c and (Path(c) / "env.py").is_file() and (Path(c) / "versions").is_dir():
            return Path(c) / "versions"
    return None


@lru_cache
def expected_head() -> str | None:
    """The revision no other revision builds on. Read from the migration files, so it works
    without a database connection (the diagnostic CLI uses it when the database is down)."""
    versions = versions_dir()
    if versions is None:
        return None
    revs, downs = set(), set()
    for f in versions.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        rev, down = _REV.search(text), _DOWN.search(text)
        if rev:
            revs.add(rev.group(1))
        if down and down.group(1) not in ("None",):
            downs.add(down.group(1))
    heads = sorted(revs - downs)
    return heads[-1] if heads else None
