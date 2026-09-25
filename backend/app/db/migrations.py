"""Which schema version this code expects (the Alembic head shipped with it)."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_VERSIONS = Path(__file__).resolve().parents[2] / "alembic" / "versions"
_REV = re.compile(r'^revision(?::\s*str)?\s*=\s*"([^"]+)"', re.M)
_DOWN = re.compile(r'^down_revision(?::\s*[^=]+)?\s*=\s*"?([^"\n]+)"?', re.M)


@lru_cache
def expected_head() -> str | None:
    """The revision no other revision builds on. Read from the migration files, so it works
    without a database connection (the diagnostic CLI uses it when the database is down)."""
    revs, downs = set(), set()
    for f in _VERSIONS.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        rev, down = _REV.search(text), _DOWN.search(text)
        if rev:
            revs.add(rev.group(1))
        if down and down.group(1) not in ("None",):
            downs.add(down.group(1))
    heads = sorted(revs - downs)
    return heads[-1] if heads else None
