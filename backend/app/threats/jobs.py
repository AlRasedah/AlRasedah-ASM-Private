"""Cross-tenant Threat Center work: find tenants in a system session, then do the
work for each one in its own tenant session (RLS applies to everything it reads
and writes). Used by the Celery tasks and, in inline mode, directly."""

from __future__ import annotations

import logging
import uuid

from app.db.session import new_session
from app.services.maintenance import active_tenants

from . import service

log = logging.getLogger(__name__)


def evaluate_everywhere(advisory_id: uuid.UUID | None = None) -> dict[str, int]:
    totals = {"tenants": 0, "matches": 0, "new_matches": 0, "events": 0, "errors": 0}
    only = [advisory_id] if advisory_id else None
    for tid in active_tenants():
        try:
            with new_session(tid) as db:
                s = service.evaluate_tenant(db, tid, only)
                db.commit()
        except Exception:  # noqa: BLE001 - one tenant's problem must not stop the others
            log.exception("Threat Center evaluation failed for tenant %s", tid)
            totals["errors"] += 1
            continue
        totals["tenants"] += 1
        totals["matches"] += s.matches
        totals["new_matches"] += s.new_matches
        totals["events"] += s.events
    return totals
