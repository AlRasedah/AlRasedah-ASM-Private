"""Moving reserved captures onto the broker (or, in inline mode, running them here)."""

from __future__ import annotations

import logging

from app.core.config import get_settings

from . import service

log = logging.getLogger(__name__)


def dispatch() -> int:
    """Reserve free slots and hand the captures to their tenants' scanner pools.

    Celery mode makes one pass (it runs every minute and after every request and
    result). Inline mode (development, tests) runs each capture to completion here,
    which frees its slot, so it loops until nothing is left to reserve."""
    inline = get_settings().sensor_mode == "inline"
    launched = 0
    while True:
        reserved = service.reserve()
        if not reserved:
            break
        for tenant_id, capture_id in reserved:
            built = service.launch(tenant_id, capture_id)
            if built is None:
                continue
            job, pool = built
            launched += 1
            if inline:
                service.mark_dispatched(tenant_id, capture_id, job.job_id, True)
                service.run_inline(job, pool)
                continue
            from app.workers.tasks import publish_job

            try:
                publish_job(job, pool)
                ok = True
            except Exception:  # noqa: BLE001 - broker unavailable: fail this capture, not the dispatcher
                log.exception("could not dispatch screenshot job %s", job.job_id)
                ok = False
            service.mark_dispatched(tenant_id, capture_id, job.job_id, ok)
        if not inline:
            break
    return launched
