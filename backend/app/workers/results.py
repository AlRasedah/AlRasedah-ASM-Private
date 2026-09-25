"""Sensor result consumer (the ``asm-ingest`` process).

Sensor workers are untrusted: they can write only their own pool's result queue
(``results.<pool>``), and this is the only platform process that reads those
queues. It is a separate Celery app that registers exactly one task, so a
message naming any other task (``asm.core.*`` included) is rejected here
instead of being executed with platform privileges.

A submitted result is accepted only when:

1. its envelope MAC verifies with the claimed pool's key (which only that
   pool's workers hold), and
2. it answers the job the platform persisted for that stage: same tenant, scan,
   stage, job id, engine and worker pool, and the stage is still running.

Run with ``celery -A app.workers.results:results_app worker`` (see docker/backend/entrypoint.sh).
"""

from __future__ import annotations

import logging
import uuid

from asm_sensors.jobs import RESULT_TASK_NAME, ResultRejected, open_result, result_queue
from celery import Celery
from kombu import Queue

from app.core import crypto
from app.core.config import get_settings
from app.db.session import new_session
from app.models import Scan, ScanStage
from app.scans import orchestrator
from app.screenshots import service as screenshots
from app.screenshots.service import ADAPTER as SCREENSHOT_ADAPTER
from app.workers.celery_app import transport_options

log = logging.getLogger(__name__)
s = get_settings()

results_app = Celery("asm-results", broker=s.broker_url, backend=None, set_as_current=False)
results_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    broker_connection_retry_on_startup=True,
    broker_transport_options=transport_options("results"),
    task_queues=[Queue(result_queue(p)) for p in s.worker_pools],
    task_default_queue=result_queue(s.worker_pools[0]),
    worker_enable_remote_control=False,
    timezone="UTC",
)


def receive_result(envelope: object) -> uuid.UUID | None:
    """Verify and ingest one submitted result. Returns the scan to advance, or None if rejected.

    A website-screenshot result is bound to its capture record instead of a scan stage
    (``app.screenshots.service.binding_error``) and never advances a scan. The two
    bindings are disjoint: a result naming the other kind finds no matching row."""
    try:
        env, result = open_result(envelope, crypto.pool_transport_key)
        tenant_id, scan_id, stage_id = uuid.UUID(env.tenant_id), uuid.UUID(env.scan_id), uuid.UUID(env.stage_id)
    except (ResultRejected, ValueError) as exc:
        log.warning("rejected sensor result: %s", exc)
        return None
    if result.adapter == SCREENSHOT_ADAPTER:
        if screenshots.receive_result(env, result):
            _send_core("asm.core.screenshot_dispatch")  # its slot is free now
        return None
    with new_session(tenant_id) as db:
        scan = db.get(Scan, scan_id, with_for_update=True)  # serializes with advance_scan
        stage = db.get(ScanStage, stage_id)
        problem = orchestrator.result_binding_error(scan, stage, env, result)
        if problem:
            log.warning("rejected sensor result for job %s (stage %s): %s", env.job_id, env.stage_id, problem)
            return None
        assert scan is not None and stage is not None
        orchestrator.complete_stage(db, scan, stage, result)
        db.commit()
    return scan_id


def _send_core(name: str, *args: str) -> None:
    if s.sensor_mode == "inline":
        return
    from app.workers.celery_app import celery_app

    try:
        celery_app.send_task(name, args=list(args), queue="core")
    except Exception:  # noqa: BLE001 - the periodic task picks it up within a minute
        log.warning("could not queue %s", name)


@results_app.task(name=RESULT_TASK_NAME, shared=False)
def submit_result(envelope: dict) -> None:
    # A stage's verbose output arrives on the same task, as its own envelope kind with its
    # own MAC key; it never advances a scan.
    if isinstance(envelope, dict) and envelope.get("kind") == "log":
        from app.scans import output

        output.receive(envelope)
        return
    scan_id = receive_result(envelope)
    if scan_id is not None:
        from app.workers.celery_app import celery_app

        celery_app.send_task("asm.core.advance_scan", args=[str(scan_id)], queue="core")


# Celery registers its built-in tasks on every app, and some of them act on
# message-supplied task signatures (``celery.group`` publishes them with this
# process's broker credentials, ``celery.map`` runs them in-process). Anything a
# sensor worker puts on its result queue must never reach those, so the result
# consumer's registry holds result submission and nothing else; the worker
# discards messages naming any other task as unregistered.
for _name in [n for n in results_app.tasks if n != RESULT_TASK_NAME]:
    results_app.tasks.unregister(_name)
if set(results_app.tasks) != {RESULT_TASK_NAME}:
    raise RuntimeError(f"result consumer must register only {RESULT_TASK_NAME}, has {sorted(results_app.tasks)}")
