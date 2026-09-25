"""Celery entry point for sensor worker containers.

Run with::

    ASM_SENSOR_POOL=default celery -A asm_sensors.worker worker --without-gossip --without-mingle --without-heartbeat

A sensor worker serves exactly one worker pool. It needs only the broker URL
(its pool's broker user), the pool name and the pool key
(``ASM_SCANNER_TRANSPORT_KEY``). It deliberately has no database credentials,
never publishes platform tasks and stores nothing in a result backend: each
finished job is submitted as an authenticated envelope on ``results.<pool>``
(see :mod:`asm_sensors.jobs`).
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import UTC, datetime

from celery import Celery, signals
from celery.exceptions import SoftTimeLimitExceeded
from kombu import Queue

from . import __version__, eventlog, health, logs
from .coordination import RedisCoordinator
from .jobs import (
    RESULT_TASK_NAME,
    TASK_NAME,
    SensorJob,
    job_queue,
    result_queue,
    seal_log,
    seal_result,
    validate_pool,
)
from .observations import SensorResult
from .runner import execute_job

log = logging.getLogger(__name__)

# Structured events (exteriq.event/1, the same schema as the platform), then the secret
# filter, before any adapter builds an HTTP client: request URLs carry credentials.
eventlog.configure("scanner", __version__, os.environ.get("ASM_LOG_LEVEL", "INFO"),
                   os.environ.get("ASM_LOG_JSON", "true").lower() != "false",
                   extra_handlers=[health.RecentErrors()])
logs.configure()
scans_log = logging.getLogger("exteriq.scans")

POOL = validate_pool(os.environ.get("ASM_SENSOR_POOL", "default"))
QUEUE = job_queue(os.environ.get("ASM_SENSOR_QUEUE_PREFIX", "scanners"), POOL)
RESULTS = result_queue(POOL)
broker = os.environ.get("ASM_CELERY_BROKER_URL") or os.environ.get("ASM_REDIS_URL", "redis://redis:6379/0")
# Must be identical in every app sharing the broker and exceed the longest job
# (stage timeout + time-limit grace); otherwise a still-running job is redelivered.
VISIBILITY_TIMEOUT = int(os.environ.get("ASM_BROKER_VISIBILITY_TIMEOUT", str(6 * 3600)))


def transport_options(pool_namespace: str) -> dict:
    """Broker options shared by every app: no priority sub-queues, per-consumer unacked keys."""
    return {
        "visibility_timeout": VISIBILITY_TIMEOUT,
        "priority_steps": [0],
        "unacked_key": f"unacked.{pool_namespace}",
        "unacked_index_key": f"unacked_index.{pool_namespace}",
        "unacked_mutex_key": f"unacked_mutex.{pool_namespace}",
    }


app = Celery("asm-sensors", broker=broker, backend=None)
app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_ignore_result=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
    broker_connection_retry_on_startup=True,
    broker_transport_options=transport_options(QUEUE),
    # Consume only the pool's job queue (results.<pool> is published to, never consumed).
    task_queues=[Queue(QUEUE)],
    task_default_queue=QUEUE,
    # Remote control (task revocation) is namespaced per pool, so one pool can
    # neither receive nor send another pool's control messages.
    control_exchange=f"asm-{POOL}",
    worker_send_task_events=False,
    worker_hijack_root_logger=False,
)


@signals.setup_logging.connect(weak=False)
def _keep_our_logging(**_: object) -> None:
    """Logging is configured above; Celery must not replace it."""


@signals.worker_ready.connect(weak=False)
@signals.worker_process_init.connect(weak=False)
def _start_health(**_: object) -> None:
    health.start(POOL, broker)

coordinator = RedisCoordinator(broker, prefix=f"asm.pool.{POOL}.")


def _submit(job: SensorJob, result: SensorResult) -> None:
    app.send_task(RESULT_TASK_NAME, args=[seal_result(job, result, POOL)], queue=RESULTS)


@app.task(name=TASK_NAME, bind=True, shared=False)
def run_sensor(self, job: dict) -> None:  # type: ignore[no-untyped-def]
    parsed = SensorJob.model_validate(job)
    header = getattr(self.request, "exteriq_ctx", None) or {}
    token = eventlog.bind(tenant_id=parsed.tenant_id, scan_id=parsed.scan_id, stage_id=parsed.stage_id,
                          job_id=parsed.job_id, pool=POOL, task_id=self.request.id, task=TASK_NAME,
                          correlation_id=(header.get("correlation_id") if isinstance(header, dict) else None)
                          or parsed.job_id)
    try:
        _run(parsed)
    finally:
        eventlog.clear()
        eventlog.reset(token)


def _run(parsed: SensorJob) -> None:
    # A job redelivered while (or after) another worker ran it must not send the same
    # active traffic twice; the platform's watchdog fails a stage whose run was lost.
    if not coordinator.claim(f"job.{parsed.job_id}", ttl=parsed.timeout_seconds + VISIBILITY_TIMEOUT):
        log.warning("job %s was already claimed by a worker; ignoring the redelivery", parsed.job_id)
        return
    started = datetime.now(UTC)

    def send_output(chunk: dict) -> None:  # the stage's cleaned verbose output, as it runs
        app.send_task(RESULT_TASK_NAME, args=[seal_log(parsed, chunk, POOL)], queue=RESULTS)

    # Website captures are not scan stages; their progress is shown on the capture itself.
    sink = None if parsed.adapter == "screenshot" else send_output
    try:
        result = asyncio.run(execute_job(parsed, coordinator=coordinator, log_sink=sink))
    except SoftTimeLimitExceeded:
        result = SensorResult(adapter=parsed.adapter, status="failed", started_at=started,
                              finished_at=datetime.now(UTC), target_count=len(parsed.targets),
                              errors=["sensor exceeded its time limit"])
    _submit(parsed, result)
    health.job_finished(result.status)
    scans_log.log(logging.INFO if result.status == "completed" else logging.WARNING,
                  "job %s %s", parsed.adapter, result.status, extra={
                      "event": "scanner.job.finished", "stream": "scans", "adapter": parsed.adapter,
                      "status": result.status, "target_count": len(parsed.targets),
                      "observation_count": len(result.observations),
                      "duration_ms": round((result.finished_at - result.started_at).total_seconds() * 1000),
                      "error_code": None if result.status == "completed" else "ASM-SCNR-004"})
