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

from celery import Celery
from celery.exceptions import SoftTimeLimitExceeded
from kombu import Queue

from . import logs
from .coordination import RedisCoordinator
from .jobs import RESULT_TASK_NAME, TASK_NAME, SensorJob, job_queue, result_queue, seal_result, validate_pool
from .observations import SensorResult
from .runner import execute_job

log = logging.getLogger(__name__)

# Before any adapter builds an HTTP client: request URLs carry credentials.
logs.configure()

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
)

coordinator = RedisCoordinator(broker, prefix=f"asm.pool.{POOL}.")


def _submit(job: SensorJob, result: SensorResult) -> None:
    app.send_task(RESULT_TASK_NAME, args=[seal_result(job, result, POOL)], queue=RESULTS)


@app.task(name=TASK_NAME, bind=True, shared=False)
def run_sensor(self, job: dict) -> None:  # type: ignore[no-untyped-def]
    parsed = SensorJob.model_validate(job)
    # A job redelivered while (or after) another worker ran it must not send the same
    # active traffic twice; the platform's watchdog fails a stage whose run was lost.
    if not coordinator.claim(f"job.{parsed.job_id}", ttl=parsed.timeout_seconds + VISIBILITY_TIMEOUT):
        log.warning("job %s was already claimed by a worker; ignoring the redelivery", parsed.job_id)
        return
    started = datetime.now(UTC)
    try:
        result = asyncio.run(execute_job(parsed, coordinator=coordinator))
    except SoftTimeLimitExceeded:
        result = SensorResult(adapter=parsed.adapter, status="failed", started_at=started,
                              finished_at=datetime.now(UTC), target_count=len(parsed.targets),
                              errors=["sensor exceeded its time limit"])
    _submit(parsed, result)
