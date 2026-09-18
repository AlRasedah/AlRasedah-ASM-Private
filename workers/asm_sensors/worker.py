"""Celery entry point for sensor worker containers.

Run with::

    celery -A asm_sensors.worker worker -Q scanners.default --concurrency 4

The sensor worker only needs the broker/result-backend URL and the transport
key. It deliberately has no database credentials.
"""

from __future__ import annotations

import asyncio
import os

from celery import Celery

from .jobs import TASK_NAME, SensorJob
from .runner import execute_job

broker = os.environ.get("ASM_CELERY_BROKER_URL") or os.environ.get("ASM_REDIS_URL", "redis://redis:6379/0")
backend = os.environ.get("ASM_CELERY_RESULT_BACKEND") or broker

app = Celery("asm-sensors", broker=broker, backend=backend)
app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_compression="gzip",
    result_expires=24 * 3600,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=50,
    broker_connection_retry_on_startup=True,
)


@app.task(name=TASK_NAME, bind=True)
def run_sensor(self, job: dict) -> dict:  # type: ignore[no-untyped-def]
    parsed = SensorJob.model_validate(job)
    result = asyncio.run(execute_job(parsed))
    return result.model_dump(mode="json")
