"""Celery application for the platform's core worker and scheduler.

Queues:
* ``core``               – orchestration, ingestion, notifications, reports (asm-worker)
* ``scanners.<pool>``    – sensor execution (asm-scanner containers, no DB access)
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

s = get_settings()

celery_app = Celery("asm-core", broker=s.broker_url, backend=s.result_backend, include=["app.workers.tasks"])
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    result_compression="gzip",
    result_expires=24 * 3600,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_default_queue="core",
    task_routes={"asm.core.*": {"queue": "core"}},
    broker_connection_retry_on_startup=True,
    timezone="UTC",
    beat_schedule={
        "dispatch-schedules": {"task": "asm.core.dispatch_schedules", "schedule": 60.0},
        "dispatch-queued-scans": {"task": "asm.core.dispatch_queued_scans", "schedule": 60.0},
        "dispatch-notifications": {"task": "asm.core.dispatch_notifications", "schedule": 60.0},
        "watchdog": {"task": "asm.core.watchdog", "schedule": 300.0},
        "maintenance": {"task": "asm.core.maintenance", "schedule": crontab(minute=17)},
        "refresh-intel": {"task": "asm.core.refresh_intel", "schedule": crontab(hour=3, minute=5)},
        "recompute-risk": {"task": "asm.core.recompute_all_risk", "schedule": crontab(hour=4, minute=10)},
        "snapshot-metrics": {"task": "asm.core.snapshot_metrics", "schedule": crontab(hour=0, minute=5)},
    },
)
