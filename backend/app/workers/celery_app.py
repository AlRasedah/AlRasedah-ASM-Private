"""Celery application for the platform's core worker and scheduler.

Queues:
* ``core``               – orchestration, notifications, reports (asm-worker). Only
                           platform processes can write it (broker ACL).
* ``scanners.<pool>``    – sensor jobs, consumed by asm-scanner containers (no DB access)
* ``results.<pool>``     – sensor results, consumed by asm-ingest (``app.workers.results``),
                           a separate app that runs nothing but result submission
"""

from __future__ import annotations

from functools import lru_cache

from celery import Celery
from celery.schedules import crontab

from app.core.config import get_settings

s = get_settings()


def transport_options(consumer: str) -> dict:
    """Broker options every platform app uses; must match the sensor workers'.

    ``priority_steps=[0]`` keeps each queue a single, exactly named broker key
    (so broker ACLs can name it); the unacked keys are per consumer so no
    consumer can read (or restore) another's in-flight messages.
    """
    return {
        "visibility_timeout": s.broker_visibility_timeout,
        "priority_steps": [0],
        "unacked_key": f"unacked.{consumer}",
        "unacked_index_key": f"unacked_index.{consumer}",
        "unacked_mutex_key": f"unacked_mutex.{consumer}",
    }


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
    broker_transport_options=transport_options("core"),
    # Core workers accept no remote-control commands: nothing on the broker may
    # redirect them (e.g. add_consumer) to a queue that sensor workers can write.
    worker_enable_remote_control=False,
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


@lru_cache
def pool_control(pool: str) -> Celery:
    """A client app on one pool's control exchange (sensor workers use ``asm-<pool>``)."""
    app = Celery(f"asm-control-{pool}", broker=s.broker_url, backend=None, set_as_current=False)
    app.conf.update(control_exchange=f"asm-{pool}", broker_transport_options=transport_options("control"),
                    accept_content=["json"])
    return app
