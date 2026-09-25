"""A stage's verbose output: received from the scanner, stored bounded, shown to the tenant.

The scanner cleans every line before sending it (``asm_sensors.stagelog``); it is not
trusted to have done so, so each line is cleaned again here. A chunk is accepted only
when its envelope verifies with the claimed pool's key (a separate key from results)
and it belongs to the job the platform dispatched for that stage, from that pool —
the same binding a result must satisfy. Chunks may trail the stage's result by a few
seconds, so a stage that ended recently still accepts them.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from asm_sensors import stagelog
from asm_sensors.jobs import LogEnvelope, ResultRejected, open_log
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core import crypto
from app.db.session import new_session
from app.models import Scan, ScanStage, ScanStageOutput
from app.models.enums import StageStatus

log = logging.getLogger(__name__)

LATE_GRACE = timedelta(minutes=15)
LEVELS = {"info", "warning", "error", "debug"}


def binding_error(scan: Scan | None, stage: ScanStage | None, env: LogEnvelope) -> str | None:
    if scan is None or stage is None or stage.scan_id != scan.id or str(scan.tenant_id) != env.tenant_id:
        return "no such stage for this tenant and scan"
    if not stage.task_id or stage.task_id != env.job_id:
        return "job id does not match the job dispatched for the stage"
    if (stage.worker_pool or "default") != env.pool:
        return f"sent by pool {env.pool!r}, but the job was dispatched to {stage.worker_pool!r}"
    if stage.status != StageStatus.RUNNING and (
            stage.finished_at is None or datetime.now(UTC) - stage.finished_at > LATE_GRACE):
        return f"stage is {stage.status.value}; output is stale"
    return None


def _clean(lines: list[Any], limit: int) -> list[list[Any]]:
    out: list[list[Any]] = []
    for t, level, text in lines:
        c = stagelog.clean(str(text))
        if c is None:
            continue
        out.append([max(0.0, float(t)), level if level in LEVELS else c[0], c[1]])
    return out[-limit:] if limit else out


def receive(envelope: object) -> bool:
    """Verify one chunk and add it to its stage's output. False when rejected."""
    try:
        env, chunk = open_log(envelope, crypto.pool_transport_key)
        tenant_id, scan_id, stage_id = uuid.UUID(env.tenant_id), uuid.UUID(env.scan_id), uuid.UUID(env.stage_id)
    except (ResultRejected, ValueError) as exc:
        log.warning("rejected stage output: %s", exc)
        return False
    with new_session(tenant_id) as db:
        scan, stage = db.get(Scan, scan_id), db.get(ScanStage, stage_id)
        problem = binding_error(scan, stage, env)
        if problem:
            log.warning("rejected stage output for job %s (stage %s): %s", env.job_id, env.stage_id, problem)
            return False
        db.execute(insert(ScanStageOutput).values(stage_id=stage_id, tenant_id=tenant_id, scan_id=scan_id, head=[],
                                                  tail=[]).on_conflict_do_nothing(index_elements=["stage_id"]))
        row = db.get(ScanStageOutput, stage_id, with_for_update=True, populate_existing=True)
        assert row is not None
        if chunk.seq <= row.last_seq:  # a duplicate or an older chunk
            return True
        room = stagelog.HEAD - len(row.head)
        if room > 0 and chunk.head:
            row.head = row.head + _clean([list(x) for x in chunk.head], 0)[:room]
        if chunk.tail is not None:
            row.tail = _clean([list(x) for x in chunk.tail], stagelog.TAIL)
        row.total = max(row.total, chunk.total)
        row.omitted = chunk.omitted
        row.last_seq, row.final = chunk.seq, row.final or chunk.final
        db.commit()
    return True


def read(db: Session, stage: ScanStage) -> dict[str, Any]:
    row = db.get(ScanStageOutput, stage.id)
    running = stage.status == StageStatus.RUNNING
    if row is None:
        return {"head": [], "tail": [], "total": 0, "omitted": 0, "final": False, "running": running,
                "updated_at": None}
    return {"head": row.head, "tail": row.tail, "total": row.total, "omitted": row.omitted, "final": row.final,
            "running": running, "updated_at": row.updated_at}


def as_text(label: str, out: dict[str, Any]) -> str:
    def fmt(line: list[Any]) -> str:
        t, level, text = line
        return f"+{float(t):8.1f}s  {level.upper():7}  {text}"

    lines = [f"# {label}", *(fmt(x) for x in out["head"])]
    if out["omitted"]:
        lines.append(f"... {out['omitted']} line(s) not kept ...")
    lines += [fmt(x) for x in out["tail"]]
    return "\n".join(lines) + "\n"
