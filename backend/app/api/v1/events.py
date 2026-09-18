from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from pydantic import Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.api.deps import Paging, Principal, get_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound
from app.models import AssetEvent
from app.models.enums import EventType, Severity
from app.schemas.assets import EventOut
from app.schemas.common import Input, Page, paginate
from app.services import audit
from app.services.audit import Action

router = APIRouter(prefix="/events", tags=["events"])
_SEV_ORDER = [s.value for s in Severity]


class AckRequest(Input):
    event_ids: list[uuid.UUID] = Field(min_length=1, max_length=1000)


@router.get("", response_model=Page[EventOut])
def list_events(
    organization_id: uuid.UUID | None = None,
    event_type: list[EventType] = Query(default=[]),
    min_severity: Severity | None = None,
    asset_id: uuid.UUID | None = None,
    scan_id: uuid.UUID | None = None,
    acknowledged: bool | None = None,
    include_baseline: bool = False,
    since: datetime | None = None,
    until: datetime | None = None,
    paging: Paging = Depends(),
    _: Principal = Depends(require(Permission.EVENTS_READ)),
    db: Session = Depends(get_db),
) -> Page[EventOut]:
    stmt = select(AssetEvent)
    if organization_id:
        stmt = stmt.where(AssetEvent.organization_id == organization_id)
    if event_type:
        stmt = stmt.where(AssetEvent.event_type.in_([e.value for e in event_type]))
    if min_severity:
        stmt = stmt.where(AssetEvent.severity.in_(_SEV_ORDER[_SEV_ORDER.index(min_severity.value):]))
    if asset_id:
        stmt = stmt.where(AssetEvent.asset_id == asset_id)
    if scan_id:
        stmt = stmt.where(AssetEvent.scan_id == scan_id)
    if acknowledged is not None:
        stmt = stmt.where(AssetEvent.acknowledged.is_(acknowledged))
    if not include_baseline:
        stmt = stmt.where(AssetEvent.is_baseline.is_(False))
    if since:
        stmt = stmt.where(AssetEvent.occurred_at >= since)
    if until:
        stmt = stmt.where(AssetEvent.occurred_at <= until)
    stmt = stmt.order_by(AssetEvent.occurred_at.desc(), AssetEvent.id)
    rows, total = paginate(db, stmt, paging.page, paging.page_size)
    return Page(items=[EventOut.model_validate(r) for r in rows], total=total, page=paging.page,
                page_size=paging.page_size)


@router.post("/acknowledge", response_model=dict)
def acknowledge(body: AckRequest, principal: Principal = Depends(require(Permission.EVENTS_ACK)),
                db: Session = Depends(get_db)) -> dict:
    res = db.execute(update(AssetEvent).where(AssetEvent.id.in_(body.event_ids), AssetEvent.acknowledged.is_(False))
                     .values(acknowledged=True, acknowledged_by=principal.user_id, acknowledged_at=datetime.now(UTC)))
    audit.record(db, Action.EVENT_ACKNOWLEDGED, object_type="asset_event",
                 new={"count": res.rowcount, "ids": [str(i) for i in body.event_ids[:50]]})
    db.commit()
    return {"acknowledged": res.rowcount}


@router.post("/{event_id}/acknowledge", response_model=EventOut)
def acknowledge_one(event_id: uuid.UUID, principal: Principal = Depends(require(Permission.EVENTS_ACK)),
                    db: Session = Depends(get_db)) -> AssetEvent:
    ev = db.get(AssetEvent, event_id)
    if ev is None:
        raise NotFound("Event not found")
    if not ev.acknowledged:
        ev.acknowledged, ev.acknowledged_by, ev.acknowledged_at = True, principal.user_id, datetime.now(UTC)
        audit.record(db, Action.EVENT_ACKNOWLEDGED, object_type="asset_event", object_id=ev.id)
        db.commit()
    return ev
