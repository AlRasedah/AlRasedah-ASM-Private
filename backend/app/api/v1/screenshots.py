"""Website screenshots: per-endpoint captures, the tenant's status, and the platform policy.

Images are served only through ``/assets/{asset_id}/screenshots/{capture_id}/image``:
the capture is looked up in the caller's tenant session (RLS), must belong to that
asset, and its storage key is the one the platform derived — callers never name a key.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, get_system_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound
from app.models import Asset, ScreenshotCapture, Tenant
from app.models.enums import ScreenshotStatus
from app.schemas.common import Input
from app.screenshots import service as shots
from app.services.storage import get_store
from app.workers import dispatch

router = APIRouter(tags=["screenshots"])


class CaptureOut(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    status: ScreenshotStatus
    trigger: str
    error: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    captured_at: datetime | None
    final_url: str | None
    page_title: str | None
    http_status: int | None
    size: int | None
    width: int | None
    height: int | None
    sha256: str | None
    has_image: bool


def _out(c: ScreenshotCapture) -> CaptureOut:
    return CaptureOut(id=c.id, asset_id=c.asset_id, status=c.status, trigger=c.trigger, error=c.error,
                      created_at=c.created_at, started_at=c.started_at, finished_at=c.finished_at,
                      captured_at=c.captured_at, final_url=c.final_url, page_title=c.page_title,
                      http_status=c.http_status, size=c.size, width=c.width, height=c.height, sha256=c.sha256,
                      has_image=bool(c.storage_key) and c.status == ScreenshotStatus.SUCCEEDED)


class AssetScreenshots(BaseModel):
    status: dict[str, Any]
    latest: CaptureOut | None
    captures: list[CaptureOut]


def _asset(db: Session, asset_id: uuid.UUID) -> Asset:
    a = db.get(Asset, asset_id)
    if a is None:
        raise NotFound("Asset not found")
    return a


@router.get("/screenshots/status")
def screenshot_status(principal: Principal = Depends(require(Permission.ASSETS_READ)),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    tenant = db.get(Tenant, principal.require_tenant())
    assert tenant is not None
    return shots.status_for(db, tenant)


@router.get("/assets/{asset_id}/screenshots", response_model=AssetScreenshots)
def list_captures(asset_id: uuid.UUID, principal: Principal = Depends(require(Permission.ASSETS_READ)),
                  db: Session = Depends(get_db)) -> AssetScreenshots:
    _asset(db, asset_id)
    tenant = db.get(Tenant, principal.require_tenant())
    assert tenant is not None
    rows = list(db.execute(select(ScreenshotCapture).where(ScreenshotCapture.asset_id == asset_id)
                           .order_by(ScreenshotCapture.created_at.desc()).limit(10)).scalars())
    latest = db.execute(select(ScreenshotCapture).where(
        ScreenshotCapture.asset_id == asset_id, ScreenshotCapture.status == ScreenshotStatus.SUCCEEDED)
        .order_by(ScreenshotCapture.captured_at.desc()).limit(1)).scalar_one_or_none()
    return AssetScreenshots(status=shots.status_for(db, tenant), latest=_out(latest) if latest else None,
                            captures=[_out(c) for c in rows])


@router.post("/assets/{asset_id}/screenshots", response_model=CaptureOut, status_code=202)
def request_capture(asset_id: uuid.UUID, principal: Principal = Depends(require(Permission.SCANS_RUN)),
                    db: Session = Depends(get_db)) -> CaptureOut:
    c, created = shots.request_capture(db, tenant_id=principal.require_tenant(), asset_id=asset_id,
                                       user_id=principal.user_id)
    db.commit()
    if created:
        dispatch.dispatch_screenshots()
    db.refresh(c)
    return _out(c)


@router.get("/assets/{asset_id}/screenshots/{capture_id}/image")
def capture_image(asset_id: uuid.UUID, capture_id: uuid.UUID,
                  _: Principal = Depends(require(Permission.ASSETS_READ)), db: Session = Depends(get_db)) -> Response:
    _asset(db, asset_id)
    c = db.get(ScreenshotCapture, capture_id)
    if c is None or c.asset_id != asset_id or c.status != ScreenshotStatus.SUCCEEDED or not c.storage_key:
        raise NotFound("Screenshot not found")
    try:
        data = get_store().get(c.storage_key)
    except (OSError, ValueError) as exc:
        raise NotFound("Screenshot not found") from exc
    return Response(data, media_type="image/png", headers={
        "Content-Disposition": f'inline; filename="screenshot-{c.id}.png"', "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store"})


@router.post("/assets/{asset_id}/screenshots/{capture_id}/cancel", response_model=CaptureOut)
def cancel_capture(asset_id: uuid.UUID, capture_id: uuid.UUID,
                   _: Principal = Depends(require(Permission.SCANS_RUN)), db: Session = Depends(get_db)) -> CaptureOut:
    c, task = shots.cancel_capture(db, asset_id, capture_id)
    db.commit()
    if task:
        dispatch.revoke([task])
    return _out(c)


@router.delete("/assets/{asset_id}/screenshots/{capture_id}", status_code=204)
def delete_capture(asset_id: uuid.UUID, capture_id: uuid.UUID,
                   _: Principal = Depends(require(Permission.ASSETS_WRITE)), db: Session = Depends(get_db)) -> Response:
    shots.delete_capture(db, asset_id, capture_id)
    db.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------------ platform
class PolicyIn(Input):
    available: bool | None = None
    max_concurrent: int | None = Field(default=None, ge=1, le=8)
    per_tenant_daily: int | None = Field(default=None, ge=1, le=5000)
    per_tenant_queued: int | None = Field(default=None, ge=1, le=500)
    retention_per_endpoint: int | None = Field(default=None, ge=1, le=10)
    storage_quota_mb: int | None = Field(default=None, ge=10, le=100_000)
    failed_retention_days: int | None = Field(default=None, ge=1, le=365)
    timeout_seconds: int | None = Field(default=None, ge=5, le=90)
    viewport_width: int | None = Field(default=None, ge=320, le=1920)
    viewport_height: int | None = Field(default=None, ge=240, le=1200)
    max_image_kb: int | None = Field(default=None, ge=64, le=5120)


@router.get("/settings/screenshots", tags=["settings"])
def get_policy(_: Principal = Depends(require(Permission.TENANTS_ADMIN))) -> dict[str, Any]:
    return {"policy": shots.policy(), "defaults": shots.DEFAULT_POLICY, "bounds": shots.POLICY_BOUNDS}


@router.put("/settings/screenshots", tags=["settings"])
def put_policy(body: PolicyIn, principal: Principal = Depends(require(Permission.TENANTS_ADMIN)),
               db: Session = Depends(get_system_db)) -> dict[str, Any]:
    pol = shots.set_policy(db, body.model_dump(exclude_none=True), principal.user_id)
    db.commit()
    return {"policy": pol, "defaults": shots.DEFAULT_POLICY, "bounds": shots.POLICY_BOUNDS}
