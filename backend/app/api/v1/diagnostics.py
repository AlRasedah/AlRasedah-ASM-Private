"""Diagnostics & Support (docs/DIAGNOSTICS.md).

Tenant routes run in the caller's tenant session: RLS confines every query to that tenant.
Platform routes need ``platform:diagnostics`` (platform administrators only) and run in a
system session. Every list is paginated and bounded on the server.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, get_system_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound
from app.diagnostics import bundles, views
from app.models import SupportBundle, Tenant
from app.observability import health
from app.schemas.common import Input
from app.workers import dispatch

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])


# ------------------------------------------------------------------ tenant
@router.get("/tenant/overview")
def tenant_overview(principal: Principal = Depends(require(Permission.DIAGNOSTICS_READ)),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    tenant = db.get(Tenant, principal.require_tenant())
    if tenant is None:
        raise NotFound("Tenant not found")
    return views.tenant_overview(db, tenant)


@router.get("/tenant/scans")
def tenant_scans(page: int = Query(1, ge=1, le=views.MAX_PAGE), status: str | None = Query(None, max_length=16),
                 _: Principal = Depends(require(Permission.DIAGNOSTICS_READ)),
                 db: Session = Depends(get_db)) -> dict[str, Any]:
    return views.scans(db, page, status)


@router.get("/tenant/events")
def tenant_events(page: int = Query(1, ge=1, le=views.MAX_PAGE),
                  _: Principal = Depends(require(Permission.DIAGNOSTICS_READ)),
                  db: Session = Depends(get_db)) -> dict[str, Any]:
    return views.tenant_events(db, page)


# ---------------------------------------------------------------- platform
@router.get("/platform/health")
def platform_health(_: Principal = Depends(require(Permission.PLATFORM_DIAGNOSTICS)),
                    db: Session = Depends(get_system_db)) -> dict[str, Any]:
    return health.collect_platform(db)


@router.get("/platform/events")
def platform_events(page: int = Query(1, ge=1, le=views.MAX_PAGE),
                    level: Literal["WARNING", "ERROR", "CRITICAL"] | None = None,
                    service: str | None = Query(None, max_length=32), error_code: str | None = Query(None, max_length=32),
                    tenant_id: uuid.UUID | None = None, since: datetime | None = None, until: datetime | None = None,
                    _: Principal = Depends(require(Permission.PLATFORM_DIAGNOSTICS)),
                    db: Session = Depends(get_system_db)) -> dict[str, Any]:
    return views.platform_events(db, page, level, service, error_code, tenant_id, since, until)


@router.get("/platform/scans")
def platform_scans(page: int = Query(1, ge=1, le=views.MAX_PAGE), status: str | None = Query(None, max_length=16),
                   tenant_id: uuid.UUID | None = None,
                   _: Principal = Depends(require(Permission.PLATFORM_DIAGNOSTICS)),
                   db: Session = Depends(get_system_db)) -> dict[str, Any]:
    return views.scans(db, page, status, tenant_id, platform=True)


# ----------------------------------------------------------------- bundles
class BundleRequest(Input):
    scope: Literal["tenant", "platform"] = "tenant"
    window_start: datetime | None = None
    window_end: datetime | None = None
    scan_ids: list[uuid.UUID] = Field(default_factory=list, max_length=bundles.MAX_SCANS)


def _session_for(scope: str, principal: Principal) -> Session:
    """The session a bundle request runs in: the caller's tenant session, or — for a platform
    bundle, which only ``platform:diagnostics`` may touch — a system session."""
    from app.core.errors import Forbidden
    from app.db.session import new_session, system_session

    if scope == "platform":
        if not principal.can(Permission.PLATFORM_DIAGNOSTICS):
            raise Forbidden("Missing permission: platform:diagnostics")
        return system_session()
    return new_session(principal.require_tenant(), user_id=principal.user_id)


def _out(b: SupportBundle) -> dict[str, Any]:
    return {"id": str(b.id), "scope": b.scope, "status": b.status, "progress": b.progress, "error": b.error,
            "window_start": b.window_start.isoformat(), "window_end": b.window_end.isoformat(),
            "scan_ids": [str(s) for s in b.scan_ids], "size": b.size, "sha256": b.sha256, "filename": b.filename,
            "contents": b.manifest or None, "created_at": b.created_at.isoformat() if b.created_at else None,
            "finished_at": b.finished_at.isoformat() if b.finished_at else None,
            "expires_at": b.expires_at.isoformat()}


@router.post("/bundles/preview")
def preview_bundle(body: BundleRequest,
                   principal: Principal = Depends(require(Permission.SUPPORT_BUNDLES))) -> dict[str, Any]:
    with _session_for(body.scope, principal) as db:
        return bundles.preview(db, body.scope, body.window_start, body.window_end, body.scan_ids)


@router.post("/bundles", status_code=202)
def create_bundle(body: BundleRequest,
                  principal: Principal = Depends(require(Permission.SUPPORT_BUNDLES))) -> dict[str, Any]:
    with _session_for(body.scope, principal) as db:
        tenant_id = None if body.scope == "platform" else principal.require_tenant()
        b = bundles.create(db, scope=body.scope, tenant_id=tenant_id, user_id=principal.user_id,
                           start=body.window_start, end=body.window_end, scan_ids=body.scan_ids)
        db.commit()
        out = _out(b)
    dispatch.generate_support_bundle(uuid.UUID(out["id"]), tenant_id)
    with _session_for(body.scope, principal) as db:
        return _out(bundles.get(db, uuid.UUID(out["id"]), body.scope))


@router.get("/bundles")
def list_bundles(scope: Literal["tenant", "platform"] = "tenant",
                 principal: Principal = Depends(require(Permission.SUPPORT_BUNDLES))) -> list[dict[str, Any]]:
    with _session_for(scope, principal) as db:
        stmt = select(SupportBundle).where(SupportBundle.scope == scope)
        stmt = stmt.where(SupportBundle.tenant_id.is_(None)) if scope == "platform" else stmt
        return [_out(b) for b in db.execute(stmt.order_by(SupportBundle.created_at.desc()).limit(50)).scalars()]


@router.get("/bundles/{bundle_id}")
def get_bundle(bundle_id: uuid.UUID, scope: Literal["tenant", "platform"] = "tenant",
               principal: Principal = Depends(require(Permission.SUPPORT_BUNDLES))) -> dict[str, Any]:
    with _session_for(scope, principal) as db:
        return _out(bundles.get(db, bundle_id, scope))


@router.get("/bundles/{bundle_id}/download")
def download_bundle(bundle_id: uuid.UUID, scope: Literal["tenant", "platform"] = "tenant",
                    principal: Principal = Depends(require(Permission.SUPPORT_BUNDLES))) -> Response:
    with _session_for(scope, principal) as db:
        b = bundles.get(db, bundle_id, scope)
        data = bundles.download(db, b, principal.user_id)
        name = b.filename or f"exteriq-support-{bundle_id}.zip"
        db.commit()
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"',
                             "X-Content-SHA256": b.sha256 or ""})


@router.delete("/bundles/{bundle_id}", status_code=204)
def delete_bundle(bundle_id: uuid.UUID, scope: Literal["tenant", "platform"] = "tenant",
                  principal: Principal = Depends(require(Permission.SUPPORT_BUNDLES))) -> Response:
    with _session_for(scope, principal) as db:
        b = bundles.get(db, bundle_id, scope)
        bundles.delete(db, b, principal.user_id)
        db.commit()
    return Response(status_code=204)
