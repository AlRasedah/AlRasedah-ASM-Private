from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import Paging, Principal, get_db, require
from app.auth.permissions import Permission
from app.core.errors import NotFound, ValidationFailed
from app.models import Organization, Report
from app.models.enums import JobStatus, ReportFormat, ReportType
from app.reporting.service import CSV_TYPES, EXT, TITLES
from app.schemas.common import ORM, Input, Page, paginate
from app.services import audit
from app.services.audit import Action
from app.services.storage import get_store
from app.workers import dispatch

router = APIRouter(prefix="/reports", tags=["reports"])


class ReportCreate(Input):
    report_type: ReportType
    report_format: ReportFormat = ReportFormat.HTML
    organization_id: uuid.UUID | None = None
    days: int = Field(default=30, ge=1, le=365)
    title: str | None = Field(default=None, max_length=200)
    classification: str | None = Field(default=None, max_length=64)


class ReportOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    report_type: ReportType
    report_format: ReportFormat
    title: str
    status: JobStatus
    size: int | None
    error: str | None
    parameters: dict[str, Any]
    created_at: datetime
    completed_at: datetime | None


@router.get("", response_model=Page[ReportOut])
def list_reports(paging: Paging = Depends(), _: Principal = Depends(require(Permission.REPORTS_READ)),
                 db: Session = Depends(get_db)) -> Page:
    rows, total = paginate(db, select(Report).order_by(Report.created_at.desc()), paging.page, paging.page_size)
    return Page(items=[ReportOut.model_validate(r) for r in rows], total=total, page=paging.page,
                page_size=paging.page_size)


@router.post("", response_model=ReportOut, status_code=201)
def create_report(body: ReportCreate, principal: Principal = Depends(require(Permission.REPORTS_CREATE)),
                  db: Session = Depends(get_db)) -> Report:
    if body.report_format == ReportFormat.CSV and body.report_type not in CSV_TYPES:
        raise ValidationFailed("CSV is available for inventory, vulnerability, change and risk-trend reports")
    if body.organization_id and db.get(Organization, body.organization_id) is None:
        raise NotFound("Organization not found")
    r = Report(tenant_id=principal.require_tenant(), organization_id=body.organization_id,
               report_type=body.report_type, report_format=body.report_format,
               title=body.title or TITLES[body.report_type], requested_by=principal.user_id,
               parameters={"days": body.days, "title": body.title, "classification": body.classification},
               status=JobStatus.PENDING)
    db.add(r)
    db.commit()
    dispatch.generate_report(r.tenant_id, r.id)
    db.refresh(r)
    return r


def _get(db: Session, report_id: uuid.UUID) -> Report:
    r = db.get(Report, report_id)
    if r is None:
        raise NotFound("Report not found")
    return r


@router.get("/{report_id}", response_model=ReportOut)
def get_report(report_id: uuid.UUID, _: Principal = Depends(require(Permission.REPORTS_READ)),
               db: Session = Depends(get_db)) -> Report:
    return _get(db, report_id)


@router.get("/{report_id}/download")
def download(report_id: uuid.UUID, _: Principal = Depends(require(Permission.REPORTS_READ)),
             db: Session = Depends(get_db)) -> Response:
    r = _get(db, report_id)
    if r.status != JobStatus.COMPLETED or not r.storage_key:
        raise ValidationFailed("The report is not ready")
    data = get_store().get(r.storage_key)
    ext, ctype = EXT[r.report_format]
    audit.record(db, Action.REPORT_DOWNLOADED, object_type="report", object_id=r.id)
    db.commit()
    disposition = "inline" if r.report_format == ReportFormat.HTML else "attachment"
    headers = {"Content-Disposition": f'{disposition}; filename="{r.report_type.value}-{r.created_at:%Y%m%d}.{ext}"'}
    if r.report_format == ReportFormat.HTML:
        # Reports are self-contained; lock them down when rendered in the browser.
        headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; sandbox"
    return Response(data, media_type=ctype, headers=headers)
