from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, require
from app.auth.permissions import Permission
from app.services import dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(organization_id: uuid.UUID | None = None, _: Principal = Depends(require(Permission.ASSETS_READ)),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    return dashboard.summary(db, organization_id)


@router.get("/trends")
def trends(organization_id: uuid.UUID | None = None, days: int = Query(30, ge=7, le=365),
           _: Principal = Depends(require(Permission.ASSETS_READ)), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return dashboard.trends(db, organization_id, days)
