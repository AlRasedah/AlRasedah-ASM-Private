"""External exposure map: a bounded neighbourhood of observed relationships."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import Principal, get_db, require
from app.auth.permissions import Permission
from app.exposure.graph import MapParams, cached_build

router = APIRouter(tags=["exposure"])


@router.get("/exposure-map")
def exposure_map(
    organization_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    expand: uuid.UUID | None = Query(None, description="Return one node's neighbours (progressive expansion)"),
    depth: int = Query(2, ge=1, le=4),
    max_nodes: int = Query(150, ge=10, le=300),
    per_node: int = Query(25, ge=5, le=100),
    include_inactive: bool = False,
    include_findings: bool = True,
    include_unverified: bool = False,
    include_context: bool = False,
    principal: Principal = Depends(require(Permission.ASSETS_READ)),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    params = MapParams(organization_id=organization_id, asset_id=asset_id, expand=expand, depth=depth,
                       max_nodes=max_nodes, per_node=per_node, include_inactive=include_inactive,
                       include_findings=include_findings, include_unverified=include_unverified,
                       include_context=include_context)
    return cached_build(db, params, tenant_id=principal.require_tenant(), role=principal.role.value,
                        findings_allowed=principal.can(Permission.FINDINGS_READ))
