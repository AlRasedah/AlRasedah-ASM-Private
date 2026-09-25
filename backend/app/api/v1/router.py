from fastapi import APIRouter

from . import (
    assets,
    auth,
    dashboard,
    diagnostics,
    events,
    exposure,
    findings,
    integrations,
    organizations,
    reports,
    scans,
    scopes,
    screenshots,
    settings,
    setup,
    tenants,
    threats,
    users,
)

api_router = APIRouter()
for module in (auth, organizations, scopes, assets, findings, scans, events, dashboard, reports, integrations, users,
               tenants, settings, threats, screenshots, exposure, diagnostics,
               setup):
    api_router.include_router(module.router)
