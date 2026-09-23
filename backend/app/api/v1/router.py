from fastapi import APIRouter

from . import (
    assets,
    auth,
    dashboard,
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
    tenants,
    threats,
    users,
)

api_router = APIRouter()
for module in (auth, organizations, scopes, assets, findings, scans, events, dashboard, reports, integrations, users,
               tenants, settings, threats, screenshots, exposure):
    api_router.include_router(module.router)
