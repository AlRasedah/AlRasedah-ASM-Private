"""Schemas for tenants, users, organizations and scope."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.models.enums import Role, ScopeEntryType, TenantStatus, VerificationStatus

from .common import ORM, Email, Input


# ------------------------------------------------------------------ tenants
class PlanOut(ORM):
    id: uuid.UUID
    code: str
    name: str
    max_organizations: int | None
    max_assets: int | None
    max_users: int | None
    max_scans_per_day: int | None
    max_concurrent_scans: int
    allow_active_scanning: bool


class TenantOut(ORM):
    id: uuid.UUID
    name: str
    slug: str
    status: TenantStatus
    worker_pool: str
    data_region: str | None
    plan: PlanOut | None
    created_at: datetime


class TenantCreate(Input):
    name: str = Field(min_length=2, max_length=200)
    slug: str | None = Field(default=None, max_length=100, pattern=r"^[a-z0-9-]+$")
    plan_code: str | None = None
    admin_email: Email | None = None
    admin_name: str | None = Field(default=None, max_length=200)


class TenantCreated(TenantOut):
    admin_password_reset_token: str | None = None


class TenantUpdate(Input):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    status: TenantStatus | None = None
    plan_code: str | None = None
    worker_pool: str | None = Field(default=None, pattern=r"^[a-z0-9-]{1,64}$")


# -------------------------------------------------------------------- users
class MemberOut(BaseModel):
    user_id: uuid.UUID
    email: str
    full_name: str | None
    role: Role
    is_active: bool
    mfa_enabled: bool
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(Input):
    email: Email
    full_name: str | None = Field(default=None, max_length=200)
    role: Role = Role.VIEWER
    password: str | None = Field(default=None, max_length=256)


class UserCreated(MemberOut):
    password_reset_token: str | None = None


class UserUpdate(Input):
    full_name: str | None = Field(default=None, max_length=200)
    role: Role | None = None
    is_active: bool | None = None


# ------------------------------------------------------------ organizations
class OrganizationOut(ORM):
    id: uuid.UUID
    name: str
    description: str | None
    industry: str | None
    settings: dict[str, Any]
    is_active: bool
    baseline_completed_at: datetime | None
    created_at: datetime


class OrganizationSummary(OrganizationOut):
    scope_entries: int = 0
    assets: int = 0
    open_findings: int = 0
    risk_score: int = 0
    last_scan_at: datetime | None = None


class OrganizationCreate(Input):
    name: str = Field(min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    industry: str | None = Field(default=None, max_length=100)


class OrgSettingsIn(Input):
    derived_ip_scanning: bool | None = None
    skip_cdn_ips: bool | None = None


class OrganizationUpdate(Input):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    industry: str | None = Field(default=None, max_length=100)
    is_active: bool | None = None
    settings: OrgSettingsIn | None = None


# -------------------------------------------------------------------- scope
class ScopeEntryOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID
    entry_type: ScopeEntryType
    value: str
    include_subdomains: bool
    is_exclusion: bool
    allow_active_scanning: bool
    verification_status: VerificationStatus
    verified_at: datetime | None
    notes: str | None
    created_at: datetime


class ScopeEntryCreate(Input):
    organization_id: uuid.UUID
    entry_type: ScopeEntryType
    value: str = Field(min_length=1, max_length=255)
    include_subdomains: bool = True
    is_exclusion: bool = False
    allow_active_scanning: bool = True
    notes: str | None = Field(default=None, max_length=2000)


class ScopeEntryBulkCreate(Input):
    organization_id: uuid.UUID
    entries: list[str] = Field(min_length=1, max_length=500)
    is_exclusion: bool = False
    allow_active_scanning: bool = True


class ScopeEntryUpdate(Input):
    include_subdomains: bool | None = None
    allow_active_scanning: bool | None = None
    notes: str | None = Field(default=None, max_length=2000)


class ScopeCheckRequest(Input):
    organization_id: uuid.UUID
    target: str = Field(min_length=1, max_length=2048)
    active: bool = True


class ScopeCheckResponse(BaseModel):
    target: str
    allowed: bool
    reason: str
    scope_status: str


class VerificationInstructions(BaseModel):
    record_type: str
    name: str
    value: str
    status: VerificationStatus
