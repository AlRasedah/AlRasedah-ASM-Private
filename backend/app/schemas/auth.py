from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import Role

from .common import ORM, Email, Input


class LoginRequest(Input):
    email: Email
    password: str = Field(min_length=1, max_length=256)


class MfaVerifyRequest(Input):
    mfa_token: str = Field(max_length=2048)
    code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


class TenantRef(ORM):
    id: uuid.UUID
    name: str
    slug: str


class UserOut(ORM):
    id: uuid.UUID
    email: str
    full_name: str | None
    is_platform_admin: bool
    mfa_enabled: bool


class TokenResponse(BaseModel):
    access_token: str | None = None
    token_type: str = "bearer"
    expires_in: int | None = None
    mfa_required: bool = False
    mfa_token: str | None = None


class Membership(BaseModel):
    tenant: TenantRef
    role: Role


class MeResponse(BaseModel):
    user: UserOut
    tenant: TenantRef | None
    role: Role
    permissions: list[str]
    memberships: list[Membership]


class SwitchTenantRequest(Input):
    tenant_id: uuid.UUID


class ForgotPasswordRequest(Input):
    email: Email


class ResetPasswordRequest(Input):
    token: str = Field(min_length=16, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(Input):
    current_password: str = Field(max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


class MfaSetupRequest(Input):
    # Re-authentication: enrolling an authenticator requires the current password.
    password: str = Field(max_length=256)


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class MfaCodeRequest(Input):
    code: str = Field(pattern=r"^\d{6,8}$")


class MfaDisableRequest(Input):
    password: str = Field(max_length=256)
    code: str = Field(pattern=r"^\d{6,8}$")


class ApiTokenCreate(Input):
    name: str = Field(min_length=1, max_length=128)
    role: Role = Role.VIEWER
    expires_at: datetime | None = None


class ApiTokenOut(ORM):
    id: uuid.UUID
    name: str
    token_prefix: str
    role: Role
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime


class ApiTokenCreated(ApiTokenOut):
    token: str
