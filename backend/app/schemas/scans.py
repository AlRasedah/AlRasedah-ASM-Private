from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from croniter import croniter
from pydantic import BaseModel, Field, field_validator

from app.models.enums import DecisionResult, ScanStatus, ScanTrigger, StageStatus, StageType

from .common import ORM, Input


class StageOut(ORM):
    id: uuid.UUID
    position: int
    stage_type: StageType
    label: str = ""
    engine: str
    status: StageStatus
    is_active: bool
    target_count: int
    rejected_count: int
    observation_count: int
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    stats: dict[str, Any]
    time_limit_seconds: int | None = None


class ScanOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID
    profile_id: uuid.UUID | None
    profile_name: str
    status: ScanStatus
    trigger: ScanTrigger
    requested_by: uuid.UUID | None
    is_baseline: bool
    target_override: list[str] | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    stats: dict[str, Any]
    error: str | None


class ScanDetail(ScanOut):
    stages: list[StageOut]


class ScanCreate(Input):
    organization_id: uuid.UUID
    profile_id: uuid.UUID
    targets: list[str] | None = Field(default=None, max_length=1000)


class DecisionOut(ORM):
    id: int
    stage_id: uuid.UUID | None
    target: str
    decision: DecisionResult
    reason: str
    active: bool
    created_at: datetime


class ArtifactOut(ORM):
    id: uuid.UUID
    stage_id: uuid.UUID | None
    name: str
    size: int
    sha256: str
    truncated: bool
    created_at: datetime
    expires_at: datetime | None


class ProfileStage(BaseModel):
    stage: StageType
    engine: str
    config: dict[str, Any] = {}
    enabled: bool = True
    optional: bool = False
    active: bool = False
    label: str | None = None


class ProfileOut(ORM):
    id: uuid.UUID
    slug: str
    name: str
    description: str | None
    stages: list[ProfileStage]
    is_builtin: bool
    is_active_scanning: bool
    retain_raw_output: bool
    tenant_id: uuid.UUID | None


class ProfileCreate(Input):
    name: str = Field(min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    stages: list[dict[str, Any]] = Field(min_length=1, max_length=20)
    retain_raw_output: bool = False


class ProfileUpdate(Input):
    name: str | None = Field(default=None, min_length=2, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    stages: list[dict[str, Any]] | None = Field(default=None, min_length=1, max_length=20)
    retain_raw_output: bool | None = None


class EngineOut(BaseModel):
    name: str
    display_name: str
    stage_types: list[str]
    active: bool
    credential_providers: list[str]
    config_schema: dict[str, Any]


class ScheduleOut(ORM):
    id: uuid.UUID
    organization_id: uuid.UUID
    profile_id: uuid.UUID
    name: str
    cron: str
    timezone: str
    enabled: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_scan_id: uuid.UUID | None


def _valid_cron(v: str) -> str:
    if not croniter.is_valid(v) or len(v.split()) != 5:
        raise ValueError("cron must be a standard 5-field expression, e.g. '0 2 * * *'")
    return v


class ScheduleCreate(Input):
    organization_id: uuid.UUID
    profile_id: uuid.UUID
    name: str = Field(min_length=1, max_length=128)
    cron: str = Field(max_length=64)
    timezone: str = Field(default="Asia/Riyadh", max_length=64)
    enabled: bool = True

    @field_validator("cron")
    @classmethod
    def _cron(cls, v: str) -> str:
        return _valid_cron(v)


class ScheduleUpdate(Input):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    cron: str | None = Field(default=None, max_length=64)
    timezone: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None
    profile_id: uuid.UUID | None = None

    @field_validator("cron")
    @classmethod
    def _cron(cls, v: str | None) -> str | None:
        return _valid_cron(v) if v is not None else v
