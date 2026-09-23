"""Platform configuration (12-factor, environment driven, prefix ``ASM_``)."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

PLACEHOLDER = "CHANGE_ME"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="ASM_", env_file=".env", extra="ignore")

    # --- general ---------------------------------------------------------
    env: Literal["development", "production", "test"] = "development"
    app_name: str = "Exteriq ASM"
    public_url: str = "http://localhost:8080"
    log_level: str = "INFO"
    log_json: bool = True
    # Region label recorded on tenants; informational (e.g. "sa-riyadh-1").
    data_region: str = "sa-central"

    # --- secrets ---------------------------------------------------------
    secret_key: SecretStr = SecretStr(PLACEHOLDER)
    # Comma separated "key_id:base64url(32 bytes)"; the first key encrypts,
    # all keys decrypt (supports rotation).
    encryption_keys: SecretStr = SecretStr(PLACEHOLDER)
    scanner_transport_key: SecretStr = SecretStr(PLACEHOLDER)

    # --- data stores -----------------------------------------------------
    database_url: str = "postgresql+psycopg://asm:asm@localhost:5432/asm"
    db_pool_size: int = 10
    db_max_overflow: int = 20
    db_echo: bool = False
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str | None = None
    celery_result_backend: str | None = None

    # --- auth ------------------------------------------------------------
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    session_absolute_ttl_days: int = 30
    # Sign a session out after this long without the user doing anything. The browser
    # enforces it on real interaction (pointer, keyboard, tab focus) because an open tab
    # polls by itself; the server enforces it on `last_used_at` so a client that does not
    # cooperate cannot keep a session alive. 0 disables it.
    session_idle_ttl_minutes: int = 30
    mfa_challenge_ttl_minutes: int = 5
    password_reset_ttl_minutes: int = 30
    password_min_length: int = 12
    cookie_secure: bool = True
    cookie_domain: str | None = None
    account_lockout_threshold: int = 5
    account_lockout_minutes: int = 15
    login_rate_limit_per_minute: int = 10
    api_rate_limit_per_minute: int = 1200
    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # --- bootstrap -------------------------------------------------------
    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: SecretStr | None = None
    bootstrap_tenant_name: str = "Default"

    # --- email (platform mail: password resets, email notifications) -----
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from: str = "Exteriq ASM <asm@localhost>"
    smtp_starttls: bool = True
    smtp_ssl: bool = False
    smtp_timeout_seconds: int = 20

    # --- object storage --------------------------------------------------
    storage_backend: Literal["local", "s3"] = "local"
    storage_local_path: str = "/data/storage"
    s3_endpoint_url: str | None = None
    s3_bucket: str = "asm"
    s3_region: str | None = None
    s3_access_key: str | None = None
    s3_secret_key: SecretStr | None = None

    # --- scanning --------------------------------------------------------
    # "celery": sensors run in dedicated sensor worker containers (production).
    # "inline": sensors run in the calling process (development/tests only).
    sensor_mode: Literal["celery", "inline"] = "celery"
    sensor_queue_prefix: str = "scanners"
    # Worker pools whose result queues (results.<pool>) the result consumer serves.
    worker_pools: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["default"])
    # A worker pool is a trust domain: its workers hold that pool's broker credentials
    # and transport key, so a compromised scanner reaches every job in the pool. With
    # "per_tenant" (the default) the platform refuses to dispatch a tenant's scan to a
    # pool another tenant also uses — mutually untrusted customers must not share
    # scanners. "shared" permits it, for a single-tenant or in-house deployment where
    # every tenant is the same organization.
    scanner_isolation: Literal["per_tenant", "shared"] = "per_tenant"
    max_concurrent_scans_global: int = 10
    scanner_max_rate: int = 2000
    stage_timeout_seconds: int = 4 * 3600
    # Redis redelivers an unacknowledged message after this long, so it must exceed
    # the longest sensor job (stage timeout + time-limit grace). Every app sharing
    # the broker (platform and sensor workers) must use the same value.
    broker_visibility_timeout: int = 6 * 3600
    max_targets_per_stage: int = 50_000
    # Lab/testing only: accept private/reserved addresses in scope entries and as
    # active-scan destinations (including addresses in-scope hostnames resolve to).
    allow_non_public_scope: bool = False
    # Platform floor for DNS ownership verification: when true every tenant must
    # verify domain scope before active scanning, whatever its own setting says.
    require_scope_verification: bool = False
    raw_output_retention_days: int = 30
    observation_retention_days: int = 365

    # --- integrations ----------------------------------------------------
    allow_private_webhook_targets: bool = True
    webhook_timeout_seconds: int = 15

    # --- vulnerability intelligence (free/public feeds, overridable for mirrors)
    intel_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    intel_epss_api_url: str = "https://api.first.org/data/v1/epss"
    intel_nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    intel_refresh_enabled: bool = True

    @field_validator("cors_origins", "worker_pools", mode="before")
    @classmethod
    def _split_list(cls, v: object) -> object:
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @field_validator("worker_pools")
    @classmethod
    def _valid_pools(cls, v: list[str]) -> list[str]:
        from asm_sensors.jobs import validate_pool

        return [validate_pool(p) for p in v] or ["default"]

    @model_validator(mode="after")
    def _visibility_covers_jobs(self) -> Settings:
        # Sensor tasks run for up to stage_timeout + 300s (hard time limit).
        if self.broker_visibility_timeout < self.stage_timeout_seconds + 900:
            raise ValueError("ASM_BROKER_VISIBILITY_TIMEOUT must exceed ASM_STAGE_TIMEOUT_SECONDS by at least 900 "
                             "seconds, or long sensor jobs are redelivered while still running")
        return self

    @model_validator(mode="after")
    def _refuse_placeholders_in_production(self) -> Settings:
        if self.env == "production":
            for name in ("secret_key", "encryption_keys", "scanner_transport_key"):
                val = getattr(self, name).get_secret_value()
                if not val or PLACEHOLDER in val:
                    raise ValueError(f"ASM_{name.upper()} must be set to a generated value in production")
            if len(self.secret_key.get_secret_value()) < 32:
                raise ValueError("ASM_SECRET_KEY must be at least 32 characters")
        return self

    @property
    def broker_url(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def result_backend(self) -> str:
        return self.celery_result_backend or self.broker_url

    @property
    def is_production(self) -> bool:
        return self.env == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
