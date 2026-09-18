"""Role-based access control.

Roles map to permission sets in code today; the ``Permission`` vocabulary is
the extension point for custom roles later (a roles table mapping names to
permission lists) without touching endpoint code.
"""

from __future__ import annotations

from enum import StrEnum

from app.models.enums import Role


class Permission(StrEnum):
    ASSETS_READ = "assets:read"
    ASSETS_WRITE = "assets:write"
    FINDINGS_READ = "findings:read"
    FINDINGS_WRITE = "findings:write"
    FINDINGS_ACCEPT_RISK = "findings:accept_risk"
    EVENTS_READ = "events:read"
    EVENTS_ACK = "events:ack"
    SCANS_READ = "scans:read"
    SCANS_RUN = "scans:run"
    PROFILES_WRITE = "profiles:write"
    SCHEDULES_WRITE = "schedules:write"
    SCOPE_READ = "scope:read"
    SCOPE_WRITE = "scope:write"
    ORGS_READ = "orgs:read"
    ORGS_WRITE = "orgs:write"
    REPORTS_READ = "reports:read"
    REPORTS_CREATE = "reports:create"
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_WRITE = "integrations:write"
    CREDENTIALS_WRITE = "credentials:write"
    USERS_READ = "users:read"
    USERS_WRITE = "users:write"
    SETTINGS_WRITE = "settings:write"
    AUDIT_READ = "audit:read"
    # Platform level
    TENANTS_ADMIN = "tenants:admin"
    INTEL_ADMIN = "intel:admin"


_VIEWER = {
    Permission.ASSETS_READ, Permission.FINDINGS_READ, Permission.EVENTS_READ, Permission.SCANS_READ,
    Permission.SCOPE_READ, Permission.ORGS_READ, Permission.REPORTS_READ,
}
_ANALYST = _VIEWER | {
    Permission.ASSETS_WRITE, Permission.FINDINGS_WRITE, Permission.EVENTS_ACK, Permission.SCANS_RUN,
    Permission.REPORTS_CREATE, Permission.INTEGRATIONS_READ, Permission.USERS_READ,
}
_TENANT_ADMIN = _ANALYST | {
    Permission.FINDINGS_ACCEPT_RISK, Permission.PROFILES_WRITE, Permission.SCHEDULES_WRITE,
    Permission.SCOPE_WRITE, Permission.ORGS_WRITE, Permission.INTEGRATIONS_WRITE, Permission.CREDENTIALS_WRITE,
    Permission.USERS_WRITE, Permission.SETTINGS_WRITE, Permission.AUDIT_READ,
}
_PLATFORM_ADMIN = set(Permission)

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.SECURITY_ANALYST: frozenset(_ANALYST),
    Role.TENANT_ADMIN: frozenset(_TENANT_ADMIN),
    Role.PLATFORM_ADMIN: frozenset(_PLATFORM_ADMIN),
}

ROLE_RANK = {Role.VIEWER: 0, Role.SECURITY_ANALYST: 1, Role.TENANT_ADMIN: 2, Role.PLATFORM_ADMIN: 3}


def permissions_for(role: Role) -> frozenset[Permission]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def can_assign(actor_role: Role, target_role: Role) -> bool:
    """Users may only grant roles at or below their own level; platform admin is never grantable via tenants."""
    if target_role == Role.PLATFORM_ADMIN:
        return False
    return ROLE_RANK[actor_role] >= ROLE_RANK[target_role]
