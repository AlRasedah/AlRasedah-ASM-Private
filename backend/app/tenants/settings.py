"""Tenant/organization configuration with safe defaults.

Stored as JSON on the tenant/organization row and deep-merged over these
defaults, so new settings never require a migration.
"""

from __future__ import annotations

import copy
from typing import Any

DEFAULT_TENANT_SETTINGS: dict[str, Any] = {
    # Consecutive covered-but-not-observed runs before something is considered gone.
    "inactivity": {
        "default": 3,
        "subdomain": 3,
        "root_domain": 3,
        "domain": 3,
        "port": 2,
        "service": 2,
        "http_endpoint": 2,
        "relation": 2,
        "finding": 2,
        # Assets not seen at all for this many days become inactive (time-based rule).
        "max_age_days": 30,
    },
    "risk": {
        "severity_points": {"critical": 55, "high": 40, "medium": 25, "low": 10, "info": 2},
        "kev_points": 20,
        "epss_max_points": 18,
        "exploit_points": 8,
        "exposure_points": 5,
        "management_interface_points": 10,
        "auth_exposure_points": 4,
        "risky_port_points": 6,
        "criticality_points": {"low": 0, "medium": 4, "high": 9, "critical": 14},
        "shadow_it_points": 5,
        "unauthorized_points": 10,
        "new_asset_points": 3,
        "new_asset_days": 7,
        "age_points_per_30_days": 2,
        "age_max_points": 8,
        "levels": {"critical": 80, "high": 60, "medium": 35, "low": 15},
    },
    "scanning": {
        "require_scope_verification": False,
    },
    "detection_rules": {
        "risky_ports": True,
        "management_interfaces": True,
        "certificates": True,
        "weak_tls": True,
        "api_documentation": True,
        "certificate_expiry_days": 30,
    },
}

DEFAULT_ORG_SETTINGS: dict[str, Any] = {
    # Allow active scanning of IPs that in-scope hostnames resolve to.
    "derived_ip_scanning": True,
    # Do not port-scan CDN/WAF edge IPs (shared infrastructure).
    "skip_cdn_ips": True,
}


def deep_merge(base: dict[str, Any], override: dict[str, Any] | None) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def tenant_settings(tenant: Any) -> dict[str, Any]:
    out = deep_merge(DEFAULT_TENANT_SETTINGS, getattr(tenant, "settings", None) or {})
    from app.core.config import get_settings

    if get_settings().require_scope_verification:
        # Platform floor (ASM_REQUIRE_SCOPE_VERIFICATION): a tenant cannot switch it off.
        out["scanning"]["require_scope_verification"] = True
    return out


def org_settings(org: Any) -> dict[str, Any]:
    return deep_merge(DEFAULT_ORG_SETTINGS, getattr(org, "settings", None) or {})


def inactivity_threshold(settings: dict[str, Any], key: str) -> int:
    rules = settings.get("inactivity", {})
    return max(1, int(rules.get(key, rules.get("default", 3))))
