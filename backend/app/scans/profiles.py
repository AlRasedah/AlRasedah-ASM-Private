"""Scan profile definitions and validation.

A profile is an ordered list of stages. Each stage names a platform stage type
(Exteriq concept) and the sensor engine that implements it (implementation
detail). Stages always execute in canonical pipeline order.
"""

from __future__ import annotations

from typing import Any

from asm_sensors.base import ConfigurationError
from asm_sensors.registry import get_adapter
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailed
from app.models import ScanProfile
from app.models.enums import StageType
from app.scans import engines

STAGE_ORDER = [
    StageType.SUBDOMAIN_DISCOVERY,
    StageType.OSINT_ENRICHMENT,
    StageType.DNS_RESOLUTION,
    StageType.IP_ENRICHMENT,
    StageType.PORT_DISCOVERY,
    StageType.HTTP_DISCOVERY,
    StageType.WEB_CRAWL,
    StageType.VULNERABILITY_DETECTION,
]

STAGE_LABELS = {
    StageType.SUBDOMAIN_DISCOVERY: "Asset discovery",
    StageType.OSINT_ENRICHMENT: "Open-source intelligence",
    StageType.DNS_RESOLUTION: "DNS resolution",
    StageType.IP_ENRICHMENT: "Network ownership",
    StageType.PORT_DISCOVERY: "Exposed service discovery",
    StageType.HTTP_DISCOVERY: "Web service fingerprinting",
    StageType.WEB_CRAWL: "Web application crawling",
    StageType.VULNERABILITY_DETECTION: "Exposure & vulnerability detection",
}

_IP_ENRICHMENT = [
    {"stage": "ip_enrichment", "engine": "asnlookup", "config": {}, "optional": True},
    # Internet-exposure intelligence. Passive (queries Shodan, not the target) and
    # skipped automatically when the tenant has no Shodan key.
    {"stage": "ip_enrichment", "engine": "shodan", "config": {}, "optional": True},
]

_DISCOVERY = [
    {"stage": "subdomain_discovery", "engine": "subfinder", "config": {}},
    {"stage": "subdomain_discovery", "engine": "crtsh", "config": {}, "optional": True},
    # Deep enumeration is the slowest source by far and mostly repeats what the fast
    # ones already found, so it gets a tight budget: a daily scan should not spend
    # half an hour here. Raise it in a custom profile when depth matters more.
    {"stage": "subdomain_discovery", "engine": "amass", "config": {"mode": "passive", "timeout_minutes": 10},
     "optional": True},
]

BUILTIN_PROFILES: list[dict[str, Any]] = [
    {
        "slug": "passive-discovery",
        "name": "Passive Discovery",
        "description": "Discovers subdomains from passive sources and certificate transparency, resolves DNS "
                       "and maps network ownership. Sends no traffic to your hosts beyond DNS resolution.",
        "stages": [
            *_DISCOVERY,
            {"stage": "dns_resolution", "engine": "dnsx", "config": {}},
            *_IP_ENRICHMENT,
        ],
    },
    {
        "slug": "standard-asm",
        "name": "Standard ASM",
        "description": "Passive discovery plus DNS, web service fingerprinting, discovery of commonly exposed "
                       "services and safe exposure/vulnerability detection. Recommended for daily monitoring.",
        "stages": [
            *_DISCOVERY,
            {"stage": "dns_resolution", "engine": "dnsx", "config": {}},
            *_IP_ENRICHMENT,
            {"stage": "port_discovery", "engine": "naabu", "config": {"port_set": "common", "rate": 500}},
            {"stage": "http_discovery", "engine": "httpx", "config": {}},
            {"stage": "vulnerability_detection", "engine": "nuclei",
             "config": {"severities": ["low", "medium", "high", "critical"]}},
        ],
    },
    {
        "slug": "deep-assessment",
        "name": "Deep Assessment",
        "description": "Extended discovery (all passive sources, optional OSINT enrichment), extended port "
                       "coverage and the broader safe detection template set including informational exposures.",
        "stages": [
            {"stage": "subdomain_discovery", "engine": "subfinder", "config": {"all_sources": True, "max_time_minutes": 15}},
            {"stage": "subdomain_discovery", "engine": "crtsh", "config": {}, "optional": True},
            # Deep assessment may dig longer than the daily profiles, but 90 minutes in one
            # stage made whole scans look stuck; 25 is still thorough for passive enumeration.
            {"stage": "subdomain_discovery", "engine": "amass", "config": {"mode": "passive", "timeout_minutes": 25},
             "optional": True},
            {"stage": "osint_enrichment", "engine": "spiderfoot", "config": {"use_case": "passive"}, "optional": True},
            {"stage": "dns_resolution", "engine": "dnsx",
             "config": {"record_types": ["a", "aaaa", "cname", "mx", "ns", "txt", "caa"]}},
            *_IP_ENRICHMENT,
            {"stage": "port_discovery", "engine": "naabu", "config": {"port_set": "extended", "rate": 800}},
            {"stage": "http_discovery", "engine": "httpx", "config": {
                "ports": "80,81,443,591,2082,2083,2087,3000,4443,5000,7001,7443,8000,8008,8080,8081,8088,8443,"
                         "8834,8888,9000,9090,9443,10443"}},
            {"stage": "web_crawl", "engine": "zap_spider", "config": {"passive_scan": True}, "optional": True},
            {"stage": "vulnerability_detection", "engine": "nuclei",
             "config": {"severities": ["info", "low", "medium", "high", "critical"]}},
        ],
    },
    {
        "slug": "web-app-scan",
        "name": "Web Application Scan (DAST)",
        "description": "Dynamic application security testing: fingerprints web services, crawls each "
                       "application (spider + passive scanning) and actively probes it for injection and other "
                       "web vulnerabilities. Requires the optional web application scanner and active-scanning "
                       "authorization.",
        "stages": [
            {"stage": "dns_resolution", "engine": "dnsx", "config": {}},
            {"stage": "port_discovery", "engine": "naabu", "config": {"port_set": "web"}, "optional": True},
            {"stage": "http_discovery", "engine": "httpx", "config": {}},
            {"stage": "web_crawl", "engine": "zap_spider",
             "config": {"max_duration_minutes": 20, "passive_scan": True}},
            {"stage": "vulnerability_detection", "engine": "zap_active",
             "config": {"max_duration_minutes": 60, "attack_strength": "medium"}},
        ],
    },
    {
        "slug": "exposure-monitoring",
        "name": "Exposure Monitoring",
        "description": "Fast re-check of already known assets (no discovery): DNS, web services and commonly "
                       "exposed ports. Suited for frequent schedules.",
        "stages": [
            {"stage": "dns_resolution", "engine": "dnsx", "config": {}},
            {"stage": "port_discovery", "engine": "naabu", "config": {"port_set": "web"}},
            {"stage": "http_discovery", "engine": "httpx", "config": {}},
        ],
    },
]


# Profiles the platform uses internally. They exist as rows so an internal scan has a
# profile like any other (audit, quotas, history), but they are never listed or
# offered: a Threat Center check supplies its own single stage, built from an
# approved check, when it creates the scan (app/threats/service.py).
THREAT_CHECK_SLUG = "threat-check"
INTERNAL_PROFILES: list[dict[str, Any]] = [
    {
        "slug": THREAT_CHECK_SLUG,
        "name": "Threat Center check",
        "description": "Runs one platform-approved detection check against assets selected in the Threat Center.",
        "stages": [{"stage": "vulnerability_detection", "engine": "nuclei",
                    "config": {"include_tech_detection": False}}],
    },
]
INTERNAL_SLUGS = frozenset(p["slug"] for p in INTERNAL_PROFILES)


def validate_stages(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate and canonicalize a profile's stages. Raises ValidationFailed."""
    if not stages:
        raise ValidationFailed("A scan profile needs at least one stage")
    if len(stages) > 20:
        raise ValidationFailed("A scan profile may have at most 20 stages")
    out = []
    errors: list[str] = []
    for i, raw in enumerate(stages):
        if not isinstance(raw, dict):
            errors.append(f"stage {i}: must be an object")
            continue
        unknown = set(raw) - {"stage", "engine", "config", "enabled", "optional"}
        if unknown:
            errors.append(f"stage {i}: unknown keys {sorted(unknown)}")
            continue
        try:
            stage_type = StageType(raw.get("stage"))
        except ValueError:
            errors.append(f"stage {i}: unknown stage type {raw.get('stage')!r}")
            continue
        try:
            # Accepts the opaque token the API hands out, or the engine name (CLI, scripts).
            adapter = get_adapter(engines.engine_for(str(raw.get("engine"))))
        except KeyError:
            errors.append(f"stage {i}: unknown capability {raw.get('engine')!r}")
            continue
        if stage_type not in adapter.stage_types:
            errors.append(f"stage {i}: {adapter.display_name} cannot perform {STAGE_LABELS[stage_type]}")
            continue
        try:
            cfg = adapter.parse_config(raw.get("config") or {})
        except ConfigurationError as exc:
            errors.append(f"stage {i}: {exc}")
            continue
        out.append({
            "stage": stage_type.value,
            "engine": adapter.name,
            "config": cfg.model_dump(mode="json", exclude_defaults=True),
            "enabled": bool(raw.get("enabled", True)),
            "optional": bool(raw.get("optional", False)),
            "active": adapter.is_active(cfg),
        })
    if errors:
        raise ValidationFailed("Invalid scan profile", details=errors)
    out.sort(key=lambda s: STAGE_ORDER.index(StageType(s["stage"])))
    return out


def profile_is_active(stages: list[dict[str, Any]]) -> bool:
    return any(s.get("active") and s.get("enabled", True) for s in stages)


def ensure_builtin_profiles(db: Session) -> None:
    """Idempotently create/refresh global built-in profiles (system session)."""
    for spec in [*BUILTIN_PROFILES, *INTERNAL_PROFILES]:
        stages = validate_stages(spec["stages"])
        existing = db.execute(
            select(ScanProfile).where(ScanProfile.tenant_id.is_(None), ScanProfile.slug == spec["slug"])
        ).scalar_one_or_none()
        if existing is None:
            existing = ScanProfile(tenant_id=None, slug=spec["slug"], is_builtin=True)
            db.add(existing)
        existing.name = spec["name"]
        existing.description = spec["description"]
        existing.stages = stages
        existing.is_active_scanning = profile_is_active(stages)
    db.flush()


# Per-engine wall-clock budget, mirroring the sensor adapters (asm_sensors/adapters/*):
# (config key, default minutes, grace seconds). Other engines run until the platform limit.
_ENGINE_BUDGET = {"amass": ("timeout_minutes", 30, 300), "bbot": ("timeout_minutes", 60, 0),
                  "subfinder": ("max_time_minutes", 10, 120),
                  "zap_spider": ("max_duration_minutes", 15, 120),
                  "zap_active": ("max_duration_minutes", 60, 180)}


def stage_time_limit(engine: str, config: dict | None, platform_limit_seconds: int) -> int:
    """Longest a stage can run before its sensor stops it, in seconds (shown next to running stages)."""
    budget = _ENGINE_BUDGET.get(engine)
    if not budget:
        return platform_limit_seconds
    key, default_minutes, grace = budget
    try:
        minutes = int((config or {}).get(key, default_minutes))
    except (TypeError, ValueError):
        minutes = default_minutes
    return min(platform_limit_seconds, minutes * 60 + grace)
