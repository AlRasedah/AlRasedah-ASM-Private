"""Adapter registry.

Adapters register themselves with :func:`register`. Third-party adapters can be
shipped as separate packages exposing the ``asm_sensors.adapters`` entry point
group; they are discovered by :func:`load_adapters`.
"""

from __future__ import annotations

import importlib
from importlib.metadata import entry_points
from typing import Any

from .base import ScannerAdapter, StageType

_REGISTRY: dict[str, type[ScannerAdapter]] = {}
_LOADED = False

BUILTIN_MODULES = (
    "asm_sensors.adapters.amass",
    "asm_sensors.adapters.subfinder",
    "asm_sensors.adapters.crtsh",
    "asm_sensors.adapters.dnsx",
    "asm_sensors.adapters.asnlookup",
    "asm_sensors.adapters.shodan",
    "asm_sensors.adapters.naabu",
    "asm_sensors.adapters.httpx",
    "asm_sensors.adapters.nuclei",
    "asm_sensors.adapters.spiderfoot",
    "asm_sensors.adapters.bbot",
    "asm_sensors.adapters.zap",
    "asm_sensors.adapters.screenshot",
)


def register(cls: type[ScannerAdapter]) -> type[ScannerAdapter]:
    if not getattr(cls, "name", None):
        raise TypeError("adapter must define a name")
    _REGISTRY[cls.name] = cls
    return cls


def load_adapters() -> None:
    global _LOADED
    if _LOADED:
        return
    for mod in BUILTIN_MODULES:
        importlib.import_module(mod)
    for ep in entry_points(group="asm_sensors.adapters"):
        ep.load()
    _LOADED = True


def get_adapter(name: str) -> ScannerAdapter:
    load_adapters()
    try:
        return _REGISTRY[name]()
    except KeyError:
        raise KeyError(f"unknown sensor adapter: {name}") from None


def adapter_names() -> list[str]:
    load_adapters()
    return sorted(_REGISTRY)


def describe_adapters() -> list[dict[str, Any]]:
    load_adapters()
    out = []
    for name in sorted(_REGISTRY):
        cls = _REGISTRY[name]
        out.append(
            {
                "name": name,
                "display_name": cls.display_name,
                "stage_types": sorted(s.value for s in cls.stage_types),
                "target_kinds": sorted(k.value for k in cls.target_kinds),
                "active": cls.active,
                "credential_providers": list(cls.credential_providers),
                "config_schema": cls.config_model.model_json_schema(),
            }
        )
    return out


def adapters_for_stage(stage: StageType) -> list[str]:
    load_adapters()
    return sorted(n for n, c in _REGISTRY.items() if stage in c.stage_types)
