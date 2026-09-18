from __future__ import annotations

from pathlib import Path

import pytest

from asm_sensors.base import RawOutput
from asm_sensors.observations import AssetObservation, FindingObservation, RelationObservation
from asm_sensors.targets import Target, TargetKind

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def raw(name: str) -> RawOutput:
    return RawOutput(files={name: fixture_bytes(name)})


def t(kind: str, value: str) -> Target:
    return Target(kind=TargetKind(kind), value=value)


class Obs:
    """Convenience accessors over a NormalizedOutput."""

    def __init__(self, normalized):
        self.n = normalized
        self.assets = [o for o in normalized.observations if isinstance(o, AssetObservation)]
        self.relations = [o for o in normalized.observations if isinstance(o, RelationObservation)]
        self.findings = [o for o in normalized.observations if isinstance(o, FindingObservation)]

    def values(self, type_: str) -> set[str]:
        return {a.value for a in self.assets if a.type.value == type_}

    def asset(self, type_: str, value: str) -> AssetObservation:
        return next(a for a in self.assets if a.type.value == type_ and a.value == value)

    def rels(self, relation: str) -> set[tuple[str, str]]:
        return {(r.source.value, r.target.value) for r in self.relations if r.relation.value == relation}


@pytest.fixture
def obs_factory():
    return Obs
