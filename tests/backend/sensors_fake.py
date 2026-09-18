"""Replace sensor execution with recorded tool output (no binaries, no network)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from asm_sensors.base import RawOutput
from asm_sensors.execution import ProcessResult
from asm_sensors.registry import _REGISTRY, load_adapters

FIXTURES = Path(__file__).resolve().parents[1] / "sensors" / "fixtures"

DEFAULT_OUTPUTS: dict[str, str | list] = {
    "amass": "amass_v4.txt",
    "subfinder": "subfinder.jsonl",
    "dnsx": "dnsx.jsonl",
    "naabu": "naabu.jsonl",
    "httpx": "httpx.jsonl",
    "nuclei": "nuclei.jsonl",
    "crtsh": [],
    "asnlookup": [{"ip": "192.0.2.20", "asn": "AS64500", "cidr": "192.0.2.0/24", "country": "SA",
                   "registry": "ripencc", "as_name": "EXAMPLE-NET"}],
}


class FakeSensors:
    """Records calls (targets per engine) and serves canned output."""

    def __init__(self, monkeypatch, outputs: dict[str, str | list | bytes | Callable] | None = None) -> None:
        load_adapters()
        self.outputs = dict(DEFAULT_OUTPUTS)
        self.outputs.update(outputs or {})
        self.calls: dict[str, list[list[str]]] = {}
        for name, cls in _REGISTRY.items():
            monkeypatch.setattr(cls, "execute", self._make_execute(name))
            monkeypatch.setattr(cls, "validate_configuration", _noop_validate)

    def set(self, engine: str, output) -> None:
        self.outputs[engine] = output

    def _make_execute(self, name: str):
        fake = self

        async def execute(self_adapter, targets, config, ctx):  # noqa: ANN001
            fake.calls.setdefault(name, []).append([t.value for t in targets])
            out = fake.outputs.get(name, b"")
            if callable(out):
                out = out(targets)
            proc = ProcessResult(argv=[name], returncode=0, stdout=b"", stderr=b"", duration=0.01)
            if isinstance(out, list):
                return RawOutput(records=out)
            data = out if isinstance(out, bytes) else (FIXTURES / out).read_bytes() if out else b""
            return RawOutput(process=proc, files={f"{name}.out": data})

        return execute


async def _noop_validate(self, config, ctx):  # noqa: ANN001
    return None
