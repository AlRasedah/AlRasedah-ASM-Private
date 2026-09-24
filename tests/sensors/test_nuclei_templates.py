"""A run limited to named detections must never turn "nothing to run" into "not detected".

Threat Center checks name one detection (the automatic feed names the community
detection after the CVE). If the scanner's template set does not have it, or it is
classified intrusive, the engine would load nothing and report nothing; the adapter
refuses instead, so the check is inconclusive and says why.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from asm_sensors.adapters.nuclei import NucleiAdapter, NucleiConfig, resolve_templates
from asm_sensors.base import ConfigurationError, ExecutionContext
from asm_sensors.targets import Target, TargetKind


def _template(root: Path, rel: str, tid: str, tags: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"id: {tid}\n\ninfo:\n  name: {tid}\n  severity: critical\n  tags: {tags}\n\nhttp:\n  - method: GET\n")


@pytest.fixture
def templates(tmp_path):
    _template(tmp_path, "http/cves/2021/CVE-2021-41773.yaml", "CVE-2021-41773", "cve,cve2021,apache,lfi,kev")
    _template(tmp_path, "http/cves/2099/CVE-2099-0666.yaml", "CVE-2099-0666", "cve,intrusive,rce")
    _template(tmp_path, "http/misconfiguration/some-panel.yaml", "exposed-admin-panel", "panel,misconfig")
    return tmp_path


def test_named_detections_resolve_to_their_exact_ids(templates):
    run, reasons = resolve_templates(str(templates), ["cve-2021-41773", "exposed-admin-panel"], ["dos", "intrusive"])
    assert run == ["CVE-2021-41773", "exposed-admin-panel"] and reasons == []


def test_missing_and_intrusive_detections_are_refused_with_a_reason(templates):
    run, reasons = resolve_templates(str(templates), ["cve-2099-0001", "cve-2099-0666"], ["dos", "intrusive"])
    assert run == []
    assert "cve-2099-0001 is not in this scanner's detection set" in reasons[0]
    assert "cve-2099-0666 is classified intrusive" in reasons[1]


def test_the_adapter_fails_the_run_instead_of_running_nothing(templates, tmp_path):
    ctx = ExecutionContext(workdir=tmp_path / "wd", settings={"nuclei_templates_dir": str(templates)})
    ctx.workdir.mkdir()
    cfg = NucleiConfig(template_ids=["cve-2099-0001"], include_tech_detection=False)
    with pytest.raises(ConfigurationError, match="not in this scanner's detection set"):
        asyncio.run(NucleiAdapter().execute([Target(kind=TargetKind.URL, value="https://example.com")], cfg, ctx))
