"""Two tenants exporting to a file must never share one (review finding F4).

Every file-mode integration wrote to ASM_INTEGRATION_EXPORT_DIR / file_name. The
default name is the same for everyone and the name is tenant-chosen, so two
customers using the default appended to one file — and a collector configured for
one of them forwarded the other's findings. A tenant could also pick a competitor's
file name and inject events into their stream.
"""

from __future__ import annotations

import json
import uuid

import pytest

from app.integrations.channels import ChannelError, Destination, WazuhChannel


@pytest.fixture
def export_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("ASM_INTEGRATION_EXPORT_DIR", str(tmp_path))
    return tmp_path


def _event(title: str) -> dict:
    return {"source": "exteriq-asm", "version": 1, "event_id": str(uuid.uuid4()), "event_type": "port_opened",
            "severity": "high", "title": title, "summary": None, "tenant": None, "organization": None,
            "asset": "host.example.com", "asset_type": "subdomain", "ip": "192.0.2.1", "finding": None,
            "cve": None, "risk_score": 50, "previous": None, "current": None,
            "occurred_at": "2026-09-23T10:00:00+00:00", "url": "https://asm.example.com/changes"}


def test_the_same_file_name_from_two_tenants_stays_separate(export_dir):
    acme, globex = uuid.uuid4(), uuid.uuid4()
    channel = WazuhChannel()
    config = {"mode": "file"}  # both accept the default file name

    channel.send(config, None, [_event("acme finding")], Destination(tenant_id=acme))
    channel.send(config, None, [_event("globex finding")], Destination(tenant_id=globex))

    acme_file = export_dir / str(acme) / "exteriq-asm.json"
    globex_file = export_dir / str(globex) / "exteriq-asm.json"
    assert acme_file.exists() and globex_file.exists()
    assert json.loads(acme_file.read_text())["title"] == "acme finding"
    assert json.loads(globex_file.read_text())["title"] == "globex finding"
    assert "globex" not in acme_file.read_text() and "acme" not in globex_file.read_text()


def test_choosing_another_tenants_file_name_changes_nothing(export_dir):
    acme, attacker = uuid.uuid4(), uuid.uuid4()
    channel = WazuhChannel()
    channel.send({"mode": "file", "file_name": "acme-soc.json"}, None, [_event("acme finding")],
                 Destination(tenant_id=acme))
    # The other tenant names the same file on purpose.
    channel.send({"mode": "file", "file_name": "acme-soc.json"}, None, [_event("injected")],
                 Destination(tenant_id=attacker))
    assert "injected" not in (export_dir / str(acme) / "acme-soc.json").read_text()
    assert (export_dir / str(attacker) / "acme-soc.json").exists()


def test_an_unrouted_delivery_is_refused_rather_than_written_somewhere_shared(export_dir):
    with pytest.raises(ChannelError, match="owning tenant"):
        WazuhChannel().send({"mode": "file"}, None, [_event("x")], None)
    assert not list(export_dir.iterdir())
