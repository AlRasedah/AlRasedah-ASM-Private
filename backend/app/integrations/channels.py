"""Notification channel adapters.

Each channel turns a list of normalized event payloads into a delivery. Adding
a channel = one class + registration in ``CHANNELS``. Integration config is
non-secret JSON; secrets (webhook signing keys, incoming-webhook URLs, SMTP
passwords) are resolved from the encrypted secrets store at send time.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.config import get_settings
from app.integrations.mailer import send_email
from app.schemas.common import Email


@dataclass(frozen=True)
class Destination:
    """Who a delivery belongs to, from the platform rather than from tenant config.

    A channel that writes somewhere shared — the file export, today — must separate
    tenants by an identity they cannot choose. Tenant-supplied fields (a file name,
    a URL) are not that: two customers can pick the same one, by accident or not.
    """

    tenant_id: uuid.UUID
    integration_id: uuid.UUID | None = None


class ChannelError(RuntimeError):
    pass


# ------------------------------------------------------------------ helpers
def check_outbound_url(url: str) -> str:
    """SSRF guard for user-configured outbound URLs."""
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ChannelError("URL must be http(s)")
    if parts.username or parts.password:
        raise ChannelError("credentials in URLs are not allowed; use the secret field")
    if get_settings().allow_private_webhook_targets:
        return url
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise ChannelError(f"cannot resolve {parts.hostname}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise ChannelError("destination resolves to a private or reserved address")
    return url


def _post_json(url: str, payload: Any, headers: dict[str, str] | None = None, body: bytes | None = None) -> None:
    check_outbound_url(url)
    data = body if body is not None else json.dumps(payload, default=str).encode()
    try:
        r = httpx.post(url, content=data, headers={"Content-Type": "application/json",
                                                   "User-Agent": "Exteriq-ASM/1.0", **(headers or {})},
                       timeout=get_settings().webhook_timeout_seconds, follow_redirects=False)
    except httpx.HTTPError as exc:
        raise ChannelError(f"delivery failed: {type(exc).__name__}") from exc
    if r.status_code >= 300:
        raise ChannelError(f"receiver answered HTTP {r.status_code}")


SEVERITY_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


# ------------------------------------------------------------------ configs
class _Cfg(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EmailConfig(_Cfg):
    recipients: list[Email] = Field(min_length=1, max_length=50)
    subject_prefix: str = Field(default="[Exteriq ASM]", max_length=64)


class WebhookConfig(_Cfg):
    url: str = Field(max_length=2048)
    batch: bool = False

    @field_validator("url")
    @classmethod
    def _u(cls, v: str) -> str:
        if urlsplit(v).scheme not in ("http", "https"):
            raise ValueError("url must be http(s)")
        return v


class WazuhConfig(_Cfg):
    mode: Literal["syslog", "webhook", "file"] = "syslog"
    host: str | None = Field(default=None, max_length=255)
    port: int = Field(default=514, ge=1, le=65535)
    protocol: Literal["udp", "tcp"] = "udp"
    url: str | None = Field(default=None, max_length=2048)
    file_name: str = Field(default="exteriq-asm.json", pattern=r"^[A-Za-z0-9._-]{1,64}$")


class ChatConfig(_Cfg):
    mention: str | None = Field(default=None, max_length=64)


# ----------------------------------------------------------------- channels
class Channel:
    type: ClassVar[str]
    config_model: ClassVar[type[BaseModel]]
    needs_secret: ClassVar[bool] = False
    implemented: ClassVar[bool] = True

    def validate(self, config: dict[str, Any]) -> dict[str, Any]:
        return self.config_model.model_validate(config).model_dump(mode="json")

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        raise NotImplementedError


def email_message(payloads: list[dict[str, Any]], subject_prefix: str = "[Exteriq ASM]") -> tuple[str, str]:
    """Subject and plain-text body for a batch of events (shared by the email channel
    and the per-user alerts people switch on for their own login address)."""
    top = max(payloads, key=lambda p: ["info", "low", "medium", "high", "critical"].index(p["severity"]))
    subject = (f"{subject_prefix} {top['severity'].upper()}: {top['title']}" if len(payloads) == 1
               else f"{subject_prefix} {len(payloads)} attack surface changes")
    lines = []
    for p in payloads:
        lines.append(f"[{p['severity'].upper()}] {p['title']}")
        if p.get("organization"):
            lines.append(f"  Organization: {p['organization']}")
        if p.get("asset"):
            lines.append(f"  Asset: {p['asset']}" + (f" ({p['ip']})" if p.get("ip") else ""))
        if p.get("summary"):
            lines.append(f"  {p['summary']}")
        if p.get("previous") or p.get("current"):
            lines.append(f"  Previous: {json.dumps(p.get('previous'))}")
            lines.append(f"  Current:  {json.dumps(p.get('current'))}")
        lines.append(f"  When: {p['occurred_at']}   Risk: {p.get('risk_score', '-')}")
        if p.get("url"):
            lines.append(f"  {p['url']}")
        lines.append("")
    return subject, "\n".join(lines)


class EmailChannel(Channel):
    type = "email"
    config_model = EmailConfig

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        cfg = EmailConfig.model_validate(config)
        subject, body = email_message(payloads, cfg.subject_prefix)
        try:
            send_email([str(r) for r in cfg.recipients], subject, body)
        except Exception as exc:  # noqa: BLE001
            raise ChannelError(f"email delivery failed: {type(exc).__name__}") from exc


class WebhookChannel(Channel):
    """Generic JSON webhook, HMAC-SHA256 signed when a signing secret is set:
    ``X-ASM-Signature: sha256=hex(hmac(secret, timestamp + "." + body))``."""

    type = "webhook"
    config_model = WebhookConfig

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        cfg = WebhookConfig.model_validate(config)
        bodies = [{"events": payloads}] if cfg.batch else payloads
        for body in bodies:
            raw = json.dumps(body, default=str, separators=(",", ":")).encode()
            headers = {}
            if secret:
                ts = str(int(time.time()))
                sig = hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest()
                headers = {"X-ASM-Timestamp": ts, "X-ASM-Signature": f"sha256={sig}"}
            _post_json(cfg.url, None, headers, body=raw)


def wazuh_event(p: dict[str, Any]) -> dict[str, Any]:
    """Flat structured JSON consumed by Wazuh's JSON decoder (see docs/integrations/wazuh.md)."""
    return {
        "source": "exteriq-asm",
        "event_type": p["event_type"],
        "severity": p["severity"],
        "title": p["title"],
        "tenant": p.get("tenant"),
        "organization": p.get("organization"),
        "asset": p.get("asset"),
        "asset_type": p.get("asset_type"),
        "ip": p.get("ip"),
        "finding": p.get("finding"),
        "cve": p.get("cve"),
        "risk_score": p.get("risk_score"),
        "previous": p.get("previous"),
        "current": p.get("current"),
        "event_id": p["event_id"],
        "timestamp": p["occurred_at"],
        "url": p.get("url"),
    }


_SYSLOG_SEVERITY = {"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}


def syslog_line(p: dict[str, Any], hostname: str = "exteriq-asm") -> bytes:
    pri = 16 * 8 + _SYSLOG_SEVERITY.get(p["severity"], 6)  # facility local0
    now = datetime.now(UTC)
    ts = f"{now:%b} {now.day:>2} {now:%H:%M:%S}"  # RFC 3164 timestamp (space-padded day)
    msg = json.dumps(wazuh_event(p), default=str, separators=(",", ":"))
    return f"<{pri}>{ts} {hostname} exteriq-asm: {msg}".encode()


class WazuhChannel(Channel):
    type = "wazuh"
    config_model = WazuhConfig

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        cfg = WazuhConfig.model_validate(config)
        if cfg.mode == "syslog":
            if not cfg.host:
                raise ChannelError("syslog mode requires host")
            try:
                if cfg.protocol == "udp":
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        for p in payloads:
                            sock.sendto(syslog_line(p), (cfg.host, cfg.port))
                else:
                    with socket.create_connection((cfg.host, cfg.port), timeout=10) as sock:
                        for p in payloads:
                            sock.sendall(syslog_line(p) + b"\n")
            except OSError as exc:
                raise ChannelError(f"syslog delivery failed: {exc.strerror or type(exc).__name__}") from exc
        elif cfg.mode == "webhook":
            if not cfg.url:
                raise ChannelError("webhook mode requires url")
            headers = {"Authorization": f"Bearer {secret}"} if secret else {}
            for p in payloads:
                _post_json(cfg.url, wazuh_event(p), headers)
        else:
            # One directory per tenant. The file name is tenant-chosen, so without this
            # two customers picking the default would append to one file and each would
            # read the other's findings out of their own collector.
            if destination is None:
                raise ChannelError("file mode has no owning tenant; this delivery was not routed")
            directory = Path(os.environ.get("ASM_INTEGRATION_EXPORT_DIR", "/data/exports")) / str(destination.tenant_id)
            directory.mkdir(parents=True, exist_ok=True)
            path = directory / cfg.file_name
            with path.open("a", encoding="utf-8") as fh:
                for p in payloads:
                    fh.write(json.dumps(wazuh_event(p), default=str, separators=(",", ":")) + "\n")


class SlackChannel(Channel):
    type = "slack"
    config_model = ChatConfig
    needs_secret = True  # the incoming-webhook URL is a credential

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        if not secret:
            raise ChannelError("Slack incoming webhook URL is not configured")
        cfg = ChatConfig.model_validate(config)
        text = "\n".join(f"{SEVERITY_EMOJI.get(p['severity'], '')} *{p['title']}*"
                         + (f"\n>{p['summary']}" if p.get("summary") else "")
                         + (f" <{p['url']}|open>" if p.get("url") else "") for p in payloads[:20])
        _post_json(secret, {"text": (f"{cfg.mention} " if cfg.mention else "") + text})


class TeamsChannel(Channel):
    type = "teams"
    config_model = ChatConfig
    needs_secret = True

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        if not secret:
            raise ChannelError("Teams webhook URL is not configured")
        body = [{"type": "TextBlock", "weight": "Bolder", "text": "Exteriq ASM", "size": "Medium"}]
        for p in payloads[:20]:
            body.append({"type": "TextBlock", "wrap": True,
                         "text": f"**[{p['severity'].upper()}] {p['title']}**"
                                 + (f"\n\n{p['summary']}" if p.get("summary") else "")})
        card = {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                    "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                                                                "type": "AdaptiveCard", "version": "1.4", "body": body}}]}
        _post_json(secret, card)


class _Planned(Channel):
    config_model = _Cfg
    implemented = False

    def send(self, config: dict[str, Any], secret: str | None, payloads: list[dict[str, Any]],
             destination: Destination | None = None) -> None:
        raise ChannelError(f"the {self.type} integration is planned but not yet available")


class JiraChannel(_Planned):
    """Ticket creation for findings. Planned; hidden in the UI until it works."""

    type = "jira"


class ServiceNowChannel(_Planned):
    """Incident creation for findings. Planned; hidden in the UI until it works."""

    type = "servicenow"


CHANNELS: dict[str, Channel] = {c.type: c for c in (EmailChannel(), WebhookChannel(), WazuhChannel(), SlackChannel(),
                                                    TeamsChannel(), JiraChannel(), ServiceNowChannel())}
