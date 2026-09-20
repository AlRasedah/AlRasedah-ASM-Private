"""Platform SMTP mailer (password resets, email notifications)."""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import make_msgid

from app.core.config import get_settings

log = logging.getLogger(__name__)


class MailNotConfigured(RuntimeError):
    pass


def _stored_settings() -> dict:
    """Mail settings a platform administrator saved in the web interface (if any)."""
    from app.db.session import system_session
    from app.services.platform_settings import smtp_override as stored

    try:
        with system_session() as db:
            return stored(db)
    except Exception:  # noqa: BLE001 - never let a settings lookup break mail delivery
        log.exception("could not read the platform mail settings; falling back to the environment")
        return {}


def send_email(to: list[str], subject: str, text: str, html: str | None = None,
               smtp_override: dict | None = None) -> None:
    """Send one mail. Settings precedence: explicit override > platform settings > environment."""
    s = get_settings()
    cfg = {
        "host": s.smtp_host, "port": s.smtp_port, "username": s.smtp_username,
        "password": s.smtp_password.get_secret_value() if s.smtp_password else None,
        "sender": s.smtp_from, "starttls": s.smtp_starttls, "ssl": s.smtp_ssl,
    }
    cfg.update({k: v for k, v in _stored_settings().items() if v is not None})
    cfg.update({k: v for k, v in (smtp_override or {}).items() if v is not None})
    if not cfg["host"]:
        raise MailNotConfigured("Email delivery is not configured. A platform administrator can set the mail "
                                "server in Settings → Email delivery.")
    msg = EmailMessage()
    msg["From"] = cfg["sender"]
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject.replace("\n", " ")[:250]
    msg["Message-ID"] = make_msgid(domain="exteriq-asm")
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    context = ssl.create_default_context()
    timeout = s.smtp_timeout_seconds
    if cfg["ssl"]:
        server: smtplib.SMTP = smtplib.SMTP_SSL(cfg["host"], int(cfg["port"]), timeout=timeout, context=context)
    else:
        server = smtplib.SMTP(cfg["host"], int(cfg["port"]), timeout=timeout)
    with server:
        if cfg["starttls"] and not cfg["ssl"]:
            server.starttls(context=context)
        if cfg["username"] and cfg["password"]:
            server.login(cfg["username"], cfg["password"])
        server.send_message(msg)


def send_password_reset(email: str, raw_token: str) -> None:
    s = get_settings()
    link = f"{s.public_url.rstrip('/')}/reset-password?token={raw_token}"
    minutes = s.password_reset_ttl_minutes
    text = (f"A password reset was requested for your {s.app_name} account.\n\n"
            f"Reset your password: {link}\n\nThis link expires in {minutes} minutes and can be used once. "
            "If you did not request it, ignore this email.")
    try:
        send_email([email], f"{s.app_name}: password reset", text)
    except MailNotConfigured:
        # Never log the token itself.
        log.warning("password reset requested but SMTP is not configured; an administrator can reset the password")
