"""Cron-based recurring scans."""

from __future__ import annotations

from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter

from app.core.errors import ValidationFailed


def validate_timezone(tz: str) -> str:
    try:
        ZoneInfo(tz)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValidationFailed(f"Unknown timezone '{tz}'") from exc
    return tz


def next_run(cron: str, tz: str, after: datetime | None = None) -> datetime:
    zone = ZoneInfo(tz)
    base = (after or datetime.now(UTC)).astimezone(zone)
    return croniter(cron, base).get_next(datetime).astimezone(UTC)
