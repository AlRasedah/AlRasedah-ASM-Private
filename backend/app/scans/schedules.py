"""Recurring scans.

People schedule scans in words — "every Sunday at 9 am" — so that is what the
interface asks for. Cron remains the storage format because it is what computes
the next run and what an operator can still write by hand for an odd cadence;
:func:`to_cron`, :func:`from_cron` and :func:`describe` translate between the two.
Anything a person builds here round-trips; anything more unusual keeps working and
is simply shown as its cron expression.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter

from app.core.errors import ValidationFailed

# Cron numbers days 0-6 from Sunday, which is also how a week reads in Saudi Arabia.
WEEKDAYS = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")


@dataclass(frozen=True)
class Recurrence:
    """A schedule as someone would say it out loud."""

    frequency: str  # "daily" | "weekly" | "monthly"
    hour: int
    minute: int = 0
    weekday: int | None = None  # weekly: 0 = Sunday
    day: int | None = None      # monthly: 1-28, so every month has the day


def to_cron(rec: Recurrence) -> str:
    if not 0 <= rec.hour <= 23 or not 0 <= rec.minute <= 59:
        raise ValidationFailed("Choose a time between 00:00 and 23:59")
    if rec.frequency == "daily":
        return f"{rec.minute} {rec.hour} * * *"
    if rec.frequency == "weekly":
        if rec.weekday is None or not 0 <= rec.weekday <= 6:
            raise ValidationFailed("Choose a day of the week")
        return f"{rec.minute} {rec.hour} * * {rec.weekday}"
    if rec.frequency == "monthly":
        if rec.day is None or not 1 <= rec.day <= 28:
            raise ValidationFailed("Choose a day of the month between 1 and 28")
        return f"{rec.minute} {rec.hour} {rec.day} * *"
    raise ValidationFailed("Choose how often the scan should run")


_DAILY = re.compile(r"^(\d{1,2}) (\d{1,2}) \* \* \*$")
_WEEKLY = re.compile(r"^(\d{1,2}) (\d{1,2}) \* \* ([0-7])$")
_MONTHLY = re.compile(r"^(\d{1,2}) (\d{1,2}) (\d{1,2}) \* \*$")


def from_cron(cron: str) -> Recurrence | None:
    """The recurrence a cron expression stands for, or None if it says something else."""
    text = " ".join(cron.split())
    if m := _DAILY.match(text):
        return Recurrence("daily", hour=int(m.group(2)), minute=int(m.group(1)))
    if m := _WEEKLY.match(text):
        return Recurrence("weekly", hour=int(m.group(2)), minute=int(m.group(1)),
                          weekday=int(m.group(3)) % 7)  # cron allows 7 for Sunday
    if m := _MONTHLY.match(text):
        day = int(m.group(3))
        if 1 <= day <= 28:
            return Recurrence("monthly", hour=int(m.group(2)), minute=int(m.group(1)), day=day)
    return None


def describe(cron: str) -> str:
    """One line a person can check at a glance."""
    rec = from_cron(cron)
    if rec is None:
        return f"Custom schedule ({' '.join(cron.split())})"
    at = f"{rec.hour:02d}:{rec.minute:02d}"
    if rec.frequency == "daily":
        return f"Every day at {at}"
    if rec.frequency == "weekly":
        return f"Every {WEEKDAYS[rec.weekday or 0]} at {at}"
    return f"Day {rec.day} of every month at {at}"


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
