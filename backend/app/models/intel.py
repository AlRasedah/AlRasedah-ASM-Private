"""Locally cached vulnerability intelligence (CVE / CVSS / EPSS / CISA KEV). Global."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import Date, Float, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class VulnIntel(Base):
    __tablename__ = "vuln_intel"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(256))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    epss_date: Mapped[date | None] = mapped_column(Date)
    kev: Mapped[bool] = mapped_column(default=False)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_due_date: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[bool] = mapped_column(default=False)
    kev_vendor: Mapped[str | None] = mapped_column(String(200))
    kev_product: Mapped[str | None] = mapped_column(String(200))
    exploit_available: Mapped[bool] = mapped_column(default=False)
    published_at: Mapped[datetime | None]
    extra: Mapped[dict[str, Any]] = mapped_column(default=dict)
    updated_at: Mapped[datetime] = mapped_column(server_default=func.now(), onupdate=func.now())


class IntelFeedState(Base):
    __tablename__ = "intel_feed_state"

    feed: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_success_at: Mapped[datetime | None]
    last_attempt_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(Text)
    etag: Mapped[str | None] = mapped_column(String(256))
    records: Mapped[int | None]
