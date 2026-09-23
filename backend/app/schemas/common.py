from __future__ import annotations

from typing import Annotated, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, StringConstraints
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

T = TypeVar("T")

# Deliberately permissive: enterprise directories commonly use internal or reserved
# domains (corp.local, example.internal) that strict RFC/"deliverability" validation rejects.
Email = Annotated[str, StringConstraints(strip_whitespace=True, to_lower=True, min_length=3, max_length=320,
                                         pattern=r"^[^@\s]+@[^@\s]+$")]


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


class Message(BaseModel):
    message: str


def paginate(db: Session, stmt: Select, page: int, page_size: int) -> tuple[list, int]:
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = db.execute(stmt.limit(page_size).offset((page - 1) * page_size)).scalars().all()
    return list(rows), total


SOURCE_LABELS = {
    "nuclei": "Vulnerability detection",
    "zap_spider": "Web application crawling",
    "zap_active": "Active web scanning",
    "asm-rules": "Exposure rules",
    "spiderfoot": "OSINT enrichment",
    "bbot": "OSINT discovery",
    "amass": "Asset discovery",
    "subfinder": "Asset discovery",
    "crtsh": "Certificate transparency",
    "dnsx": "DNS resolution",
    "httpx": "Web fingerprinting",
    "naabu": "Service discovery",
    "asnlookup": "Network ownership",
    "shodan": "Internet exposure intelligence",
    "scope": "Authorized scope",
    "manual": "Manual entry",
}


# Detections confirmed by actively exercising the running web application.
DAST_SOURCES = frozenset({"zap_active"})


def source_label(source: str | None) -> str | None:
    if source is None:
        return None
    return SOURCE_LABELS.get(source, source.replace("-", " ").replace("_", " ").capitalize())
