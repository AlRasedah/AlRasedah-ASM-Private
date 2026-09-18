"""Vulnerability intelligence: CISA KEV, FIRST EPSS, (optional) NVD CVSS.

Only free/public feeds; everything is cached in ``vuln_intel`` so scoring works
offline. Feed URLs are configurable (mirrors) and both feeds can be imported
from files for air-gapped, in-Kingdom deployments:

    python -m app.cli intel-import --kev known_exploited_vulnerabilities.json --epss epss_scores.csv.gz
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
from collections.abc import Iterable
from datetime import UTC, date, datetime
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import new_session, system_session
from app.findings.service import enrich_from_intel
from app.models import Finding, IntelFeedState, Organization, Tenant, VulnIntel
from app.models.enums import OPEN_FINDING_STATES, TenantStatus

log = logging.getLogger(__name__)
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _state(db: Session, feed: str) -> IntelFeedState:
    st = db.get(IntelFeedState, feed)
    if st is None:
        st = IntelFeedState(feed=feed)
        db.add(st)
    return st


def _d(value: Any) -> date | None:
    try:
        return date.fromisoformat(str(value)[:10]) if value else None
    except ValueError:
        return None


def apply_kev(db: Session, doc: dict[str, Any]) -> int:
    rows = []
    for v in doc.get("vulnerabilities", []):
        cve = str(v.get("cveID", "")).upper()
        if not CVE_RE.match(cve):
            continue
        rows.append({"cve_id": cve, "kev": True, "kev_date_added": _d(v.get("dateAdded")),
                     "kev_due_date": _d(v.get("dueDate")), "exploit_available": True,
                     "kev_ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known",
                     "kev_vendor": (v.get("vendorProject") or "")[:200], "kev_product": (v.get("product") or "")[:200],
                     "description": v.get("shortDescription")})
    for i in range(0, len(rows), 1000):
        stmt = insert(VulnIntel).values(rows[i:i + 1000])
        stmt = stmt.on_conflict_do_update(index_elements=[VulnIntel.cve_id], set_={
            k: getattr(stmt.excluded, k) for k in ("kev", "kev_date_added", "kev_due_date", "exploit_available",
                                                  "kev_ransomware", "kev_vendor", "kev_product")})
        db.execute(stmt)
    return len(rows)


def apply_epss_rows(db: Session, rows: Iterable[dict[str, Any]]) -> int:
    batch: list[dict[str, Any]] = []
    n = 0

    def flush() -> None:
        if not batch:
            return
        stmt = insert(VulnIntel).values(batch)
        stmt = stmt.on_conflict_do_update(index_elements=[VulnIntel.cve_id], set_={
            "epss_score": stmt.excluded.epss_score, "epss_percentile": stmt.excluded.epss_percentile,
            "epss_date": stmt.excluded.epss_date})
        db.execute(stmt)
        batch.clear()

    for r in rows:
        cve = str(r.get("cve", "")).upper()
        if not CVE_RE.match(cve):
            continue
        try:
            batch.append({"cve_id": cve, "epss_score": float(r["epss"]), "epss_percentile": float(r["percentile"]),
                          "epss_date": _d(r.get("date")) or date.today()})
        except (KeyError, ValueError, TypeError):
            continue
        n += 1
        if len(batch) >= 2000:
            flush()
    flush()
    return n


def parse_epss_csv(data: bytes) -> Iterable[dict[str, Any]]:
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    lines = [ln for ln in data.decode("utf-8", "replace").splitlines() if not ln.startswith("#")]
    return csv.DictReader(io.StringIO("\n".join(lines)))


def refresh_kev(db: Session, client: httpx.Client) -> int:
    st = _state(db, "kev")
    st.last_attempt_at = datetime.now(UTC)
    r = client.get(get_settings().intel_kev_url)
    r.raise_for_status()
    n = apply_kev(db, r.json())
    st.last_success_at, st.records, st.last_error = datetime.now(UTC), n, None
    return n


def refresh_epss(db: Session, client: httpx.Client, cves: list[str]) -> int:
    """Targeted EPSS lookups for CVEs present in findings (FIRST API, batches of 100)."""
    st = _state(db, "epss")
    st.last_attempt_at = datetime.now(UTC)
    n = 0
    for i in range(0, len(cves), 100):
        r = client.get(get_settings().intel_epss_api_url, params={"cve": ",".join(cves[i:i + 100])})
        r.raise_for_status()
        n += apply_epss_rows(db, r.json().get("data", []))
    st.last_success_at, st.records, st.last_error = datetime.now(UTC), n, None
    return n


def parse_nvd(doc: dict[str, Any]) -> dict[str, Any] | None:
    vulns = doc.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                         ("cvssMetricV2", "2.0")):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            if data.get("baseScore") is not None:
                desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), None)
                return {"cvss_score": float(data["baseScore"]), "cvss_vector": data.get("vectorString"),
                        "cvss_version": version, "description": desc,
                        "published_at": cve.get("published")}
    return None


def refresh_nvd(db: Session, client: httpx.Client, cves: list[str], max_lookups: int = 40) -> int:
    """Fill CVSS for CVEs that sensors reported without a score (NVD is rate limited: be gentle)."""
    import time

    known = {c for (c,) in db.execute(select(VulnIntel.cve_id).where(VulnIntel.cvss_score.is_not(None)))}
    todo = [c for c in cves if c not in known][:max_lookups]
    n = 0
    for i, cve in enumerate(todo):
        if i:
            time.sleep(6.5)  # public API: 5 requests / 30 s without a key
        r = client.get(get_settings().intel_nvd_api_url, params={"cveId": cve})
        if r.status_code != 200:
            continue
        parsed = parse_nvd(r.json())
        if not parsed:
            continue
        published = parsed.pop("published_at")
        values = {"cve_id": cve, **parsed,
                  "published_at": datetime.fromisoformat(published).replace(tzinfo=UTC) if published else None}
        stmt = insert(VulnIntel).values(values)
        db.execute(stmt.on_conflict_do_update(index_elements=[VulnIntel.cve_id], set_={
            k: getattr(stmt.excluded, k) for k in ("cvss_score", "cvss_vector", "cvss_version", "description",
                                                  "published_at")}))
        n += 1
    return n


def finding_cves(db: Session) -> list[str]:
    cves: set[str] = set()
    for (arr,) in db.execute(select(Finding.cve).where(func.cardinality(Finding.cve) > 0)):
        cves.update(c for c in arr or [] if CVE_RE.match(c))
    return sorted(cves)


def reenrich_findings() -> int:
    """Re-apply cached intel to open findings in every tenant; risk is recomputed nightly/after scans."""
    updated = 0
    with system_session() as sdb:
        tenants = [t for (t,) in sdb.execute(select(Tenant.id).where(Tenant.status == TenantStatus.ACTIVE))]
    for tid in tenants:
        with new_session(tid) as db:
            for f in db.execute(select(Finding).where(func.cardinality(Finding.cve) > 0, Finding.status.in_(
                    [s.value for s in OPEN_FINDING_STATES]))).scalars():
                enrich_from_intel(db, f)
                updated += 1
            db.commit()
            from app.risk.service import recompute_organization

            for org in db.execute(select(Organization)).scalars():
                recompute_organization(db, org)
            db.commit()
    return updated


def refresh_all() -> dict[str, Any]:
    s = get_settings()
    out: dict[str, Any] = {}
    if not s.intel_refresh_enabled:
        return {"skipped": "intel refresh disabled"}
    with system_session() as db, httpx.Client(timeout=60, headers={"User-Agent": "Exteriq-ASM"}) as client:
        for feed, fn in (("kev", lambda: refresh_kev(db, client)),
                         ("epss", lambda: refresh_epss(db, client, finding_cves(db))),
                         ("nvd", lambda: refresh_nvd(db, client, finding_cves(db)))):
            try:
                out[feed] = fn()
                db.commit()
            except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
                db.rollback()
                st = _state(db, feed)
                st.last_attempt_at, st.last_error = datetime.now(UTC), f"{type(exc).__name__}: {exc}"[:1000]
                db.commit()
                out[feed] = f"error: {type(exc).__name__}"
                log.warning("intel feed %s failed: %s", feed, exc)
    out["findings_enriched"] = reenrich_findings()
    return out


def import_files(kev_path: str | None = None, epss_path: str | None = None) -> dict[str, int]:
    out = {}
    with system_session() as db:
        if kev_path:
            with open(kev_path, "rb") as fh:
                out["kev"] = apply_kev(db, json.load(fh))
            _state(db, "kev").last_success_at = datetime.now(UTC)
        if epss_path:
            with open(epss_path, "rb") as fh:
                out["epss"] = apply_epss_rows(db, parse_epss_csv(fh.read()))
            _state(db, "epss").last_success_at = datetime.now(UTC)
        db.commit()
    out["findings_enriched"] = reenrich_findings()
    return out
