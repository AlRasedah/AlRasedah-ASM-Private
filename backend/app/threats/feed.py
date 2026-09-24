"""Automatic advisories from public vulnerability data.

The Threat Center is only useful if it keeps up without anyone typing advisories,
so this module writes them from two free, public-domain sources:

* **CISA KEV** — vulnerabilities known to be exploited in the wild. NVD flags them
  (``hasKev``), so one query returns all of them, with NVD's affected products and
  version ranges (CPE configurations). New and changed entries are fetched
  incrementally by modification date.
* optionally **recent critical CVEs** from NVD (CVSS v3 critical, published in the
  last N days), which are not known to be exploited yet.

Every CVE becomes a *feed* advisory (``origin = "feed"``) whose affected products
and version ranges come from NVD's CPE data, with product names mapped to what
fingerprinting reports (built-in aliases plus the platform's own). KEV advisories
are published automatically by default; others wait as drafts (configurable). The
feed never touches an advisory a platform administrator wrote for the same CVE.

Nothing here changes how matches are judged: a version match is still "potentially
affected" and never "confirmed". An advisory whose products NVD has not analysed yet
still matches through findings that name its CVE, and is updated when NVD adds them.

Everything is deterministic and bounded: pages of at most 2 000 CVEs, NVD's rate
limits (5 requests / 30 s, or 50 with a free API key), a time budget per run.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import get_settings
from app.core.errors import ValidationFailed
from app.models import IntelFeedState, PlatformSetting, ThreatAdvisory, ThreatCheck, ThreatFeedItem, VulnIntel
from app.models.enums import AdvisoryStatus, Severity
from app.services import audit
from app.services.audit import Action

from . import service
from .content import _NAME_RE, CVE_RE, KEY_RE, AdvisoryContent, norm_name
from .versions import UnparseableVersion, Version

log = logging.getLogger(__name__)

NVD_KEY_AAD = "platform:nvd-api-key"
PUBLISH_MODES = ("kev", "all", "none")
DEFAULTS: dict[str, Any] = {
    "enabled": True,
    "publish": "kev",  # kev: publish exploited-in-the-wild automatically, others as drafts
    "include_critical": False,  # also recent critical CVEs that are not (yet) known exploited
    "critical_days": 30,
    "auto_checks": True,  # link the community detection named after the CVE as its approved check
    "aliases": {},  # {"vendor:product": ["name as fingerprinting reports it", ...]}
}
PAGE_SIZE = 2000
MAX_WINDOW = timedelta(days=110)  # NVD allows 120 days per date-range query
RUN_BUDGET_S = 600.0
MAX_APPLY_PER_RUN = 3000
MAX_DIRECT_LOOKUPS = 10  # KEV entries NVD has not flagged yet, looked up one by one

# Names fingerprinting (technology detection, service banners, Server headers) uses for
# products whose NVD name differs. Keys are NVD CPE "vendor:product".
BUILTIN_ALIASES: dict[str, list[str]] = {
    "apache:http_server": ["apache", "apache http server", "apache httpd", "httpd"],
    "apache:tomcat": ["apache tomcat", "tomcat"],
    "microsoft:internet_information_services": ["iis", "microsoft iis", "microsoft-iis"],
    "microsoft:exchange_server": ["microsoft exchange", "microsoft exchange server", "outlook web app"],
    "microsoft:sharepoint_server": ["microsoft sharepoint", "sharepoint"],
    "fortinet:fortios": ["fortigate", "fortinet fortigate", "fortios"],
    "fortinet:fortiproxy": ["fortiproxy"],
    "citrix:netscaler_application_delivery_controller": ["citrix adc", "netscaler", "citrix netscaler"],
    "citrix:netscaler_gateway": ["citrix gateway", "netscaler gateway"],
    "ivanti:connect_secure": ["ivanti connect secure", "pulse secure", "pulse connect secure"],
    "pulsesecure:pulse_connect_secure": ["pulse secure", "pulse connect secure"],
    "atlassian:confluence_server": ["confluence", "atlassian confluence"],
    "atlassian:confluence_data_center": ["confluence", "atlassian confluence"],
    "atlassian:jira_server": ["jira", "atlassian jira"],
    "atlassian:jira_data_center": ["jira", "atlassian jira"],
    "vmware:vcenter_server": ["vmware vcenter", "vcenter"],
    "f5:big-ip_local_traffic_manager": ["f5 big-ip", "big-ip"],
    "f5:big-ip_access_policy_manager": ["f5 big-ip", "big-ip"],
    "paloaltonetworks:pan-os": ["pan-os", "palo alto globalprotect", "globalprotect"],
    "progress:moveit_transfer": ["moveit", "moveit transfer"],
    "oracle:weblogic_server": ["weblogic", "oracle weblogic"],
    "zimbra:collaboration": ["zimbra"],
    "synacor:zimbra_collaboration_suite": ["zimbra"],
    "openbsd:openssh": ["openssh"],
    "f5:nginx": ["nginx"],
    "gitlab:gitlab": ["gitlab"],
    "jenkins:jenkins": ["jenkins"],
    "sonicwall:sma_100_firmware": ["sonicwall sma"],
    "cisco:adaptive_security_appliance_software": ["cisco asa", "cisco adaptive security appliance"],
}
# NVD product names too generic to match on their own (the vendor + product name still does).
GENERIC_PRODUCTS = {
    "http_server", "server", "web_server", "application_server", "firmware", "router", "gateway", "portal",
    "firewall", "switch", "camera", "nas", "vpn", "console", "management_console", "platform", "suite",
    "multiple_products", "client", "agent", "enterprise", "cloud", "manager", "system", "software",
}


class FeedError(Exception):
    pass


def _now() -> datetime:
    return datetime.now(UTC)


# ======================================================================== settings
def settings(db: Session) -> dict[str, Any]:
    row = db.get(PlatformSetting, 1)
    stored = dict(row.threat_feed or {}) if row is not None else {}
    out = dict(DEFAULTS)
    out.update({k: v for k, v in stored.items() if k in DEFAULTS})
    return out


def nvd_api_key(db: Session) -> str | None:
    row = db.get(PlatformSetting, 1)
    if row is None or not row.nvd_api_key_ciphertext:
        return None
    return crypto.decrypt(row.nvd_api_key_ciphertext, NVD_KEY_AAD).decode()


def _alias_key(value: str) -> str:
    return value.strip().lower()


def clean_aliases(raw: Any) -> dict[str, list[str]]:
    if not isinstance(raw, dict) or len(raw) > 500:
        raise ValidationFailed("Aliases must map at most 500 'vendor:product' keys to lists of names")
    out: dict[str, list[str]] = {}
    for key, names in raw.items():
        k = _alias_key(str(key))
        if not re.match(r"^[a-z0-9][a-z0-9_.+\-!~]{0,79}:[a-z0-9][a-z0-9_.+\-!~]{0,119}$", k):
            raise ValidationFailed(f"alias key {key!r} must look like vendor:product (as in NVD)")
        if not isinstance(names, list) or not 1 <= len(names) <= 10:
            raise ValidationFailed(f"alias {key!r} needs 1 to 10 names")
        clean = sorted({norm_name(str(n)) for n in names})
        bad = [n for n in clean if not _NAME_RE.match(n)]
        if bad:
            raise ValidationFailed(f"invalid product name {bad[0]!r}: letters, digits, spaces and . _ + / - only")
        out[k] = clean
    return out


def set_settings(db: Session, values: dict[str, Any], *, api_key: str | None = None, clear_key: bool = False,
                 user_id: uuid.UUID | None = None) -> dict[str, Any]:
    """Platform administrators only (system session)."""
    row = db.get(PlatformSetting, 1)
    if row is None:
        row = PlatformSetting(id=1, smtp={}, screenshots={}, threat_feed={})
        db.add(row)
        db.flush()
    before = dict(row.threat_feed or {})
    merged = dict(before)
    for k, v in values.items():
        if k not in DEFAULTS or v is None:
            continue
        if k in ("enabled", "include_critical", "auto_checks"):
            if not isinstance(v, bool):
                raise ValidationFailed(f"{k} must be true or false")
        elif k == "publish":
            if v not in PUBLISH_MODES:
                raise ValidationFailed("publish must be one of: " + ", ".join(PUBLISH_MODES))
        elif k == "critical_days":
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 110:
                raise ValidationFailed("critical_days must be between 1 and 110")
        elif k == "aliases":
            v = clean_aliases(v)
        merged[k] = v
    row.threat_feed = merged
    key_change = None
    if clear_key:
        row.nvd_api_key_ciphertext, key_change = None, "removed"
    elif api_key:
        if not re.match(r"^[A-Za-z0-9-]{16,64}$", api_key.strip()):
            raise ValidationFailed("That does not look like an NVD API key")
        row.nvd_api_key_ciphertext, key_change = crypto.encrypt(api_key.strip().encode(), NVD_KEY_AAD), "set"
    row.updated_by = user_id
    prev, new = audit.diff(before, merged)
    if key_change:
        new["nvd_api_key"] = key_change  # never the key itself
    audit.record(db, Action.THREAT_FEED_CHANGED, platform=True, object_type="threat_feed", previous=prev, new=new)
    db.flush()
    return settings(db)


# ========================================================================= parsing
_CPE_SPLIT = re.compile(r"(?<!\\):")


def parse_cpe(criteria: str) -> tuple[str, str, str, str, str] | None:
    """cpe:2.3:part:vendor:product:version:update:... → (part, vendor, product, version, update)."""
    parts = _CPE_SPLIT.split(criteria)
    if len(parts) < 7 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    unescape = lambda s: re.sub(r"\\(.)", r"\1", s)  # noqa: E731
    return parts[2], unescape(parts[3]).lower(), unescape(parts[4]).lower(), unescape(parts[5]), unescape(parts[6])


def _bound(value: Any) -> str | None:
    if not value or not isinstance(value, str) or len(value) > 64:
        return None
    try:
        Version.parse(value)
    except UnparseableVersion:
        return None
    return value


def _range_of(m: dict[str, Any], version: str) -> dict[str, str] | None:
    """One CPE match → a version range; None means every version."""
    if version not in ("*", "-", ""):
        exact = _bound(version)
        return {"introduced": exact, "last_affected": exact} if exact else None
    # NVD's "start excluding" becomes an inclusive start: one version too many is
    # "potentially affected", never a missed one.
    r = {"introduced": _bound(m.get("versionStartIncluding") or m.get("versionStartExcluding")),
         "fixed": _bound(m.get("versionEndExcluding")),
         "last_affected": None if m.get("versionEndExcluding") else _bound(m.get("versionEndIncluding"))}
    r = {k: v for k, v in r.items() if v}
    return r or None


def parse_record(cve: dict[str, Any]) -> dict[str, Any] | None:
    """One NVD CVE object → what an advisory needs. None when it is not usable."""
    cve_id = str(cve.get("id", "")).upper()
    if not CVE_RE.match(cve_id) or cve.get("vulnStatus") == "Rejected":
        return None
    products: dict[tuple[str, str], dict[str, Any]] = {}
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if node.get("negate"):
                continue
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue  # a platform it runs on, not the vulnerable product
                parsed = parse_cpe(str(m.get("criteria", "")))
                if parsed is None or parsed[0] not in ("a", "o"):
                    continue  # hardware is never fingerprinted by name here
                _, vendor, product, version, _update = parsed
                p = products.setdefault((vendor, product), {"vendor": vendor, "product": product, "part": parsed[0],
                                                            "all_versions": False, "ranges": []})
                r = _range_of(m, version)
                if r is None:
                    p["all_versions"] = True
                elif r not in p["ranges"]:
                    p["ranges"].append(r)
    score, cvss_version = None, None
    for key, ver in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"),
                     ("cvssMetricV2", "2.0")):
        primary = [x for x in cve.get("metrics", {}).get(key, []) if x.get("type") == "Primary"] \
            or cve.get("metrics", {}).get(key, [])
        if primary and primary[0].get("cvssData", {}).get("baseScore") is not None:
            score, cvss_version = float(primary[0]["cvssData"]["baseScore"]), ver
            break
    desc = next((d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "") or ""
    refs = []
    for r in cve.get("references") or []:
        url = str(r.get("url", ""))
        if url.startswith(("https://", "http://")) and len(url) <= 1000 and url not in refs:
            refs.append(url)
    return {
        "cve": cve_id, "published": cve.get("published"), "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"), "description": desc[:4000], "cvss": score, "cvss_version": cvss_version,
        "kev_added": cve.get("cisaExploitAdd"), "kev_name": cve.get("cisaVulnerabilityName"),
        "kev_action": cve.get("cisaRequiredAction"), "references": refs[:20],
        "products": sorted(products.values(), key=lambda p: (p["part"] != "a", p["vendor"], p["product"])),
    }


def _clean_name(value: str) -> str | None:
    n = norm_name(re.sub(r"[^a-z0-9 ._+/\-]", " ", value.lower()))
    return n if _NAME_RE.match(n) and len(n) >= 3 else None


def names_for(vendor: str, product: str, aliases: dict[str, list[str]]) -> list[str]:
    """What fingerprinting might call this NVD product."""
    key = f"{vendor}:{product}"
    names = list(aliases.get(key, [])) + BUILTIN_ALIASES.get(key, [])
    if vendor and vendor != product:
        names.append(f"{vendor} {product}")
    if product not in GENERIC_PRODUCTS:
        names.append(product)
    out = []
    for n in names:
        c = _clean_name(n)
        if c and c not in out:
            out.append(c)
    return out[:10]


def _severity(score: float | None, kev: bool) -> Severity:
    if score is None:
        return Severity.HIGH if kev else Severity.MEDIUM
    for floor, sev in ((9.0, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM)):
        if score >= floor:
            return sev
    return Severity.LOW


def _collapse(ranges: list[dict[str, str]]) -> list[dict[str, str]]:
    """More ranges than an advisory holds: one range from the lowest start to the highest end
    (over-inclusive, so nothing affected is missed)."""
    starts = [Version.parse(r["introduced"]) for r in ranges if r.get("introduced")]
    ends = [(Version.parse(r.get("fixed") or r["last_affected"]), r.get("fixed") is not None, r)
            for r in ranges if r.get("fixed") or r.get("last_affected")]
    out: dict[str, str] = {}
    if starts and len(starts) == len(ranges):
        out["introduced"] = next(r["introduced"] for r in ranges if Version.parse(r["introduced"]) == min(starts))
    if ends and len(ends) == len(ranges):
        top = max(ends, key=lambda e: e[0])
        out["fixed" if top[1] else "last_affected"] = top[2].get("fixed") or top[2]["last_affected"]
    return [out] if out else []


def content_for(record: dict[str, Any], aliases: dict[str, list[str]], check_key: str | None,
                kev_names: tuple[str | None, str | None] = (None, None)) -> AdvisoryContent:
    cve = record["cve"]
    affected = []
    for p in record["products"]:
        names = names_for(p["vendor"], p["product"], aliases)
        if not names:
            continue
        ranges = [] if p["all_versions"] else p["ranges"]
        if len(ranges) > 20:
            ranges = _collapse(ranges)
        affected.append({"vendor": p["vendor"].replace("_", " ")[:120] or None,
                         "product": p["product"].replace("_", " ")[:120], "match_names": names,
                         "versions": ranges})
    # CISA's own vendor/product names, when they clearly belong to one NVD product.
    kv, kp = kev_names
    if kv and kp:
        same_vendor = [a for a in affected if norm_name(a["vendor"] or "") == norm_name(kv)]
        extra = _clean_name(f"{kv} {kp}")
        if len(same_vendor) == 1 and extra and extra not in same_vendor[0]["match_names"] \
                and len(same_vendor[0]["match_names"]) < 10:
            same_vendor[0]["match_names"].append(extra)
    kev = bool(record.get("kev_added"))
    title = (record.get("kev_name") or "").strip()
    if len(title) < 3:
        first = affected[0] if affected else None
        title = f"{cve}: {first['vendor']} {first['product']}" if first else cve
    remediation = "\n\n".join(x for x in (
        (record.get("kev_action") or "").strip(),
        "Apply the vendor's fix or mitigation; the references list the vendor advisory.",
        "Generated automatically from CISA KEV and NVD data. This product uses the NVD API but is not endorsed "
        "or certified by the NVD.") if x)
    published = record.get("kev_added") or record.get("published")
    try:
        return AdvisoryContent.model_validate({
            "title": title[:300], "summary": record.get("description") or "", "severity": _severity(record.get("cvss"),
                                                                                                    kev),
            "cves": [cve], "references": record.get("references") or [], "affected": affected[:20],
            "remediation": remediation[:8000], "check_keys": [check_key] if check_key else [],
            "source_published_at": _dt(published), "source_updated_at": _dt(record.get("last_modified")),
        })
    except ValueError as exc:
        raise FeedError(f"{cve}: {str(exc)[:200]}") from exc


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        d = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=UTC)


# ======================================================================== fetching
_sleep = time.sleep  # replaced in tests


class NvdClient:
    """NVD CVE API 2.0 with its published rate limits, bounded by a time budget."""

    def __init__(self, client: httpx.Client, api_key: str | None, deadline: float) -> None:
        self.client, self.deadline = client, deadline
        self.headers = {"apiKey": api_key} if api_key else {}
        self.gap = 0.7 if api_key else 6.5
        self._last = 0.0
        self.requests = 0

    def _get(self, flags: list[str], params: dict[str, str]) -> dict[str, Any]:
        if time.monotonic() > self.deadline:
            raise FeedError("the run's time budget is used up; the rest is fetched next time")
        wait = self._last + self.gap - time.monotonic()
        if self._last and wait > 0:
            _sleep(wait)
        # hasKev and noRejected are flags without a value.
        query = "&".join([*flags, *([urlencode(params, safe=":")] if params else [])])
        url = f"{get_settings().intel_nvd_api_url}?{query}"
        self._last = time.monotonic()
        self.requests += 1
        try:
            r = self.client.get(url, headers=self.headers)
        except httpx.HTTPError as exc:
            raise FeedError(f"NVD could not be reached: {type(exc).__name__}") from exc
        if r.status_code in (403, 429, 503):
            raise FeedError(f"NVD refused the request (HTTP {r.status_code}); it is retried on the next run")
        if r.status_code != 200:
            raise FeedError(f"NVD answered HTTP {r.status_code}")
        try:
            return r.json()
        except ValueError as exc:
            raise FeedError("NVD sent something that is not JSON") from exc

    def cves(self, flags: list[str], params: dict[str, str]) -> Any:
        start = 0
        while True:
            doc = self._get(flags, {**params, "resultsPerPage": str(PAGE_SIZE), "startIndex": str(start)})
            items = doc.get("vulnerabilities") or []
            for v in items:
                if isinstance(v, dict) and isinstance(v.get("cve"), dict):
                    yield v["cve"]
            start += len(items)
            if not items or start >= int(doc.get("totalResults") or 0):
                return


def _nvd_time(d: datetime) -> str:
    return d.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _state(db: Session, feed: str) -> IntelFeedState:
    st = db.get(IntelFeedState, feed)
    if st is None:
        st = IntelFeedState(feed=feed)
        db.add(st)
        db.flush()
    return st


def _store(db: Session, record: dict[str, Any], source: str) -> None:
    item = db.get(ThreatFeedItem, record["cve"])
    kev = bool(record.get("kev_added"))
    modified = _dt(record.get("last_modified"))
    if item is None:
        db.add(ThreatFeedItem(cve_id=record["cve"], source="kev" if kev else source, kev=kev,
                              nvd_last_modified=modified, record=record, status="pending"))
        return
    if item.nvd_last_modified and modified and modified <= item.nvd_last_modified and item.kev == kev:
        return
    item.record, item.nvd_last_modified, item.kev = record, modified, kev or item.kev
    if kev:
        item.source = "kev"


def _fetch(db: Session, nvd: NvdClient, s: dict[str, Any], now: datetime) -> dict[str, Any]:
    out: dict[str, Any] = {"fetched": 0, "errors": []}

    def pull(feed: str, flags: list[str], params: dict[str, str], source: str) -> None:
        st = _state(db, feed)
        st.last_attempt_at = now
        try:
            n = 0
            for cve in nvd.cves(flags, params):
                rec = parse_record(cve)
                if rec is not None:
                    _store(db, rec, source)
                    n += 1
                    if n % 500 == 0:
                        db.flush()
            st.last_success_at, st.records, st.last_error = now, n, None
            out["fetched"] += n
        except FeedError as exc:
            st.last_error = str(exc)[:1000]
            out["errors"].append(f"{feed}: {exc}")
        db.commit()

    kev_state = _state(db, "threat_feed_kev")
    since = kev_state.last_success_at
    if since and now - since < MAX_WINDOW:
        pull("threat_feed_kev", ["hasKev", "noRejected"],
             {"lastModStartDate": _nvd_time(since - timedelta(hours=1)), "lastModEndDate": _nvd_time(now)}, "kev")
    else:
        pull("threat_feed_kev", ["hasKev", "noRejected"], {}, "kev")
    if s["include_critical"]:
        crit = _state(db, "threat_feed_critical")
        start = max(crit.last_success_at - timedelta(hours=1) if crit.last_success_at else now - MAX_WINDOW,
                    now - timedelta(days=int(s["critical_days"])))
        pull("threat_feed_critical", ["noRejected"], {"cvssV3Severity": "CRITICAL", "pubStartDate": _nvd_time(start),
                                                      "pubEndDate": _nvd_time(now)}, "critical")
    # CISA lists a new KEV entry before NVD flags it: look those up one by one.
    seen = select(ThreatFeedItem.cve_id)
    fresh = list(db.execute(select(VulnIntel.cve_id).where(
        VulnIntel.kev.is_(True), VulnIntel.kev_date_added >= (now - timedelta(days=14)).date(),
        VulnIntel.cve_id.not_in(seen)).limit(MAX_DIRECT_LOOKUPS)).scalars())
    for cve_id in fresh:
        try:
            for cve in nvd.cves([], {"cveId": cve_id}):
                rec = parse_record(cve)
                if rec is not None:
                    rec["kev_added"] = rec.get("kev_added") or str(now.date())
                    _store(db, rec, "kev")
                    out["fetched"] += 1
        except FeedError as exc:
            out["errors"].append(f"{cve_id}: {exc}")
            break
    db.commit()
    return out


# ======================================================================= applying
def _check_for(db: Session, cve: str, s: dict[str, Any]) -> str | None:
    key = cve.lower()
    row = db.execute(select(ThreatCheck).where(ThreatCheck.key == key)).scalar_one_or_none()
    if row is None:
        # An approved check a platform administrator set up for this CVE under another key.
        row = db.execute(select(ThreatCheck).where(func.lower(ThreatCheck.template_id) == key,
                                                   ThreatCheck.enabled.is_(True))).scalars().first()
        if row is None and s["auto_checks"] and KEY_RE.match(key):
            row = service.save_check(
                db, key=key, name=f"{cve} community detection",
                description=("Added by the automatic feed: the community detection named after this CVE. If the "
                             "scanner's template set has none, or it is classified intrusive, a check is inconclusive "
                             "and says so."), template_id=key, enabled=True, user_id=None, audited=False)
    return row.key if row is not None and row.enabled else None


def _kev_names(db: Session, cve: str) -> tuple[str | None, str | None]:
    row = db.get(VulnIntel, cve)
    return (row.kev_vendor, row.kev_product) if row is not None and row.kev else (None, None)


def _current_content(db: Session, adv: ThreatAdvisory) -> dict[str, Any] | None:
    draft = service.draft_of(db, adv.id)
    ver = draft or service.published_of(db, adv)
    return ver.content if ver is not None else None


def apply_item(db: Session, item: ThreatFeedItem, s: dict[str, Any]) -> str:
    """Create or update the advisory for one feed item. Returns what happened."""
    cve = item.cve_id
    slug = cve.lower()
    adv = db.execute(select(ThreatAdvisory).where(ThreatAdvisory.slug == slug)).scalar_one_or_none()
    item.applied_last_modified = item.nvd_last_modified
    if adv is not None and adv.origin != "feed":
        item.status, item.advisory_id = "manual", adv.id
        item.detail = "a platform administrator's advisory exists for this CVE; the feed leaves it alone"
        return "manual"
    if adv is not None and adv.status == AdvisoryStatus.ARCHIVED:
        item.status, item.advisory_id, item.detail = "archived", adv.id, "archived by a platform administrator"
        return "archived"
    content = content_for(item.record, s["aliases"], _check_for(db, cve, s), _kev_names(db, cve))
    body = content.model_dump(mode="json")
    changed = False
    if adv is None:
        adv = service.create_advisory(db, slug=slug, content=content, user_id=None, origin="feed", audited=False)
        changed = True
    elif _current_content(db, adv) != body:
        service.save_draft(db, adv.id, content, None, audited=False)
        changed = True
    auto = s["publish"] == "all" or (s["publish"] == "kev" and item.kev)
    published = False
    if auto and service.draft_of(db, adv.id) is not None:
        service.publish(db, adv.id, None, audited=False)
        published = True
    item.advisory_id = adv.id
    item.status = "draft" if service.draft_of(db, adv.id) is not None else "published"
    item.detail = None if content.affected else "NVD has no product data for this CVE yet: matched through findings only"
    return "published" if published else ("updated" if changed else "unchanged")


def run(client: httpx.Client | None = None, now: datetime | None = None) -> dict[str, Any]:
    """One feed run (hourly): fetch what changed, then write advisories. System session."""
    from app.db.session import system_session

    now = now or _now()
    with system_session() as db:
        s = settings(db)
        if not s["enabled"]:
            return {"skipped": "the automatic feed is turned off"}
        own = client is None
        client = client or httpx.Client(timeout=60, headers={"User-Agent": "Exteriq-ASM threat feed"})
        try:
            nvd = NvdClient(client, nvd_api_key(db), time.monotonic() + RUN_BUDGET_S)
            out = _fetch(db, nvd, s, now)
        finally:
            if own:
                client.close()
        counts: dict[str, int] = defaultdict(int)
        todo = list(db.execute(select(ThreatFeedItem).where(
            (ThreatFeedItem.applied_last_modified.is_(None))
            | (ThreatFeedItem.nvd_last_modified > ThreatFeedItem.applied_last_modified)
            | (ThreatFeedItem.status.in_(["pending", "failed"])))
            .order_by(ThreatFeedItem.kev.desc(), ThreatFeedItem.cve_id.desc()).limit(MAX_APPLY_PER_RUN)).scalars())
        for i, item in enumerate(todo):
            try:
                with db.begin_nested():
                    counts[apply_item(db, item, s)] += 1
            except (FeedError, ValidationFailed, ValueError) as exc:
                item.status, item.detail = "failed", str(exc)[:300]
                item.applied_last_modified = item.nvd_last_modified
                counts["failed"] += 1
            if i % 100 == 99:
                db.commit()
        out.update(dict(counts), requests=nvd.requests)
        if todo or out["errors"]:
            audit.record(db, Action.THREAT_FEED_RUN, platform=True, object_type="threat_feed",
                         new={k: v for k, v in out.items() if k != "errors"} | {"errors": out["errors"][:5]})
        db.commit()
    out["evaluate"] = bool(counts.get("published") or counts.get("updated"))
    return out


def status(db: Session) -> dict[str, Any]:
    """What the platform administrator sees."""
    by_status = dict(db.execute(select(ThreatFeedItem.status, func.count()).group_by(ThreatFeedItem.status)).all())
    kev = db.scalar(select(func.count()).select_from(ThreatFeedItem).where(ThreatFeedItem.kev.is_(True))) or 0
    states = {f: db.get(IntelFeedState, f) for f in ("threat_feed_kev", "threat_feed_critical")}
    return {
        "items": sum(by_status.values()), "kev_items": kev, "by_status": by_status,
        "sources": {f.removeprefix("threat_feed_"): ({"last_success_at": st.last_success_at,
                                                      "last_attempt_at": st.last_attempt_at,
                                                      "last_error": st.last_error, "records": st.records}
                                                     if st else None) for f, st in states.items()},
        "has_api_key": nvd_api_key(db) is not None,
    }
