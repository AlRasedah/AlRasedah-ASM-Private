"""Report generation (HTML, PDF, CSV)."""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assets.queries import display_ips
from app.changes.knowledge import service_label
from app.db.session import new_session
from app.models import Asset, AssetEvent, Finding, Organization, Report, Tenant
from app.models.enums import (
    OPEN_FINDING_STATES,
    PRIMARY_TYPES,
    AssetStatus,
    AssetType,
    JobStatus,
    ReportFormat,
    ReportType,
    ScopeStatus,
)
from app.reporting import charts
from app.services import audit, dashboard
from app.services.audit import Action
from app.services.storage import get_store
from app.tenants.settings import tenant_settings

log = logging.getLogger(__name__)
_env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
                   autoescape=select_autoescape(["html"]))

TITLES = {
    ReportType.EXECUTIVE: "Executive Attack Surface Report",
    ReportType.TECHNICAL: "Technical Attack Surface Report",
    ReportType.ASSET_INVENTORY: "Asset Inventory Report",
    ReportType.VULNERABILITY: "Vulnerability Report",
    ReportType.CHANGES: "Attack Surface Change Report",
    ReportType.RISK_TREND: "Risk Trend Report",
}
SECTIONS = {
    ReportType.EXECUTIVE: {"summary", "top_risks", "growth"},
    ReportType.TECHNICAL: {"summary", "top_risks", "exposure", "findings", "changes"},
    ReportType.ASSET_INVENTORY: {"inventory"},
    ReportType.VULNERABILITY: {"summary", "findings"},
    ReportType.CHANGES: {"changes"},
    ReportType.RISK_TREND: {"trend", "growth"},
}
CSV_TYPES = {ReportType.ASSET_INVENTORY, ReportType.VULNERABILITY, ReportType.CHANGES, ReportType.RISK_TREND}
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")


class ReportError(RuntimeError):
    pass


def _d(dt: datetime | None) -> str:
    return dt.strftime("%Y-%m-%d %H:%M UTC") if dt else ""


def _factors(f: Finding, n: int = 3) -> str:
    top = sorted(f.risk_factors or [], key=lambda x: -abs(x.get("points", 0)))[:n]
    return "; ".join(x["label"] for x in top)


def _finding_row(f: Finding, assets: dict[uuid.UUID, Asset]) -> dict[str, Any]:
    a = assets.get(f.asset_id)
    return {"title": f.title, "severity": f.severity.value, "risk_score": f.risk_score, "status": f.status.value,
            "asset": a.value if a else "", "location": f.location, "cve": f.cve or [], "cvss": f.cvss_score,
            "epss": f"{f.epss_score:.1%}" if f.epss_score else None, "kev": f.kev,
            "description": (f.description or "")[:1500], "remediation": f.remediation,
            "first_seen": _d(f.first_seen), "factors": _factors(f)}


def build_context(db: Session, report: Report) -> dict[str, Any]:
    params = report.parameters or {}
    days = int(params.get("days", 30))
    org_id = report.organization_id
    tenant = db.get(Tenant, report.tenant_id)
    org = db.get(Organization, org_id) if org_id else None
    branding = tenant_settings(tenant).get("branding", {}) if tenant else {}
    accent = branding.get("primary_color") if _HEX.match(str(branding.get("primary_color", ""))) else "#a3571f"
    since = datetime.now(UTC) - timedelta(days=days)

    s = dashboard.summary(db, org_id)
    trend = dashboard.trends(db, org_id, max(days, 7))

    # Reports cover confirmed issues only; unverified third-party reports are excluded.
    fq = select(Finding).where(Finding.status.in_([x.value for x in OPEN_FINDING_STATES]),
                               Finding.unverified.is_(False))
    if org_id:
        fq = fq.where(Finding.organization_id == org_id)
    open_findings = db.execute(fq.order_by(Finding.risk_score.desc())).scalars().all()
    asset_ids = {f.asset_id for f in open_findings}
    assets_by_id = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_(asset_ids))).scalars()} if asset_ids else {}
    findings = [_finding_row(f, assets_by_id) for f in open_findings]

    aq = select(Asset).where(Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE)
    if org_id:
        aq = aq.where(Asset.organization_id == org_id)
    active_assets = db.execute(aq.order_by(Asset.risk_score.desc(), Asset.normalized_value)).scalars().all()
    inventory = [{"value": a.value, "type": a.asset_type.value, "ip": " ".join(display_ips(a)),
                  "approval": a.approval_status.value, "owner": a.owner or "", "first_seen": _d(a.first_seen),
                  "last_seen": _d(a.last_seen), "risk_score": a.risk_score, "open_findings": a.open_findings}
                 for a in active_assets if a.asset_type in PRIMARY_TYPES]
    services = []
    for a in active_assets:
        if a.asset_type == AssetType.PORT:
            port = (a.meta or {}).get("port")
            services.append({"value": a.value, "detail": (service_label(int(port)) if port else None) or "",
                             "risk_score": a.risk_score, "first_seen": _d(a.first_seen)})
    endpoints = [{"value": a.value, "status_code": (a.meta or {}).get("status_code"), "title": (a.meta or {}).get("title"),
                  "tech": ", ".join((a.meta or {}).get("technologies") or []), "risk_score": a.risk_score}
                 for a in active_assets if a.asset_type == AssetType.HTTP_ENDPOINT]

    eq = select(AssetEvent).where(AssetEvent.is_baseline.is_(False), AssetEvent.occurred_at >= since)
    if org_id:
        eq = eq.where(AssetEvent.organization_id == org_id)
    events = [{"when": _d(e.occurred_at), "severity": e.severity.value, "title": e.title,
               "event_type": e.event_type.value, "asset": e.asset_value or "",
               "diff": (f"{json.dumps(e.previous_state, default=str)} → {json.dumps(e.new_state, default=str)}"
                        if e.previous_state or e.new_state else "")[:400]}
              for e in db.execute(eq.order_by(AssetEvent.occurred_at.desc()).limit(5000)).scalars()]

    t = s["totals"]
    key_messages = []
    if t["new_assets_7d"]:
        key_messages.append(f"{t['new_assets_7d']} new internet-facing asset(s) appeared in the last 7 days.")
    if t["unknown_assets"]:
        key_messages.append(f"{t['unknown_assets']} active asset(s) have unverified ownership (potential shadow IT) "
                            "and should be reviewed.")
    if t["kev_findings"]:
        key_messages.append(f"{t['kev_findings']} open finding(s) involve vulnerabilities known to be exploited in the "
                            "wild (CISA KEV) — treat as urgent.")
    if not key_messages:
        key_messages.append("No urgent changes were detected in this period.")
    recommendations = []
    for f in open_findings[:5]:
        if f.remediation and f.remediation not in recommendations:
            recommendations.append(f.remediation)

    sev = s["findings_by_severity"]
    type_counts = sorted(((k.replace("_", " "), v) for k, v in s["asset_types"].items()
                          if AssetType(k) in PRIMARY_TYPES), key=lambda x: -x[1])
    ctx = {
        "title": params.get("title") or TITLES[report.report_type],
        "brand": branding.get("name") or "Exteriq ASM",
        "accent": accent,
        "classification": params.get("classification") or "Confidential",
        "tenant": tenant.name if tenant else "",
        "organization": org.name if org else None,
        "generated_at": _d(datetime.now(UTC)),
        "days": days,
        "sections": {k: True for k in SECTIONS[report.report_type]},
        "s": s,
        "trend": trend,
        "top_findings": findings[:10],
        "findings": findings if report.report_type != ReportType.EXECUTIVE else [],
        "assets": inventory,
        "services": services[:500],
        "endpoints": endpoints[:500],
        "certificates": s["expiring_certificates"],
        "events": events,
        "key_messages": key_messages,
        "recommendations": recommendations,
        "charts": {
            "severity": charts.hbars([(k, sev[k]) for k in ("critical", "high", "medium", "low", "info")],
                                     charts.SEVERITY_COLORS),
            "risk_trend": charts.line([(x["day"], x["risk_score"]) for x in trend], max_value=100),
            "growth": charts.line([(x["day"], x["active_assets"]) for x in trend], color="#475467"),
            "types": charts.hbars(type_counts[:8]),
            "hosting": charts.hbars([(h["provider"], h["count"]) for h in s["hosting_distribution"][:8]]),
        },
    }
    return ctx


def render_html(ctx: dict[str, Any]) -> bytes:
    return _env.get_template("report.html").render(**ctx).encode("utf-8")


def render_pdf(html: bytes) -> bytes:
    try:
        from weasyprint import HTML  # optional dependency (pip install exteriq-asm[pdf])
    except (ImportError, OSError) as exc:
        raise ReportError("PDF rendering is not available in this deployment (WeasyPrint missing)") from exc
    return HTML(string=html.decode("utf-8")).write_pdf()


def _safe(v: Any) -> Any:
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render_csv(report: Report, ctx: dict[str, Any]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    rt = report.report_type
    if rt == ReportType.ASSET_INVENTORY:
        cols = ["value", "type", "ip", "approval", "owner", "first_seen", "last_seen", "risk_score", "open_findings"]
        rows = ctx["assets"]
    elif rt == ReportType.VULNERABILITY:
        cols = ["title", "severity", "risk_score", "status", "asset", "location", "cve", "cvss", "epss", "kev",
                "first_seen", "remediation"]
        rows = [{**f, "cve": " ".join(f["cve"])} for f in ctx["findings"]]
    elif rt == ReportType.CHANGES:
        cols = ["when", "severity", "event_type", "asset", "title", "diff"]
        rows = ctx["events"]
    elif rt == ReportType.RISK_TREND:
        cols = ["day", "risk_score", "total_assets", "active_assets", "new_assets", "unknown_assets", "critical", "high",
                "medium", "low"]
        rows = ctx["trend"]
    else:
        raise ReportError("CSV is available for inventory, vulnerability, change and trend reports")
    w.writerow(cols)
    for r in rows:
        w.writerow([_safe(r.get(c)) for c in cols])
    return buf.getvalue().encode("utf-8")


EXT = {ReportFormat.HTML: ("html", "text/html"), ReportFormat.PDF: ("pdf", "application/pdf"),
       ReportFormat.CSV: ("csv", "text/csv")}


def run_report(tenant_id: uuid.UUID, report_id: uuid.UUID) -> None:
    with new_session(tenant_id) as db:
        report = db.get(Report, report_id)
        if report is None or report.status not in (JobStatus.PENDING, JobStatus.FAILED):
            return
        report.status = JobStatus.RUNNING
        db.commit()
        try:
            ctx = build_context(db, report)
            if report.report_format == ReportFormat.CSV:
                data = render_csv(report, ctx)
            else:
                html = render_html(ctx)
                data = render_pdf(html) if report.report_format == ReportFormat.PDF else html
            ext, ctype = EXT[report.report_format]
            key = f"tenants/{tenant_id}/reports/{report.id}.{ext}"
            get_store().put(key, data, ctype)
            report.storage_key, report.size = key, len(data)
            report.status, report.completed_at, report.error = JobStatus.COMPLETED, datetime.now(UTC), None
            audit.record(db, Action.REPORT_GENERATED, tenant_id=tenant_id, user_id=report.requested_by,
                         object_type="report", object_id=report.id,
                         new={"type": report.report_type.value, "format": report.report_format.value, "size": len(data)})
        except ReportError as exc:
            report.status, report.error = JobStatus.FAILED, str(exc)
        except Exception as exc:  # noqa: BLE001
            log.exception("report %s failed", report_id)
            report.status, report.error = JobStatus.FAILED, f"Report generation failed ({type(exc).__name__})"
        db.commit()
