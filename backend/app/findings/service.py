"""Finding lifecycle: de-duplication, re-detection, automatic resolution,
re-opening, and the analyst workflow."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from asm_sensors.observations import FindingCoverage, FindingObservation
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.changes.detector import EventDraft
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.models import Asset, Finding, FindingActivity, VulnIntel
from app.models.enums import OPEN_FINDING_STATES, EventType, FindingStatus, Severity
from app.services import audit
from app.services.audit import Action


def _norm_location(location: str | None) -> str:
    if not location:
        return ""
    loc = location.strip()
    try:
        p = urlsplit(loc)
        if p.scheme in ("http", "https"):
            # Query strings often carry nonces/timestamps; path identifies the issue.
            return f"{p.scheme}://{(p.hostname or '').lower()}{':' + str(p.port) if p.port else ''}{p.path or '/'}"
    except ValueError:
        pass
    return loc.lower()


def fingerprint(tenant_id: uuid.UUID, asset_id: uuid.UUID, source: str, rule_id: str, location: str | None) -> str:
    raw = "|".join([str(tenant_id), str(asset_id), source, rule_id, _norm_location(location)])
    return hashlib.sha256(raw.encode()).hexdigest()


@dataclass
class FindingChange:
    finding: Finding
    event: EventDraft | None


def enrich_from_intel(db: Session, finding: Finding) -> None:
    if not finding.cve:
        return
    rows = db.execute(select(VulnIntel).where(VulnIntel.cve_id.in_(finding.cve))).scalars().all()
    for r in rows:
        if r.kev:
            finding.kev = True
            if r.kev_due_date:
                finding.kev_due_date = datetime.combine(r.kev_due_date, datetime.min.time(), tzinfo=UTC)
        if r.epss_score is not None and (finding.epss_score or 0) < r.epss_score:
            finding.epss_score = r.epss_score
            finding.epss_percentile = r.epss_percentile
        if r.cvss_score is not None and finding.cvss_score is None:
            finding.cvss_score = r.cvss_score
            finding.cvss_vector = r.cvss_vector
        if r.exploit_available:
            finding.exploit_available = True
    if finding.kev:
        finding.exploit_available = True


def _activity(db: Session, f: Finding, kind: str, *, user_id: uuid.UUID | None = None, previous: Any = None,
              new: Any = None, comment: str | None = None, scan_id: uuid.UUID | None = None) -> None:
    db.add(FindingActivity(tenant_id=f.tenant_id, finding_id=f.id, user_id=user_id, activity_type=kind,
                           previous=previous, new=new, comment=comment, scan_id=scan_id))


def upsert_observation(db: Session, *, tenant_id: uuid.UUID, organization_id: uuid.UUID, asset: Asset,
                       obs: FindingObservation, source: str, now: datetime, scan_id: uuid.UUID | None) -> FindingChange:
    fp = fingerprint(tenant_id, asset.id, source, obs.rule_id, obs.location)
    f = db.execute(select(Finding).where(Finding.tenant_id == tenant_id, Finding.fingerprint == fp)).scalar_one_or_none()
    if f is None:
        f = Finding(
            tenant_id=tenant_id, organization_id=organization_id, asset_id=asset.id, fingerprint=fp,
            source=source, source_finding_id=obs.rule_id, title=obs.title, description=obs.description,
            category=obs.category, severity=obs.severity, location=(obs.location or None),
            cve=obs.cve, cwe=obs.cwe, cvss_score=obs.cvss_score, cvss_vector=obs.cvss_vector,
            epss_score=obs.epss_score, evidence=obs.evidence, remediation=obs.remediation,
            references=obs.references, confidence=obs.confidence, tags=sorted(set(obs.tags))[:20],
            first_seen=now, last_seen=now, last_scan_id=scan_id, status=FindingStatus.NEW,
            occurrence_count=1, missed_count=0,
        )
        enrich_from_intel(db, f)
        db.add(f)
        db.flush()
        _activity(db, f, "detected", new={"severity": f.severity.value}, scan_id=scan_id)
        ev = EventDraft(EventType.VULNERABILITY_DETECTED, f.severity, f"{f.title} on {asset.value}",
                        f.description[:500] if f.description else None,
                        new={"severity": f.severity.value, "cve": f.cve, "rule": obs.rule_id},
                        details={"finding_id": str(f.id), "category": f.category.value})
        return FindingChange(f, ev)

    event = None
    f.last_seen = now
    f.last_scan_id = scan_id
    f.occurrence_count += 1
    f.missed_count = 0
    # Detection content may be updated between template versions.
    f.title, f.severity, f.evidence = obs.title, obs.severity, obs.evidence or f.evidence
    f.description = obs.description or f.description
    f.remediation = obs.remediation or f.remediation
    if obs.cve:
        f.cve = sorted(set(f.cve or []) | set(obs.cve))
    if obs.cvss_score is not None:
        f.cvss_score, f.cvss_vector = obs.cvss_score, obs.cvss_vector or f.cvss_vector
    enrich_from_intel(db, f)
    if f.status == FindingStatus.REMEDIATED:
        prev = f.status
        f.status = FindingStatus.REOPENED
        f.resolved_at = None
        _activity(db, f, "reopened", previous={"status": prev.value}, new={"status": f.status.value}, scan_id=scan_id)
        event = EventDraft(EventType.VULNERABILITY_REOPENED, f.severity, f"Previously remediated issue is back: {f.title} "
                           f"on {asset.value}", previous={"status": "remediated"}, new={"status": "reopened"},
                           details={"finding_id": str(f.id)})
    return FindingChange(f, event)


def _matches_filter(f: Finding, cov: FindingCoverage) -> bool:
    if cov.severities is not None and f.severity.value not in {s.value for s in cov.severities}:
        return False
    tags = set(f.tags or [])
    if cov.include_tags and not tags & set(cov.include_tags):
        return False
    if cov.exclude_tags and tags & set(cov.exclude_tags):
        return False
    if cov.rule_ids and f.source_finding_id.split(":")[0] not in set(cov.rule_ids):
        return False
    return True


def resolve_unobserved(db: Session, *, tenant_id: uuid.UUID, asset_ids: Iterable[uuid.UUID], source: str,
                       coverage: FindingCoverage | None, observed_ids: set[uuid.UUID], threshold: int,
                       now: datetime, scan_id: uuid.UUID | None) -> list[FindingChange]:
    ids = list(set(asset_ids))
    if not ids:
        return []
    rows = db.execute(select(Finding).where(
        Finding.tenant_id == tenant_id, Finding.asset_id.in_(ids), Finding.source == source,
        Finding.status.in_(OPEN_FINDING_STATES))).scalars().all()
    changes = []
    for f in rows:
        if f.id in observed_ids or (coverage is not None and not _matches_filter(f, coverage)):
            continue
        f.missed_count += 1
        if f.missed_count < threshold:
            continue
        prev = f.status
        f.status = FindingStatus.REMEDIATED
        f.resolved_at = now
        _activity(db, f, "resolved", previous={"status": prev.value}, new={"status": "remediated"},
                  comment="Automatically resolved: no longer detected by a scan that covered this asset.", scan_id=scan_id)
        changes.append(FindingChange(f, EventDraft(
            EventType.VULNERABILITY_RESOLVED, Severity.INFO, f"Resolved: {f.title}",
            previous={"status": prev.value}, new={"status": "remediated"}, details={"finding_id": str(f.id)})))
    return changes


def resolve_for_inactive_asset(db: Session, asset: Asset, now: datetime, scan_id: uuid.UUID | None) -> list[FindingChange]:
    """An asset that left the attack surface takes its open findings with it."""
    rows = db.execute(select(Finding).where(Finding.asset_id == asset.id,
                                            Finding.status.in_(OPEN_FINDING_STATES))).scalars().all()
    out = []
    for f in rows:
        prev = f.status
        f.status = FindingStatus.REMEDIATED
        f.resolved_at = now
        _activity(db, f, "resolved", previous={"status": prev.value}, new={"status": "remediated"},
                  comment="Automatically resolved: the affected asset is no longer observed.", scan_id=scan_id)
        out.append(FindingChange(f, EventDraft(EventType.VULNERABILITY_RESOLVED, Severity.INFO,
                                               f"Resolved (asset gone): {f.title}", previous={"status": prev.value},
                                               new={"status": "remediated"}, details={"finding_id": str(f.id)})))
    return out


# ------------------------------------------------------------ analyst workflow
ALLOWED_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.NEW: {FindingStatus.INVESTIGATING, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE,
                        FindingStatus.REMEDIATED},
    FindingStatus.INVESTIGATING: {FindingStatus.NEW, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE,
                                  FindingStatus.REMEDIATED},
    FindingStatus.REOPENED: {FindingStatus.INVESTIGATING, FindingStatus.ACCEPTED_RISK, FindingStatus.FALSE_POSITIVE,
                             FindingStatus.REMEDIATED},
    FindingStatus.ACCEPTED_RISK: {FindingStatus.REOPENED, FindingStatus.INVESTIGATING},
    FindingStatus.FALSE_POSITIVE: {FindingStatus.REOPENED, FindingStatus.INVESTIGATING},
    FindingStatus.REMEDIATED: {FindingStatus.REOPENED},
}


def update_finding(db: Session, finding_id: uuid.UUID, changes: dict[str, Any], *, user_id: uuid.UUID,
                   can_accept_risk: bool) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise NotFound("Finding not found")
    before = {"status": f.status.value, "assigned_to": str(f.assigned_to) if f.assigned_to else None,
              "tags": list(f.tags or []), "notes": f.notes, "accepted_until": f.accepted_until}
    comment = changes.pop("comment", None)

    if "status" in changes and changes["status"] is not None:
        new_status = FindingStatus(changes["status"])
        if new_status != f.status:
            if new_status not in ALLOWED_TRANSITIONS[f.status]:
                raise ValidationFailed(f"Cannot move a finding from {f.status.value} to {new_status.value}")
            if new_status == FindingStatus.ACCEPTED_RISK:
                if not can_accept_risk:
                    raise Forbidden("Accepting risk requires the tenant administrator role")
                if not comment:
                    raise ValidationFailed("A justification comment is required to accept risk")
                f.accepted_until = changes.get("accepted_until")
            f.false_positive = new_status == FindingStatus.FALSE_POSITIVE
            if new_status == FindingStatus.REMEDIATED:
                f.resolved_at = datetime.now(UTC)
            elif new_status == FindingStatus.REOPENED:
                f.resolved_at = None
            _activity(db, f, "status", user_id=user_id, previous={"status": f.status.value},
                      new={"status": new_status.value}, comment=comment)
            f.status = new_status
            comment = None
    if "assigned_to" in changes:
        new_assignee = changes["assigned_to"]
        if new_assignee != f.assigned_to:
            _activity(db, f, "assignment", user_id=user_id,
                      previous={"assigned_to": str(f.assigned_to) if f.assigned_to else None},
                      new={"assigned_to": str(new_assignee) if new_assignee else None})
            f.assigned_to = new_assignee
    if "tags" in changes and changes["tags"] is not None:
        tags = sorted({t.strip().lower()[:64] for t in changes["tags"] if t and t.strip()})[:30]
        if tags != sorted(f.tags or []):
            _activity(db, f, "tags", user_id=user_id, previous={"tags": f.tags}, new={"tags": tags})
            f.tags = tags
    if "notes" in changes:
        f.notes = changes["notes"]
    if comment:
        _activity(db, f, "comment", user_id=user_id, comment=comment)

    after = {"status": f.status.value, "assigned_to": str(f.assigned_to) if f.assigned_to else None,
             "tags": list(f.tags or []), "notes": f.notes, "accepted_until": f.accepted_until}
    prev, new = audit.diff(before, after)
    if prev or new:
        action = Action.RISK_ACCEPTED if after["status"] == "accepted_risk" and before["status"] != "accepted_risk" \
            else Action.FINDING_UPDATED
        audit.record(db, action, tenant_id=f.tenant_id, object_type="finding", object_id=f.id, previous=prev, new=new)
    db.flush()
    return f


def add_comment(db: Session, finding_id: uuid.UUID, user_id: uuid.UUID, comment: str) -> FindingActivity:
    f = db.get(Finding, finding_id)
    if f is None:
        raise NotFound("Finding not found")
    act = FindingActivity(tenant_id=f.tenant_id, finding_id=f.id, user_id=user_id, activity_type="comment",
                          comment=comment)
    db.add(act)
    db.flush()
    return act
