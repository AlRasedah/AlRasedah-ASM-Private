"""Threat Center: catalog management, tenant evaluation, checks and remediation.

Evaluation answers "which of our assets may be affected?" from the inventory the
platform already has — it never starts a scan. It runs incrementally:

* when a scan of an organization finishes (its inventory changed): every
  published advisory, that organization only;
* when an advisory version is published: that advisory, every tenant;
* once a day as a safety net (``evaluate_all``).

Each run is serialized per organization (advisory lock) and is idempotent: a
match row is unique per (tenant, advisory, asset), so a repeat changes nothing
and emits nothing. A notification is emitted only when an evaluation *creates*
matches that may be affected, once per organization and advisory.

Checks go through the ordinary scan pipeline (``orchestrator.create_scan`` with
the internal Threat Center profile): scope authorization, active-scanning
permission, plan quotas, concurrency and the per-tenant scanner pool all apply
exactly as for any other scan.
"""

from __future__ import annotations

import logging
import uuid
from collections import OrderedDict, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from asm_sensors.registry import adapter_names, get_adapter
from sqlalchemy import ARRAY, bindparam, event, func, or_, select, text, update
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Session, aliased

from app.assets.normalization import parse_port_value
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.models import (
    Asset,
    AssetEvent,
    AssetRelationship,
    Finding,
    Organization,
    Scan,
    ScanProfile,
    ScopeDecision,
    TenantMembership,
    ThreatAdvisory,
    ThreatAdvisoryVersion,
    ThreatCampaign,
    ThreatCheck,
    ThreatCheckRun,
    ThreatMatch,
)
from app.models.enums import (
    ACTIVE_CHECK_RUN_STATES,
    AFFECTED_ASSESSMENTS,
    AdvisoryStatus,
    Assessment,
    AssetStatus,
    AssetType,
    CheckOutcome,
    CheckRunStatus,
    DecisionResult,
    EventType,
    FindingStatus,
    MatchBasis,
    MatchStatus,
    RelationType,
    RemediationStatus,
    ScanStatus,
    ScanTrigger,
    ScopeStatus,
    Severity,
    StageStatus,
)
from app.scans.profiles import THREAT_CHECK_SLUG
from app.services import audit
from app.services.audit import Action

from .content import KEY_RE, AdvisoryContent, norm_name
from .matching import AssetVerdict, ProductObservation, match, names_of

log = logging.getLogger(__name__)

# Bounds on one evaluation of one organization.
MAX_OBSERVATIONS = 20_000
MAX_MATCHES_PER_ADVISORY = 5_000
MAX_CHECK_ASSETS = 50
CHECK_ENGINE = "nuclei"  # internal: never sent to a browser (ADR-022)
TEMPLATE_RE = KEY_RE.pattern  # same shape the detection engine accepts


def _now() -> datetime:
    return datetime.now(UTC)


def _historical_sources() -> frozenset[str]:
    """Sources that report a third party's record rather than a live observation."""
    return frozenset(n for n in adapter_names() if get_adapter(n).historical)


# ======================================================================= catalog
# Platform administration only. Every function here expects a *system* session:
# the catalog is global and RLS lets tenant sessions read published rows only.

def _check_keys_exist(db: Session, keys: Iterable[str]) -> None:
    keys = list(keys)
    if not keys:
        return
    found = set(db.execute(select(ThreatCheck.key).where(ThreatCheck.key.in_(keys))).scalars())
    missing = sorted(set(keys) - found)
    if missing:
        raise ValidationFailed("The advisory names checks that are not on the approved list",
                               details=[f"unknown check: {k}" for k in missing])


def _content(raw: dict[str, Any] | AdvisoryContent) -> AdvisoryContent:
    if isinstance(raw, AdvisoryContent):
        return raw
    try:
        return AdvisoryContent.model_validate(raw)
    except ValueError as exc:
        raise ValidationFailed("Invalid advisory", details=[str(exc)[:500]]) from exc


def create_advisory(db: Session, *, slug: str, content: AdvisoryContent, user_id: uuid.UUID | None,
                    origin: str = "manual", audited: bool = True) -> ThreatAdvisory:
    if not KEY_RE.match(slug):
        raise ValidationFailed("The identifier must be 3–64 lower-case letters, digits or '-'")
    if db.execute(select(ThreatAdvisory.id).where(ThreatAdvisory.slug == slug)).first():
        raise Conflict("An advisory with this identifier already exists")
    _check_keys_exist(db, content.check_keys)
    adv = ThreatAdvisory(slug=slug, status=AdvisoryStatus.DRAFT, title=content.title, severity=content.severity,
                         cves=content.cves, source_published_at=content.source_published_at,
                         source_updated_at=content.source_updated_at, created_by=user_id, updated_by=user_id,
                         origin=origin)
    db.add(adv)
    db.flush()
    db.add(ThreatAdvisoryVersion(advisory_id=adv.id, version=1, state="draft",
                                 content=content.model_dump(mode="json"), created_by=user_id))
    if audited:  # the feed records one summary entry per run instead of one per advisory
        audit.record(db, Action.ADVISORY_CHANGED, platform=True, object_type="threat_advisory", object_id=adv.id,
                     new={"slug": slug, "title": content.title, "state": "draft"})
    db.flush()
    return adv


def _advisory(db: Session, advisory_id: uuid.UUID) -> ThreatAdvisory:
    adv = db.get(ThreatAdvisory, advisory_id)
    if adv is None:
        raise NotFound("Advisory not found")
    return adv


def draft_of(db: Session, advisory_id: uuid.UUID) -> ThreatAdvisoryVersion | None:
    return db.execute(select(ThreatAdvisoryVersion).where(
        ThreatAdvisoryVersion.advisory_id == advisory_id, ThreatAdvisoryVersion.state == "draft")).scalar_one_or_none()


def published_of(db: Session, adv: ThreatAdvisory) -> ThreatAdvisoryVersion | None:
    if adv.published_version is None:
        return None
    return db.execute(select(ThreatAdvisoryVersion).where(
        ThreatAdvisoryVersion.advisory_id == adv.id, ThreatAdvisoryVersion.version == adv.published_version,
        ThreatAdvisoryVersion.state == "published")).scalar_one_or_none()


def save_draft(db: Session, advisory_id: uuid.UUID, content: AdvisoryContent,
               user_id: uuid.UUID | None, audited: bool = True) -> ThreatAdvisoryVersion:
    """Edit the working copy. The published version keeps applying until the draft is published."""
    adv = _advisory(db, advisory_id)
    _check_keys_exist(db, content.check_keys)
    draft = draft_of(db, adv.id)
    if draft is None:
        last = db.scalar(select(func.max(ThreatAdvisoryVersion.version))
                         .where(ThreatAdvisoryVersion.advisory_id == adv.id)) or 0
        draft = ThreatAdvisoryVersion(advisory_id=adv.id, version=last + 1, state="draft", created_by=user_id)
        db.add(draft)
    before = draft.content or {}
    draft.content = content.model_dump(mode="json")
    if adv.published_version is None:  # never published: the listing shows the draft
        adv.title, adv.severity, adv.cves = content.title, content.severity, content.cves
    adv.updated_by = user_id
    if audited:
        prev, new = audit.diff(before, draft.content)
        audit.record(db, Action.ADVISORY_CHANGED, platform=True, object_type="threat_advisory", object_id=adv.id,
                     previous=prev, new={**new, "state": "draft", "version": draft.version})
    db.flush()
    return draft


def publish(db: Session, advisory_id: uuid.UUID, user_id: uuid.UUID | None, audited: bool = True) -> ThreatAdvisory:
    adv = _advisory(db, advisory_id)
    draft = draft_of(db, adv.id)
    if draft is None:
        raise Conflict("There is no draft to publish; edit the advisory first")
    content = _content(draft.content)
    _check_keys_exist(db, content.check_keys)  # the allowlist may have changed since the draft was saved
    now = _now()
    draft.state, draft.published_at = "published", now
    adv.published_version = draft.version
    adv.status = AdvisoryStatus.PUBLISHED
    adv.title, adv.severity, adv.cves = content.title, content.severity, content.cves
    adv.source_published_at, adv.source_updated_at = content.source_published_at, content.source_updated_at
    adv.version_published_at = now
    adv.updated_by = user_id
    if audited:
        audit.record(db, Action.ADVISORY_PUBLISHED, platform=True, object_type="threat_advisory", object_id=adv.id,
                     new={"version": draft.version, "title": content.title})
    db.flush()
    return adv


def set_archived(db: Session, advisory_id: uuid.UUID, archived: bool, user_id: uuid.UUID | None) -> ThreatAdvisory:
    adv = _advisory(db, advisory_id)
    if archived:
        adv.status = AdvisoryStatus.ARCHIVED
    else:
        adv.status = AdvisoryStatus.PUBLISHED if adv.published_version else AdvisoryStatus.DRAFT
    adv.updated_by = user_id
    audit.record(db, Action.ADVISORY_CHANGED, platform=True, object_type="threat_advisory", object_id=adv.id,
                 new={"status": adv.status.value})
    db.flush()
    return adv


def save_check(db: Session, *, key: str, name: str, description: str | None, template_id: str, enabled: bool,
               user_id: uuid.UUID | None, audited: bool = True) -> ThreatCheck:
    """Add or update an approved check. The template id names one detection in the vetted
    template set — never a template body, a URL or a command."""
    import re

    if not KEY_RE.match(key):
        raise ValidationFailed("The check identifier must be 3–64 lower-case letters, digits or '-'")
    tid = template_id.strip().lower()
    if not re.match(r"^[a-z0-9][a-z0-9_.-]{0,63}$", tid):
        raise ValidationFailed("The detection identifier may contain only letters, digits, '.', '_' and '-'")
    row = db.execute(select(ThreatCheck).where(ThreatCheck.key == key)).scalar_one_or_none()
    before = None if row is None else {"name": row.name, "template_id": row.template_id, "enabled": row.enabled}
    if row is None:
        row = ThreatCheck(key=key, kind="detection_template", created_by=user_id)
        db.add(row)
    row.name, row.description, row.template_id, row.enabled = name, description, tid, enabled
    if audited:
        audit.record(db, Action.THREAT_CHECK_CHANGED, platform=True, object_type="threat_check", object_id=key,
                     previous=before, new={"name": name, "template_id": tid, "enabled": enabled})
    db.flush()
    return row


# ==================================================================== evaluation
@dataclass
class EvalStats:
    advisories: int = 0
    observations: int = 0
    matches: int = 0
    new_matches: int = 0
    events: int = 0
    truncated: bool = False
    per_advisory_new: dict[uuid.UUID, int] = field(default_factory=dict)


# A published version never changes, so its validated content is cached by (advisory, version).
_CONTENT: OrderedDict[tuple[uuid.UUID, int], AdvisoryContent] = OrderedDict()
_CONTENT_MAX = 5000


def published_advisories(db: Session, only: Iterable[uuid.UUID] | None = None
                         ) -> list[tuple[ThreatAdvisory, AdvisoryContent]]:
    """Published (not archived) advisories with their current content. Works in a tenant session."""
    stmt = select(ThreatAdvisory).where(ThreatAdvisory.status == AdvisoryStatus.PUBLISHED,
                                        ThreatAdvisory.published_version.is_not(None))
    if only is not None:
        stmt = stmt.where(ThreatAdvisory.id.in_(list(only)))
    advisories = list(db.execute(stmt).scalars())
    missing = [a for a in advisories if (a.id, a.published_version) not in _CONTENT]
    if missing:
        for adv_id, version, content in db.execute(select(
                ThreatAdvisoryVersion.advisory_id, ThreatAdvisoryVersion.version, ThreatAdvisoryVersion.content).where(
                ThreatAdvisoryVersion.advisory_id.in_([a.id for a in missing]),
                ThreatAdvisoryVersion.state == "published")):
            try:
                _CONTENT[(adv_id, version)] = AdvisoryContent.model_validate(content)
            except ValueError:
                log.error("advisory %s version %s has invalid content; skipped", adv_id, version)
        while len(_CONTENT) > _CONTENT_MAX:
            _CONTENT.popitem(last=False)
    out = []
    for adv in advisories:
        content = _CONTENT.get((adv.id, adv.published_version or 0))
        if content is not None:
            out.append((adv, content))
    return out


def _norm_sql(col: Any) -> Any:
    return func.lower(func.regexp_replace(func.trim(col), r"[\s_]+", " ", "g"))


def product_observations(db: Session, org: Organization, names: set[str]) -> tuple[list[ProductObservation], bool]:
    """What fingerprinting recorded for products with these names, in this organization.

    Only active, non-third-party-scoped assets. Bounded; the flag says whether the
    bound was hit."""
    if not names:
        return [], False
    historical = _historical_sources()
    out: list[ProductObservation] = []
    live = [Asset.status == AssetStatus.ACTIVE, Asset.scope_status != ScopeStatus.OUT_OF_SCOPE,
            Asset.organization_id == org.id]
    tech = aliased(Asset)
    rows = db.execute(
        select(AssetRelationship.source_asset_id, tech.normalized_value, AssetRelationship.attributes,
               AssetRelationship.last_seen, AssetRelationship.source)
        .join(tech, tech.id == AssetRelationship.target_asset_id)
        .join(Asset, Asset.id == AssetRelationship.source_asset_id)
        .where(AssetRelationship.organization_id == org.id, AssetRelationship.active.is_(True),
               AssetRelationship.relation_type == RelationType.USES_TECHNOLOGY,
               _norm_sql(tech.normalized_value).in_(names), *live)
        .limit(MAX_OBSERVATIONS)).all()
    for asset_id, name, attrs, seen, source in rows:
        out.append(ProductObservation(asset_id, org.id, name, (attrs or {}).get("version"), "technology", seen,
                                      third_party=source in historical))
    rows = db.execute(
        select(Asset.id, Asset.meta, Asset.last_seen, Asset.sources)
        .where(Asset.asset_type == AssetType.SERVICE, _norm_sql(Asset.meta["product"].astext).in_(names), *live)
        .limit(MAX_OBSERVATIONS)).all()
    for asset_id, meta, seen, sources in rows:
        out.append(ProductObservation(asset_id, org.id, str(meta.get("product")), meta.get("version"), "service", seen,
                                      third_party=bool(sources) and set(sources) <= historical))
    server = func.split_part(func.split_part(Asset.meta["webserver"].astext, " ", 1), "/", 1)
    rows = db.execute(
        select(Asset.id, Asset.meta, Asset.last_seen)
        .where(Asset.asset_type == AssetType.HTTP_ENDPOINT, _norm_sql(server).in_(names), *live)
        .limit(MAX_OBSERVATIONS)).all()
    for asset_id, meta, seen in rows:
        first = str(meta.get("webserver") or "").split(" ")[0]
        name, _, version = first.partition("/")
        out.append(ProductObservation(asset_id, org.id, name, version or None, "web_server", seen))
    return out[:MAX_OBSERVATIONS], len(out) >= MAX_OBSERVATIONS


@dataclass
class _FindingRef:
    id: uuid.UUID
    asset_id: uuid.UUID
    cves: set[str]
    rule: str
    unverified: bool
    scan_id: uuid.UUID | None
    source: str


def _findings(db: Session, org: Organization, cves: set[str], templates: set[str]
              ) -> tuple[list[_FindingRef], bool]:
    """Existing findings that concern these CVEs / detections. Referenced, never copied.
    Bounded; the flag says whether the bound was hit."""
    if not cves and not templates:
        return [], False
    conds = []
    if cves:
        conds.append(Finding.cve.overlap(sorted(cves)))
    if templates:
        conds.append(func.lower(func.split_part(Finding.source_finding_id, ":", 1)).in_(sorted(templates)))
    rows = db.execute(select(Finding.id, Finding.asset_id, Finding.cve, Finding.source_finding_id, Finding.unverified,
                             Finding.last_scan_id, Finding.source)
                      .where(Finding.organization_id == org.id, Finding.status != FindingStatus.FALSE_POSITIVE,
                             or_(*conds))
                      .limit(MAX_OBSERVATIONS)).all()
    return ([_FindingRef(i, a, set(c or []), (r or "").split(":")[0].lower(), bool(u), s, src)
             for i, a, c, r, u, s, src in rows], len(rows) >= MAX_OBSERVATIONS)


def assess(match_status: MatchStatus, basis: MatchBasis, check: CheckOutcome, has_verified: bool) -> Assessment:
    """The one label per asset. Order matters and is documented in docs/THREAT_CENTER.md."""
    if has_verified or check == CheckOutcome.DETECTED:
        return Assessment.CONFIRMED
    if match_status == MatchStatus.NO_LONGER_OBSERVED:
        return Assessment.NO_LONGER_OBSERVED
    if check == CheckOutcome.PENDING:
        return Assessment.CHECK_PENDING
    if match_status == MatchStatus.NOT_AFFECTED_VERSION:
        return Assessment.NOT_AFFECTED_VERSION
    if check == CheckOutcome.NOT_DETECTED:
        return Assessment.NOT_DETECTED
    if check == CheckOutcome.INCONCLUSIVE:
        return Assessment.INCONCLUSIVE
    if basis == MatchBasis.THIRD_PARTY:
        return Assessment.REPORTED_UNVERIFIED
    if match_status == MatchStatus.VERSION_UNKNOWN:
        return Assessment.VERSION_UNKNOWN
    return Assessment.POTENTIALLY_AFFECTED


def run_applies(run: ThreatCheckRun | None, version: int, templates: set[str], cves: Iterable[str]) -> bool:
    """Whether a check run tested what this advisory version asks for: the same detection
    and the same CVEs. A result never carries over to a version that asks something else."""
    if run is None:
        return False
    if run.template_id is None:  # recorded before the run kept its own definition
        return run.advisory_version == version
    return run.template_id.lower() in templates and set(run.cves or []) == set(cves)


def _templates_for(db: Session, content: AdvisoryContent) -> set[str]:
    if not content.check_keys:
        return set()
    return {t.lower() for t in db.execute(select(ThreatCheck.template_id)
                                          .where(ThreatCheck.key.in_(content.check_keys))).scalars()}


def _templates_by_advisory(db: Session, advisories: list[tuple[ThreatAdvisory, AdvisoryContent]]
                           ) -> dict[uuid.UUID, set[str]]:
    """The same, for many advisories in one query (the feed publishes hundreds)."""
    keys = {k for _, c in advisories for k in c.check_keys}
    by_key = {k: tid.lower() for k, tid in db.execute(select(ThreatCheck.key, ThreatCheck.template_id)
                                                        .where(ThreatCheck.key.in_(keys)))} if keys else {}
    return {a.id: {by_key[k] for k in c.check_keys if k in by_key} for a, c in advisories}


# Feed advisories for long-known vulnerabilities are imported in bulk; their first matches
# are inventory, not news, so they do not notify (later new matches do).
BACKFILL_QUIET_FOR = timedelta(days=1)
BACKFILL_OLDER_THAN = timedelta(days=30)


def _quiet_backfill(adv: ThreatAdvisory, now: datetime) -> bool:
    if adv.origin != "feed" or adv.created_at is None or now - adv.created_at > BACKFILL_QUIET_FOR:
        return False
    return adv.source_published_at is not None and now - adv.source_published_at > BACKFILL_OLDER_THAN


def evaluate_org(db: Session, org: Organization, advisories: list[tuple[ThreatAdvisory, AdvisoryContent]],
                 now: datetime | None = None) -> EvalStats:
    """Bring one organization's matches up to date with these advisories (tenant session)."""
    now = now or _now()
    stats = EvalStats(advisories=len(advisories))
    if not advisories:
        return stats
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"threat:{org.id}"})
    all_names = set().union(*(names_of(c) for _, c in advisories))
    observations, obs_truncated = product_observations(db, org, all_names)
    templates = _templates_by_advisory(db, advisories)
    all_cves = set().union(*(set(c.cves) for _, c in advisories))
    findings, findings_truncated = _findings(db, org, all_cves, set().union(*templates.values()))
    stats.observations = len(observations)
    # A bound that was hit means part of the inventory was not seen: it is not evidence
    # that anything disappeared, so such an evaluation adds and updates but never retires.
    shared_gap = (f"more than {MAX_OBSERVATIONS} product observations" if obs_truncated
                  else f"more than {MAX_OBSERVATIONS} related findings" if findings_truncated else None)
    existing: dict[tuple[uuid.UUID, uuid.UUID], ThreatMatch] = {
        (m.advisory_id, m.asset_id): m for m in db.execute(select(ThreatMatch).where(
            ThreatMatch.organization_id == org.id,
            ThreatMatch.advisory_id.in_([a.id for a, _ in advisories]))).scalars()}
    run_ids = {m.last_check_run_id for m in existing.values() if m.last_check_run_id}
    runs = {r.id: r for r in db.execute(select(ThreatCheckRun).where(ThreatCheckRun.id.in_(run_ids))).scalars()} \
        if run_ids else {}
    active_assets = set(db.execute(select(Asset.id).where(
        Asset.organization_id == org.id, Asset.status == AssetStatus.ACTIVE,
        Asset.id.in_({f.asset_id for f in findings}))).scalars()) if findings else set()
    # Indexes, so each advisory looks only at what can concern it (there may be thousands).
    obs_by_name: dict[str, list[ProductObservation]] = defaultdict(list)
    for o in observations:
        obs_by_name[norm_name(o.name)].append(o)
    findings_by_key: dict[str, list[_FindingRef]] = defaultdict(list)
    for f in findings:
        for key in {*f.cves, f"rule:{f.rule}"}:
            findings_by_key[key].append(f)
    existing_by_adv: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for adv_id, asset_id in existing:
        existing_by_adv[adv_id].append(asset_id)
    untouched: list[uuid.UUID] = []
    campaigns = {c.advisory_id: c for c in db.execute(select(ThreatCampaign).where(
        ThreatCampaign.tenant_id == org.tenant_id,
        ThreatCampaign.advisory_id.in_([a.id for a, _ in advisories]))).scalars()}

    for adv, content in advisories:
        relevant = [o for n in names_of(content) for o in obs_by_name.get(n, ())]
        verdicts: dict[uuid.UUID, AssetVerdict] = match(content, relevant) if relevant else {}
        verified: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
        unverified: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
        concerned = {id(f): f for k in (*content.cves, *(f"rule:{r}" for r in templates[adv.id]))
                     for f in findings_by_key.get(k, ())}
        for f in concerned.values():
            if f.asset_id not in active_assets and f.asset_id not in verdicts:
                continue
            (unverified if f.unverified else verified)[f.asset_id].append(f.id)
        asset_ids = (set(verdicts) | set(verified) | set(unverified))
        gap = shared_gap
        if len(asset_ids) > MAX_MATCHES_PER_ADVISORY:
            gap = gap or f"more than {MAX_MATCHES_PER_ADVISORY} assets match"
            # Keep what is already tracked current first; the rest waits for more room.
            ranked = sorted(asset_ids, key=lambda a: ((adv.id, a) not in existing, str(a)))
            asset_ids = set(ranked[:MAX_MATCHES_PER_ADVISORY])
        stats.truncated = stats.truncated or gap is not None
        version = adv.published_version or 0
        new_countable = 0
        for asset_id in asset_ids:
            v = verdicts.get(asset_id)
            if v is not None:
                basis = MatchBasis.PRODUCT
                status = v.status
                evidence: dict[str, Any] = {"observations": v.evidence, "third_party_only": v.third_party_only}
                if v.third_party_only and not verified.get(asset_id):
                    basis = MatchBasis.THIRD_PARTY
            elif verified.get(asset_id):
                basis, status = MatchBasis.FINDING, MatchStatus.POTENTIALLY_AFFECTED
                evidence = {"observations": [], "reason": "a verified finding on this asset names the advisory"}
            else:
                basis, status = MatchBasis.THIRD_PARTY, MatchStatus.POTENTIALLY_AFFECTED
                evidence = {"observations": [], "reason": "only an unverified third-party report names the advisory"}
            m = existing.pop((adv.id, asset_id), None)
            if m is None:
                m = ThreatMatch(tenant_id=org.tenant_id, organization_id=org.id, advisory_id=adv.id,
                                asset_id=asset_id, first_matched_at=now, check_outcome=CheckOutcome.NONE,
                                remediation_status=RemediationStatus.OPEN)
                db.add(m)
                is_new = True
            else:
                is_new = False
            outcome, detail, checked = m.check_outcome, m.check_detail, m.checked_at
            if outcome in (CheckOutcome.DETECTED, CheckOutcome.NOT_DETECTED, CheckOutcome.INCONCLUSIVE) \
                    and not run_applies(runs.get(m.last_check_run_id), version, templates[adv.id], content.cves):
                # The last check tested an earlier definition; it says nothing about this one.
                outcome, checked = CheckOutcome.NONE, None
                detail = f"the last check tested an earlier version of this advisory; it does not apply to version {version}"
            found = sorted(set(verified.get(asset_id, [])), key=str)
            values = {"advisory_version": version, "check_outcome": outcome, "check_detail": detail,
                      "checked_at": checked, "basis": basis, "match_status": status, "evidence": evidence,
                      "finding_ids": found,
                      "unverified_finding_ids": sorted(set(unverified.get(asset_id, [])), key=str),
                      "assessment": assess(status, basis, outcome, bool(found))}
            # Only rows that change are written: re-evaluating a large, unchanged inventory
            # touches their timestamp in one statement instead of rewriting every row.
            if is_new or any(getattr(m, k) != v for k, v in values.items()):
                for k, v in values.items():
                    setattr(m, k, v)
                m.last_evaluated_at = now
            else:
                untouched.append(m.id)
            stats.matches += 1
            if is_new and m.assessment in AFFECTED_ASSESSMENTS:
                new_countable += 1
        # Matched before, not any more: keep the row (history, remediation), say why.
        # Only after an evaluation that saw everything; otherwise leave the row as it was.
        for _asset in existing_by_adv.get(adv.id, ()):
            m = existing.pop((adv.id, _asset), None)
            if m is None or gap is not None:
                continue
            m.match_status = MatchStatus.NO_LONGER_OBSERVED
            m.finding_ids, m.unverified_finding_ids = [], []
            m.evidence = {**(m.evidence or {}), "reason": "the product or finding is no longer observed on this asset"}
            m.assessment = assess(m.match_status, m.basis, m.check_outcome, False)
            m.last_evaluated_at = now
        _touch_campaign(db, org, adv, now, gap, campaigns)
        if new_countable:
            stats.new_matches += new_countable
            stats.per_advisory_new[adv.id] = new_countable
            if not _quiet_backfill(adv, now):
                _match_event(db, org, adv, new_countable, now)
                stats.events += 1
    if untouched:  # one statement, one array parameter
        db.execute(update(ThreatMatch).where(ThreatMatch.id == func.any(bindparam("ids", type_=ARRAY(PG_UUID))))
                   .values(last_evaluated_at=now).execution_options(synchronize_session=False), {"ids": untouched})
    db.flush()
    return stats


def _touch_campaign(db: Session, org: Organization, adv: ThreatAdvisory, now: datetime, gap: str | None,
                    campaigns: dict[uuid.UUID, ThreatCampaign]) -> None:
    c = campaigns.get(adv.id)
    if c is None:
        c = campaigns[adv.id] = ThreatCampaign(tenant_id=org.tenant_id, advisory_id=adv.id, incomplete_orgs={})
        db.add(c)
    c.evaluated_version, c.last_evaluated_at = adv.published_version, now
    gaps = {k: v for k, v in (c.incomplete_orgs or {}).items() if k != str(org.id)}
    if gap:
        gaps[str(org.id)] = f"{org.name}: {gap}; the assessment covers part of the inventory"[:300]
    c.incomplete_orgs = gaps


def _match_event(db: Session, org: Organization, adv: ThreatAdvisory, count: int, now: datetime) -> None:
    noun = "asset" if count == 1 else "assets"
    db.add(AssetEvent(
        tenant_id=org.tenant_id, organization_id=org.id, event_type=EventType.THREAT_ADVISORY_MATCHED,
        severity=adv.severity, occurred_at=now, is_baseline=False,
        title=f"{adv.title}: {count} {noun} may be affected",
        summary=("Matched from recorded inventory (product and version). Not confirmed: open the Threat Center to "
                 "see the evidence and run an approved check."),
        new_state={"new_matches": count, "cves": list(adv.cves)},
        details={"advisory_id": str(adv.id), "advisory_version": adv.published_version}))


def evaluate_tenant(db: Session, tenant_id: uuid.UUID, advisory_ids: Iterable[uuid.UUID] | None = None,
                    organization_id: uuid.UUID | None = None) -> EvalStats:
    reconcile_check_runs(db)
    advisories = published_advisories(db, advisory_ids)
    total = EvalStats(advisories=len(advisories))
    stmt = select(Organization).where(Organization.tenant_id == tenant_id, Organization.is_active.is_(True))
    if organization_id:
        stmt = stmt.where(Organization.id == organization_id)
    for org in db.execute(stmt).scalars():
        s = evaluate_org(db, org, advisories)
        total.observations += s.observations
        total.matches += s.matches
        total.new_matches += s.new_matches
        total.events += s.events
        total.truncated = total.truncated or s.truncated
    return total


def on_scan_finished(db: Session, scan: Scan, org: Organization | None) -> None:
    """Called by the orchestrator (in a savepoint) when a scan ends or is cancelled.

    A finished check is recorded here, with the scan. Matching the organization's new
    inventory against every advisory (there may be thousands) runs as its own job once
    the scan has committed, so it never delays or holds up a scan's finalization."""
    sync_check_run(db, scan)
    if org is not None and scan.status in (ScanStatus.COMPLETED, ScanStatus.PARTIAL):
        _after_outer_commit(db, ("threat-evaluate", org.tenant_id, org.id))


def _after_outer_commit(db: Session, job: tuple[str, uuid.UUID, uuid.UUID]) -> None:
    """Start ``job`` once this session's *outermost* transaction commits. SQLAlchemy also
    reports a released savepoint as a commit; running then would wait for row locks the
    still-open transaction holds. Any rollback (a failed savepoint too) drops it."""
    db.info.setdefault("threat_jobs", set()).add(job)
    if not db.info.get("threat_jobs_hooked"):
        db.info["threat_jobs_hooked"] = True
        event.listen(db, "after_commit", _run_jobs)
        event.listen(db, "after_soft_rollback", _drop_jobs)


def _run_jobs(session: Session) -> None:
    if session.in_nested_transaction():
        return
    from app.workers import dispatch

    for _kind, tenant_id, org_id in session.info.pop("threat_jobs", set()):
        try:
            dispatch.evaluate_organization(tenant_id, org_id)
        except Exception:  # noqa: BLE001 - the daily evaluation repairs it
            log.exception("could not start the Threat Center update for organization %s", org_id)


def _drop_jobs(session: Session, _previous: Any) -> None:
    # Any rollback, a failed savepoint included: what registered the job did not happen.
    session.info.pop("threat_jobs", None)


# ========================================================================= checks
def _target_for(asset: Asset) -> str | None:
    """How an asset is named to the scan pipeline ("limit to specific targets")."""
    if asset.asset_type in (AssetType.HTTP_ENDPOINT, AssetType.WEB_APPLICATION):
        return asset.normalized_value if "://" in asset.normalized_value else None
    if asset.asset_type in (AssetType.PORT, AssetType.SERVICE):
        p = parse_port_value(asset.normalized_value)
        if not p or p[2] != "tcp":
            return None
        host = f"[{p[0]}]" if ":" in p[0] else p[0]
        return f"{host}:{p[1]}"
    if asset.asset_type in (AssetType.IP_ADDRESS, AssetType.ROOT_DOMAIN, AssetType.DOMAIN, AssetType.SUBDOMAIN):
        return asset.normalized_value
    return None


def usable_check(db: Session, content: AdvisoryContent) -> ThreatCheck | None:
    for key in content.check_keys:
        c = db.execute(select(ThreatCheck).where(ThreatCheck.key == key, ThreatCheck.enabled.is_(True))
                       ).scalar_one_or_none()
        if c is not None:
            return c
    return None


def request_checks(db: Session, *, tenant_id: uuid.UUID, advisory_id: uuid.UUID, match_ids: list[uuid.UUID],
                   user_id: uuid.UUID | None, trigger: ScanTrigger = ScanTrigger.MANUAL) -> list[ThreatCheckRun]:
    """"Check selected assets": one scan per organization, through the normal pipeline."""
    from app.scans import orchestrator

    if not match_ids:
        raise ValidationFailed("Select at least one asset to check")
    if len(match_ids) > MAX_CHECK_ASSETS:
        raise ValidationFailed(f"Select at most {MAX_CHECK_ASSETS} assets per check")
    found = published_advisories(db, [advisory_id])
    if not found:
        raise NotFound("Advisory not found")
    adv, content = found[0]
    check = usable_check(db, content)
    if check is None:
        raise ValidationFailed("No approved check is available for this advisory, so it can only be assessed from "
                               "inventory. Ask a platform administrator to approve a check for it.")
    matches = list(db.execute(select(ThreatMatch).where(ThreatMatch.id.in_(match_ids),
                                                        ThreatMatch.advisory_id == adv.id)).scalars())
    if len(matches) != len(set(match_ids)):
        raise NotFound("One or more selected assets were not found for this advisory")
    profile = db.execute(select(ScanProfile).where(ScanProfile.tenant_id.is_(None),
                                                   ScanProfile.slug == THREAT_CHECK_SLUG)).scalar_one_or_none()
    if profile is None:
        raise Conflict("The Threat Center check profile is missing; a platform administrator must run the upgrade")
    by_org: dict[uuid.UUID, list[ThreatMatch]] = defaultdict(list)
    for m in matches:
        by_org[m.organization_id].append(m)
    runs: list[ThreatCheckRun] = []
    for org_id, group in by_org.items():
        active = db.execute(select(ThreatCheckRun).where(
            ThreatCheckRun.organization_id == org_id, ThreatCheckRun.advisory_id == adv.id,
            ThreatCheckRun.status.in_([s.value for s in ACTIVE_CHECK_RUN_STATES]))).scalar_one_or_none()
        if active is not None:
            raise Conflict("A check for this advisory is already queued or running for this organization",
                           details={"check_run_id": str(active.id)})
        assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_([m.asset_id for m in group]))).scalars()}
        targets = sorted({t for m in group if (a := assets.get(m.asset_id)) and (t := _target_for(a))})
        if not targets:
            raise ValidationFailed("None of the selected assets can be checked directly (select web endpoints, "
                                   "ports or hosts)")
        stage = {"stage": "vulnerability_detection", "engine": CHECK_ENGINE, "enabled": True, "optional": False,
                 "config": {"template_ids": [check.template_id], "include_tech_detection": False,
                            "severities": ["info", "low", "medium", "high", "critical"]}}
        scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=profile.id,
                                        trigger=trigger, requested_by=user_id, target_override=targets,
                                        stages=[stage])
        run = ThreatCheckRun(tenant_id=tenant_id, organization_id=org_id, advisory_id=adv.id,
                             advisory_version=adv.published_version or 0, check_key=check.key,
                             template_id=check.template_id, cves=list(content.cves), scan_id=scan.id,
                             asset_ids=[m.asset_id for m in group], status=CheckRunStatus.QUEUED,
                             requested_by=user_id, summary={})
        db.add(run)
        db.flush()
        for m in group:
            m.check_outcome, m.check_detail, m.last_check_run_id = CheckOutcome.PENDING, None, run.id
            m.assessment = assess(m.match_status, m.basis, m.check_outcome, bool(m.finding_ids))
        audit.record(db, Action.THREAT_CHECK_REQUESTED, tenant_id=tenant_id, object_type="threat_check_run",
                     object_id=run.id, new={"advisory": adv.slug, "check": check.key, "assets": len(group),
                                            "scan_id": str(scan.id)})
        runs.append(run)
    db.flush()
    return runs


def _host_port(url: str) -> tuple[str, int] | None:
    try:
        u = urlsplit(url)
        return (u.hostname or "", u.port or (443 if u.scheme == "https" else 80))
    except ValueError:
        return None


def _tested(asset: Asset, allowed: set[str]) -> bool:
    """Whether any target the check was authorized to test belongs to this asset."""
    if asset.asset_type in (AssetType.HTTP_ENDPOINT, AssetType.WEB_APPLICATION):
        return asset.normalized_value in allowed
    hp = [x for x in (_host_port(u) for u in allowed) if x]
    if asset.asset_type in (AssetType.PORT, AssetType.SERVICE):
        p = parse_port_value(asset.normalized_value)
        return bool(p) and any(h == p[0] and port == p[1] for h, port in hp)
    return any(h == asset.normalized_value for h, _ in hp)


def sync_check_run(db: Session, scan: Scan) -> ThreatCheckRun | None:
    """Turn a finished (or cancelled) check scan into per-asset outcomes.

    Conservative on purpose: "not detected" requires the check's stage to have
    completed cleanly *and* the asset's target to have been authorized and tested.
    Everything else — failure, partial run, skipped stage, scope rejection, egress
    block, cancellation — is inconclusive. Nothing here resolves or closes a
    finding; only the scan's own completed coverage can do that.
    """
    run = db.execute(select(ThreatCheckRun).where(ThreatCheckRun.scan_id == scan.id)).scalar_one_or_none()
    if run is None or run.status not in ACTIVE_CHECK_RUN_STATES:
        return run
    now = _now()
    stage = scan.stages[0] if scan.stages else None
    reason: str | None = None
    if scan.status == ScanStatus.CANCELLED:
        reason = "the check was cancelled" + (f": {scan.error}" if scan.error else "")
    elif stage is None or stage.status == StageStatus.SKIPPED:
        reason = ("nothing could be tested: no authorized web endpoint for the selected assets"
                  + (f" ({stage.error})" if stage is not None and stage.error else ""))
    elif stage.status in (StageStatus.FAILED, StageStatus.CANCELLED):
        reason = f"the check did not run successfully{': ' + stage.error if stage.error else ''}"
    elif stage.status == StageStatus.PARTIAL:
        reason = "the check did not complete, so absence cannot be concluded"
    elif stage.status == StageStatus.COMPLETED and stage.error:
        # e.g. some targets blocked by the egress policy: be conservative for all of them.
        reason = f"the check completed with problems: {stage.error}"
    elif stage.status != StageStatus.COMPLETED:
        reason = f"the check ended in state {stage.status.value}"

    allowed: set[str] = set()
    if stage is not None:
        allowed = set(db.execute(select(ScopeDecision.target).where(
            ScopeDecision.scan_id == scan.id, ScopeDecision.stage_id == stage.id,
            ScopeDecision.decision == DecisionResult.ALLOWED)).scalars())
    # Read the result against what was dispatched, not against today's definitions.
    if run.template_id is not None:
        adv_cves, template = set(run.cves or []), run.template_id
    else:
        adv_cves = set(db.execute(select(ThreatAdvisory.cves).where(ThreatAdvisory.id == run.advisory_id)).scalar()
                       or [])
        template = db.execute(select(ThreatCheck.template_id).where(ThreatCheck.key == run.check_key)).scalar()
    current = published_advisories(db, [run.advisory_id])
    current_templates = _templates_for(db, current[0][1]) if current else set()
    concerns = [func.lower(func.split_part(Finding.source_finding_id, ":", 1)) == (template or "").lower()]
    if adv_cves:
        concerns.append(Finding.cve.overlap(sorted(adv_cves)))
    hits = db.execute(select(Finding.asset_id, Asset.normalized_value).join(Asset, Asset.id == Finding.asset_id).where(
        Finding.last_scan_id == scan.id, Finding.unverified.is_(False), or_(*concerns))).all()
    hit_assets = {a for a, _ in hits}
    hit_values = {v for _, v in hits}

    counts = {"detected": 0, "not_detected": 0, "inconclusive": 0}
    assets = {a.id: a for a in db.execute(select(Asset).where(Asset.id.in_(run.asset_ids))).scalars()}
    matches = db.execute(select(ThreatMatch).where(ThreatMatch.advisory_id == run.advisory_id,
                                                   ThreatMatch.asset_id.in_(run.asset_ids))).scalars()
    for m in matches:
        if m.last_check_run_id != run.id:
            continue  # a newer run owns this asset's outcome
        a = assets.get(m.asset_id)
        tested = a is not None and _tested(a, allowed)
        # A detection on the asset itself, or on a web endpoint that belongs to it.
        if a is not None and (a.id in hit_assets or any(_tested(a, {v}) for v in hit_values)):
            outcome, detail = CheckOutcome.DETECTED, "the approved check reported the issue on this asset"
        elif reason:
            outcome, detail = CheckOutcome.INCONCLUSIVE, reason
        elif not tested:
            outcome, detail = CheckOutcome.INCONCLUSIVE, ("this asset was not tested: it has no web endpoint the "
                                                          "check could reach, or scope did not authorize it")
        else:
            outcome, detail = CheckOutcome.NOT_DETECTED, ("the check completed without detecting the issue. This "
                                                          "is not proof the asset is safe")
        if current and not run_applies(run, m.advisory_version, current_templates, current[0][1].cves):
            outcome, detail = CheckOutcome.NONE, ("the advisory changed while this check ran, so its result does "
                                                  "not apply to the current version; request the check again")
        m.check_outcome, m.check_detail = outcome, detail[:500]
        m.checked_at = now if outcome != CheckOutcome.NONE else None
        m.assessment = assess(m.match_status, m.basis, m.check_outcome, bool(m.finding_ids))
        key = outcome.value if outcome.value in counts else "superseded"
        counts[key] = counts.get(key, 0) + 1
    if scan.status == ScanStatus.CANCELLED:
        run.status = CheckRunStatus.CANCELLED
    elif reason:
        run.status = CheckRunStatus.INCONCLUSIVE
    else:
        run.status = CheckRunStatus.COMPLETED
    run.finished_at = now
    run.summary = {**counts, **({"reason": reason} if reason else {})}
    db.flush()
    return run


TERMINAL_SCAN_STATES = (ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED, ScanStatus.CANCELLED)


def refresh_run_status(db: Session, run: ThreatCheckRun) -> bool:
    """Queued → running when its scan starts (display only); finish a run whose scan has
    already ended (its completion update was lost). Returns whether anything durable changed."""
    if run.status not in ACTIVE_CHECK_RUN_STATES:
        return False
    scan = db.get(Scan, run.scan_id) if run.scan_id else None
    if scan is not None and scan.status == ScanStatus.RUNNING and run.status == CheckRunStatus.QUEUED:
        run.status = CheckRunStatus.RUNNING
        return False
    if scan is None or scan.status in TERMINAL_SCAN_STATES:
        reconcile_run(db, run, scan)
        return True
    return False


def reconcile_run(db: Session, run: ThreatCheckRun, scan: Scan | None) -> None:
    locked = db.get(ThreatCheckRun, run.id, with_for_update=True, populate_existing=True)
    if locked is None or locked.status not in ACTIVE_CHECK_RUN_STATES:
        return
    if scan is not None:
        sync_check_run(db, scan)
        return
    reason = "the check's scan no longer exists"
    for m in db.execute(select(ThreatMatch).where(ThreatMatch.last_check_run_id == locked.id)).scalars():
        if m.check_outcome == CheckOutcome.PENDING:
            m.check_outcome, m.check_detail, m.checked_at = CheckOutcome.INCONCLUSIVE, reason, _now()
            m.assessment = assess(m.match_status, m.basis, m.check_outcome, bool(m.finding_ids))
    locked.status, locked.finished_at = CheckRunStatus.INCONCLUSIVE, _now()
    locked.summary = {**(locked.summary or {}), "reason": reason}
    db.flush()


def reconcile_check_runs(db: Session) -> int:
    """Finish every queued/running check whose scan has ended: the repair for a completion
    update that failed (it runs in a savepoint, so it can never fail the scan itself)."""
    fixed = 0
    for run in list(db.execute(select(ThreatCheckRun).where(
            ThreatCheckRun.status.in_([s.value for s in ACTIVE_CHECK_RUN_STATES]))).scalars()):
        fixed += refresh_run_status(db, run)
    return fixed


# ==================================================================== remediation
def update_match(db: Session, match_id: uuid.UUID, *, changes: dict[str, Any], user_id: uuid.UUID) -> ThreatMatch:
    m = db.get(ThreatMatch, match_id)
    if m is None:
        raise NotFound("Not found")
    before = {"remediation_status": m.remediation_status.value,
              "assigned_to": str(m.assigned_to) if m.assigned_to else None, "remediation_note": m.remediation_note}
    if "assigned_to" in changes and changes["assigned_to"] is not None:
        member = db.execute(select(TenantMembership.id).where(
            TenantMembership.tenant_id == m.tenant_id, TenantMembership.user_id == changes["assigned_to"],
            TenantMembership.is_active.is_(True))).first()
        if member is None:
            raise ValidationFailed("The assignee must be an active member of this tenant")
    if changes.get("remediation_status") is not None:
        m.remediation_status = RemediationStatus(changes["remediation_status"])
    if "assigned_to" in changes:
        m.assigned_to = changes["assigned_to"]
    if "remediation_note" in changes:
        m.remediation_note = changes["remediation_note"]
    after = {"remediation_status": m.remediation_status.value,
             "assigned_to": str(m.assigned_to) if m.assigned_to else None, "remediation_note": m.remediation_note}
    prev, new = audit.diff(before, after)
    if new:
        audit.record(db, Action.THREAT_REMEDIATION_UPDATED, tenant_id=m.tenant_id, user_id=user_id,
                     object_type="threat_match", object_id=m.id, previous=prev, new=new)
    db.flush()
    return m


# ======================================================================= summaries
EMPTY_COUNTS = {"affected": 0, "confirmed": 0, "not_detected": 0, "inconclusive": 0, "unchecked": 0,
                "check_pending": 0, "reported_unverified": 0, "version_unknown": 0, "not_affected_version": 0,
                "no_longer_observed": 0, "remediated": 0}


def counts_by_advisory(db: Session, advisory_ids: list[uuid.UUID],
                       organization_id: uuid.UUID | None = None) -> dict[uuid.UUID, dict[str, int]]:
    """Tenant-scoped counts (the session's RLS confines them to the caller's tenant)."""
    stmt = (select(ThreatMatch.advisory_id, ThreatMatch.assessment, ThreatMatch.remediation_status, func.count())
            .where(ThreatMatch.advisory_id.in_(advisory_ids))
            .group_by(ThreatMatch.advisory_id, ThreatMatch.assessment, ThreatMatch.remediation_status))
    if organization_id:
        stmt = stmt.where(ThreatMatch.organization_id == organization_id)
    out: dict[uuid.UUID, dict[str, int]] = {a: dict(EMPTY_COUNTS) for a in advisory_ids}
    from app.models.enums import REMEDIATION_DONE

    for adv_id, assessment, remediation, n in db.execute(stmt).all():
        c = out[adv_id]
        a = Assessment(assessment)
        if a in AFFECTED_ASSESSMENTS:
            c["affected"] += n
            if RemediationStatus(remediation) in REMEDIATION_DONE:
                c["remediated"] += n
        if a in (Assessment.POTENTIALLY_AFFECTED, Assessment.VERSION_UNKNOWN, Assessment.REPORTED_UNVERIFIED):
            c["unchecked"] += n
        if a.value in c:
            c[a.value] += n
    return out


def freshness(db: Session, advisory_ids: list[uuid.UUID]) -> dict[uuid.UUID, ThreatCampaign]:
    return {c.advisory_id: c for c in db.execute(select(ThreatCampaign).where(
        ThreatCampaign.advisory_id.in_(advisory_ids))).scalars()}


SEVERITY_RANK = {s: i for i, s in enumerate((Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH,
                                             Severity.CRITICAL))}
