"""The active web scanner must be given the pages a crawl found, not just the origin.

Found against a live DVWA: every ZAP job starts from a blank daemon session (jobs
must not see each other's traffic), so the crawl's site tree is gone by the time the
active scanner runs. It seeded one URL and attacked a tree of one node — 298 crawled
pages, then 14 observations, and not one parameter of the application was tested.

The crawl now records its pages on the endpoint asset, and a scanner that declares
`wants_crawled_pages` is handed them as targets, which it reloads before attacking.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from asm_sensors.registry import get_adapter
from asm_sensors.targets import TargetKind
from sqlalchemy import select

from app.db.session import new_session
from app.models import Asset, Organization, ScanProfile
from app.models.enums import AssetStatus, AssetType, ScopeStatus, StageType
from app.scans import orchestrator
from app.scans.targets import build_targets

ORIGIN = "http://app.example.com:8580"
PAGES = ["/vulnerabilities/sqli/?id=1&Submit=Submit", "/vulnerabilities/xss_r/?name=x", "/login.php"]


@pytest.fixture
def org_with_crawl(db_clean, factory):
    tenant = factory.tenant()
    org = factory.org(tenant.id, domains=("example.com",))
    now = datetime.now(UTC)
    with new_session(tenant.id) as db:
        db.add(Asset(tenant_id=tenant.id, organization_id=org.id, asset_type=AssetType.HTTP_ENDPOINT,
                     value=ORIGIN, normalized_value=ORIGIN, status=AssetStatus.ACTIVE,
                     scope_status=ScopeStatus.IN_SCOPE, first_seen=now, last_seen=now, discovered_at=now,
                     meta={"crawled_pages": PAGES}))
        db.commit()
    return tenant, org


def _scan(db, tenant_id, org_id, slug="web-app-scan"):
    pid = db.scalar(select(ScanProfile.id).where(ScanProfile.slug == slug, ScanProfile.tenant_id.is_(None)))
    scan = orchestrator.create_scan(db, tenant_id=tenant_id, organization_id=org_id, profile_id=pid)
    db.commit()
    return scan


class TestTargeting:
    def test_a_parameter_scanner_gets_every_crawled_page(self, org_with_crawl):
        tenant, org = org_with_crawl
        with new_session(tenant.id) as db:
            scan = _scan(db, tenant.id, org.id)
            o = db.get(Organization, org.id)
            built = build_targets(db, o, scan, StageType.VULNERABILITY_DETECTION, limit=500, crawled_pages=True)
        values = {t.value for t in built.targets}
        assert values == {ORIGIN} | {ORIGIN + p for p in PAGES}
        assert all(t.kind == TargetKind.URL for t in built.targets)

    def test_a_scanner_that_did_not_ask_still_gets_origins_only(self, org_with_crawl):
        # Nuclei shares this stage; handing it 300 URLs would multiply every scan's work.
        tenant, org = org_with_crawl
        with new_session(tenant.id) as db:
            scan = _scan(db, tenant.id, org.id)
            o = db.get(Organization, org.id)
            built = build_targets(db, o, scan, StageType.VULNERABILITY_DETECTION, limit=500)
        assert {t.value for t in built.targets} == {ORIGIN}

    def test_the_page_list_respects_the_stage_limit(self, org_with_crawl):
        tenant, org = org_with_crawl
        with new_session(tenant.id) as db:
            scan = _scan(db, tenant.id, org.id)
            o = db.get(Organization, org.id)
            built = build_targets(db, o, scan, StageType.VULNERABILITY_DETECTION, limit=2, crawled_pages=True)
        assert len(built.targets) <= 2

    def test_only_the_scanner_that_needs_pages_declares_it(self):
        assert get_adapter("zap_active").wants_crawled_pages is True
        assert get_adapter("nuclei").wants_crawled_pages is False
        assert get_adapter("zap_spider").wants_crawled_pages is False

    def test_the_crawl_stage_itself_is_unaffected(self, org_with_crawl):
        # The expansion follows the adapter's declaration, so the crawler — which
        # discovers pages rather than being given them — is handed origins only.
        tenant, org = org_with_crawl
        with new_session(tenant.id) as db:
            scan = _scan(db, tenant.id, org.id)
            o = db.get(Organization, org.id)
            built = build_targets(db, o, scan, StageType.WEB_CRAWL, limit=500,
                                  crawled_pages=get_adapter("zap_spider").wants_crawled_pages)
        assert {t.value for t in built.targets} == {ORIGIN}
