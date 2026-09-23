"""External exposure map on PostgreSQL with RLS: bounds, cycles, high-degree nodes, isolation."""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from .sensors_fake import FakeSensors

PW = "Sup3r-Secret-Passw0rd!"
ENGINE_NAMES = ("dnsx", "httpx", "naabu", "nuclei", "subfinder", "amass", "crtsh", "asnlookup", "shodan", "zap_")


@pytest.fixture
def env(db_clean, factory, monkeypatch):
    from app.exposure import graph
    from app.main import app

    graph.cache.clear()
    FakeSensors(monkeypatch)
    ta, tb = factory.tenant("Alpha"), factory.tenant("Bravo")
    admin = factory.user(ta.id, role="tenant_admin", password=PW)
    viewer = factory.user(ta.id, role="viewer", password=PW)
    badmin = factory.user(tb.id, role="tenant_admin", password=PW)
    with TestClient(app) as c:
        def login(u):
            token = c.post("/api/v1/auth/login", json={"email": u.email, "password": PW}).json()["access_token"]
            return {"Authorization": f"Bearer {token}"}

        yield {"c": c, "ta": ta, "tb": tb, "admin": login(admin), "viewer": login(viewer), "bravo": login(badmin)}
    graph.cache.clear()


def _scan(c, h, name="Acme"):
    org = c.post("/api/v1/organizations", headers=h, json={"name": name}).json()
    c.post("/api/v1/scopes/bulk", headers=h, json={"organization_id": org["id"], "entries": ["example.com"]})
    profiles = {p["slug"]: p for p in c.get("/api/v1/scan-profiles", headers=h).json()}
    c.post("/api/v1/scans", headers=h, json={"organization_id": org["id"], "profile_id": profiles["standard-asm"]["id"]})
    return org


def _map(c, h, **q):
    r = c.get("/api/v1/exposure-map", headers=h, params=q)
    assert r.status_code == 200, r.text
    return r.json()


def _by_label(m):
    return {n["label"]: n for n in m["nodes"]}


def test_organization_map_follows_the_exposure_chain(env):
    c, h = env["c"], env["admin"]
    org = _scan(c, h)
    m = _map(c, h, organization_id=org["id"], depth=4)
    nodes = _by_label(m)
    assert "example.com" in nodes and nodes["example.com"]["id"] in m["root_ids"]
    types = {n["type"] for n in m["nodes"]}
    assert {"root_domain", "subdomain", "ip_address", "port", "http_endpoint", "finding"} <= types
    relations = {e["relation"] for e in m["edges"]}
    assert {"subdomain_of", "resolves_to", "has_port", "serves", "has_finding"} <= relations
    for e in m["edges"]:
        assert e["meaning"] and e["source_label"] and e["freshness"] in ("current", "stale", "inactive", "historical",
                                                                           "unverified")
        assert e["first_seen"] and e["last_seen"]
    sub = next(e for e in m["edges"] if e["relation"] == "subdomain_of")
    assert sub["evidence"] == "derived" and "not a network connection" in sub["meaning"]
    assert "never means one asset can be used to reach another" in m["notice"]
    # The capability, never the engine that observed it (ADR-022).
    body = json.dumps(m).lower()
    assert not any(f'"{n}' in body or f" {n}" in body for n in ENGINE_NAMES), [n for n in ENGINE_NAMES if n in body]


def test_bounds_are_enforced_and_reported(env):
    c, h = env["c"], env["admin"]
    org = _scan(c, h)
    one = _map(c, h, organization_id=org["id"], depth=1, include_findings=False)
    assert {n["depth"] for n in one["nodes"]} <= {0, 1} and one["limits"]["depth"] == 1
    small = _map(c, h, organization_id=org["id"], depth=4, max_nodes=10)
    assert len(small["nodes"]) <= 10 and small["truncated"] and "node limit reached" in small["truncation_reasons"]
    assert len(small["edges"]) <= small["limits"]["max_edges"]
    for bad in ({"depth": 5}, {"max_nodes": 5000}, {"per_node": 1}):
        assert c.get("/api/v1/exposure-map", headers=h, params={"organization_id": org["id"], **bad}).status_code == 422
    assert c.get("/api/v1/exposure-map", headers=h).status_code == 422


def test_time_budget_returns_a_partial_map(env, monkeypatch):
    from app.exposure import graph

    c, h = env["c"], env["admin"]
    org = _scan(c, h)
    monkeypatch.setattr(graph, "TIME_BUDGET_S", 0.0)
    m = _map(c, h, organization_id=org["id"], depth=3)
    assert m["truncated"] and "time limit reached" in m["truncation_reasons"]
    assert all(n["depth"] == 0 or n["kind"] == "finding" for n in m["nodes"])


def _add(db, tenant, org, atype, value, **kw):
    from app.models import Asset

    now = datetime.now(UTC)
    a = Asset(tenant_id=tenant, organization_id=org, asset_type=atype, value=value, normalized_value=value,
              scope_status=kw.pop("scope_status", "in_scope"), first_seen=now, last_seen=now, discovered_at=now,
              meta={}, tags=[], sources=kw.pop("sources", ["dnsx"]), risk_factors=[], **kw)
    db.add(a)
    db.flush()
    return a


def _rel(db, tenant, org, src, dst, relation, **kw):
    from app.models import AssetRelationship

    now = datetime.now(UTC)
    r = AssetRelationship(tenant_id=tenant, organization_id=org, source_asset_id=src.id, target_asset_id=dst.id,
                          relation_type=relation, active=kw.pop("active", True), missed_count=0,
                          first_seen=kw.pop("first_seen", now), last_seen=kw.pop("last_seen", now),
                          source=kw.pop("source", "dnsx"), attributes={})
    db.add(r)
    db.flush()
    return r


def test_a_high_degree_node_is_capped_and_says_what_it_hid(env, tenant_db):
    c, h, ta = env["c"], env["admin"], env["ta"]
    org = c.post("/api/v1/organizations", headers=h, json={"name": "Wide"}).json()
    oid = uuid.UUID(org["id"])
    with tenant_db(ta.id) as db:
        root = _add(db, ta.id, oid, "root_domain", "wide-corp.com")
        for i in range(600):
            sub = _add(db, ta.id, oid, "subdomain", f"h{i:03d}.wide-corp.com")
            _rel(db, ta.id, oid, sub, root, "subdomain_of")
        db.commit()
    started = time.monotonic()
    m = _map(c, h, organization_id=org["id"], depth=2, per_node=25, include_findings=False)
    assert time.monotonic() - started < 5
    root_node = _by_label(m)["wide-corp.com"]
    assert len(m["nodes"]) == 26 and root_node["hidden"] == {"subdomain_of": 575}
    # Expanding the node (what the UI does for "+575 more") takes a larger per-node budget,
    # still bounded.
    wider = _map(c, h, expand=root_node["id"], per_node=100, include_findings=False)
    assert len(wider["nodes"]) == 101 and wider["expanded"] == root_node["id"]


def test_cycles_terminate_and_every_node_appears_once(env, tenant_db):
    c, h, ta = env["c"], env["admin"], env["ta"]
    org = c.post("/api/v1/organizations", headers=h, json={"name": "Loop"}).json()
    oid = uuid.UUID(org["id"])
    with tenant_db(ta.id) as db:
        a = _add(db, ta.id, oid, "subdomain", "a.loop-corp.com")
        b = _add(db, ta.id, oid, "subdomain", "b.loop-corp.com")
        d = _add(db, ta.id, oid, "subdomain", "c.loop-corp.com")
        for x, y in ((a, b), (b, d), (d, a)):
            _rel(db, ta.id, oid, x, y, "cname")
        db.commit()
        start = a.id
    m = _map(c, h, asset_id=str(start), depth=4)
    assert sorted(n["label"] for n in m["nodes"]) == ["a.loop-corp.com", "b.loop-corp.com", "c.loop-corp.com"]
    assert len(m["edges"]) == 3 and not m["truncated"]


def test_inactive_historical_and_unverified_are_distinguished(env, tenant_db):
    from app.models import Finding

    c, h, ta = env["c"], env["admin"], env["ta"]
    org = c.post("/api/v1/organizations", headers=h, json={"name": "Ages"}).json()
    oid = uuid.UUID(org["id"])
    old = datetime.now(UTC) - timedelta(days=60)
    with tenant_db(ta.id) as db:
        host = _add(db, ta.id, oid, "subdomain", "www.ages-corp.com")
        ip_now = _add(db, ta.id, oid, "ip_address", "198.51.100.1", scope_status="derived")
        ip_gone = _add(db, ta.id, oid, "ip_address", "198.51.100.2", scope_status="derived")
        ip_old = _add(db, ta.id, oid, "ip_address", "198.51.100.3", scope_status="derived")
        port = _add(db, ta.id, oid, "port", "198.51.100.1:22/tcp", scope_status="derived", sources=["shodan"])
        _rel(db, ta.id, oid, host, ip_now, "resolves_to")
        _rel(db, ta.id, oid, host, ip_gone, "resolves_to", active=False, last_seen=old)
        _rel(db, ta.id, oid, host, ip_old, "resolves_to", last_seen=old)
        _rel(db, ta.id, oid, ip_now, port, "has_port", source="shodan")
        now = datetime.now(UTC)
        db.add(Finding(tenant_id=ta.id, organization_id=oid, asset_id=port.id, fingerprint=uuid.uuid4().hex,
                       source="shodan", source_finding_id="x", title="Reported CVE", cve=["CVE-2098-1"], unverified=True,
                       first_seen=now, last_seen=now, evidence={}, references=[], cwe=[], tags=[], risk_factors=[]))
        db.commit()
        start = host.id
    default = _map(c, h, asset_id=str(start), depth=3)
    labels = _by_label(default)
    assert "198.51.100.2" not in labels  # inactive relationships are hidden unless asked for
    edges = {(e["relation"], _label(default, e["target"])): e for e in default["edges"]}
    assert edges[("resolves_to", "198.51.100.1")]["freshness"] == "current"
    assert edges[("resolves_to", "198.51.100.3")]["freshness"] == "stale"
    assert edges[("has_port", "198.51.100.1:22/tcp")]["freshness"] == "historical"
    assert labels["198.51.100.1:22/tcp"]["third_party_only"] is True
    assert not any(n["kind"] == "finding" for n in default["nodes"])  # unverified reports only on request
    full = _map(c, h, asset_id=str(start), depth=3, include_inactive=True, include_unverified=True)
    fe = {(e["relation"], _label(full, e["target"])): e for e in full["edges"]}
    assert fe[("resolves_to", "198.51.100.2")]["freshness"] == "inactive"
    finding = next(n for n in full["nodes"] if n["kind"] == "finding")
    assert finding["unverified"] is True and fe[("has_finding", "Reported CVE")]["freshness"] == "unverified"


def _label(m, node_id):
    return next(n["label"] for n in m["nodes"] if n["id"] == node_id)


def test_tenants_and_organizations_are_boundaries(env):
    c, h, bravo = env["c"], env["admin"], env["bravo"]
    org_a = _scan(c, h, "Alpha org")
    org_b = _scan(c, bravo, "Bravo org")  # the same names in another tenant
    a_map, b_map = _map(c, h, organization_id=org_a["id"]), _map(c, bravo, organization_id=org_b["id"])
    assert {n["label"] for n in a_map["nodes"] if n["kind"] == "asset"} & {n["label"] for n in b_map["nodes"]}
    assert not {n["id"] for n in a_map["nodes"]} & {n["id"] for n in b_map["nodes"]}
    a_node = next(n for n in a_map["nodes"] if n["label"] == "example.com")
    for q in ({"organization_id": org_a["id"]}, {"asset_id": a_node["id"]}, {"expand": a_node["id"]},
              {"organization_id": org_b["id"], "asset_id": a_node["id"]}):
        assert c.get("/api/v1/exposure-map", headers=bravo, params=q).status_code == 404, q
    # Inside one tenant the organization boundary is explicit too.
    org_a2 = c.post("/api/v1/organizations", headers=h, json={"name": "Other org"}).json()
    assert c.get("/api/v1/exposure-map", headers=h, params={"organization_id": org_a2["id"],
                                                           "asset_id": a_node["id"]}).status_code == 404


def test_cache_keys_carry_tenant_and_authorization(env, monkeypatch, tenant_db):
    from app.core.errors import NotFound
    from app.exposure import graph

    c, h, viewer = env["c"], env["admin"], env["viewer"]
    org = _scan(c, h)
    calls = []
    real = graph.build

    def counting(db, p, *, findings_allowed):  # noqa: ANN001
        calls.append(findings_allowed)
        return real(db, p, findings_allowed=findings_allowed)

    monkeypatch.setattr(graph, "build", counting)
    first = _map(c, h, organization_id=org["id"])
    again = _map(c, h, organization_id=org["id"])
    assert not first["cached"] and again["cached"] and len(calls) == 1
    assert not _map(c, viewer, organization_id=org["id"])["cached"]  # another role: its own entry
    # The same parameters from another tenant are never answered from this tenant's entry.
    with tenant_db(env["tb"].id) as db, pytest.raises(NotFound):
        graph.cached_build(db, graph.MapParams(organization_id=uuid.UUID(org["id"])), tenant_id=env["tb"].id,
                           role="tenant_admin", findings_allowed=True)
    assert len(calls) == 3


def test_asset_page_starts_from_that_asset(env, system_db):
    from app.models import Asset

    c, h = env["c"], env["admin"]
    _scan(c, h)
    ep = system_db.execute(select(Asset).where(Asset.normalized_value == "https://api.example.com")).scalar_one()
    m = _map(c, h, asset_id=str(ep.id), depth=1)
    assert m["root_ids"] == [str(ep.id)] and any(e["relation"] in ("serves", "hosted_on") for e in m["edges"])
