"""A data source that cannot return anything must not be offered (review finding F8).

The catalog emitted every provider an adapter declares, so Facebook CT search was
still selectable and its key still savable — with advice on obtaining a developer
app. Meta discontinued that API, so the result is the most expensive kind of
integration problem: a key that saves cleanly and produces nothing, with no error
anywhere to explain it. (Our pinned subfinder still accepts the source; the upstream
service is what is gone, which is why the registry lives here and not in a version.)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.integrations import providers as provider_info

PW = "Sup3r-Secret-Passw0rd!"


@pytest.fixture
def signed_in(db_clean, factory):
    from app.main import app

    tenant = factory.tenant()
    user = factory.user(tenant.id)
    with TestClient(app) as c:
        r = c.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
        yield c, {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_a_dead_source_is_not_in_the_catalog(signed_in):
    client, h = signed_in
    catalog = client.get("/api/v1/credentials/providers", headers=h).json()
    assert catalog, "the catalog still lists the sources that work"
    assert "facebook" not in {p["provider"] for p in catalog}
    assert {"shodan", "censys"} <= {p["provider"] for p in catalog}


def test_saving_a_key_for_it_is_refused_with_the_reason(signed_in):
    client, h = signed_in
    r = client.put("/api/v1/credentials/facebook", headers=h, json={"value": "app-id:app-secret"})
    assert r.status_code == 422
    assert "discontinued" in r.json()["error"]["message"].lower()


def test_a_key_saved_before_can_still_be_removed(signed_in, factory):
    # Hiding a provider must not strand a credential someone already stored.
    from app.db.session import new_session
    from app.models import Secret
    from sqlalchemy import select

    client, h = signed_in
    me = client.get("/api/v1/auth/me", headers=h).json()
    tenant_id = me["tenant"]["id"]
    from app.services import secrets

    with new_session(tenant_id) as db:
        secrets.put_secret(db, tenant_id=tenant_id, name="scanner:facebook", value="old:key",
                           kind="scanner_credential", provider="facebook")
        db.commit()
        cid = db.scalar(select(Secret.id).where(Secret.provider == "facebook"))
    listed = client.get("/api/v1/credentials", headers=h).json()
    assert "facebook" in {c["provider"] for c in listed}, "it is visible so it can be cleaned up"
    assert client.delete(f"/api/v1/credentials/{cid}", headers=h).status_code == 200



def test_the_registry_records_the_reason_for_developers():
    assert provider_info.is_available("shodan") and not provider_info.is_available("facebook")
    assert "Meta discontinued" in provider_info.UNAVAILABLE["facebook"]
