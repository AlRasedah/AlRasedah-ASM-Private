"""Scheduling a scan in words: "every Sunday at 9 am", not "0 9 * * 0"."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.errors import ValidationFailed
from app.db.session import new_session
from app.models import Organization, ScanProfile
from app.scans import schedules

PW = "Sup3r-Secret-Passw0rd!"


@pytest.fixture
def client(db_clean):
    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def signed_in(client, factory):
    tenant = factory.tenant()
    user = factory.user(tenant.id)
    org = factory.org(tenant.id, domains=("example.com",))
    r = client.post("/api/v1/auth/login", json={"email": user.email, "password": PW})
    with new_session(tenant.id) as db:
        pid = db.scalar(select(ScanProfile.id).where(ScanProfile.slug == "standard-asm",
                                                     ScanProfile.tenant_id.is_(None)))
        oid = db.scalar(select(Organization.id).where(Organization.id == org.id))
    return client, str(oid), str(pid), {"Authorization": f"Bearer {r.json()['access_token']}"}


class TestTranslation:
    @pytest.mark.parametrize(("rec", "cron", "words"), [
        (schedules.Recurrence("weekly", hour=9, weekday=0), "0 9 * * 0", "Every Sunday at 09:00"),
        (schedules.Recurrence("weekly", hour=17, minute=30, weekday=3), "30 17 * * 3", "Every Wednesday at 17:30"),
        (schedules.Recurrence("daily", hour=2), "0 2 * * *", "Every day at 02:00"),
        (schedules.Recurrence("monthly", hour=3, day=1), "0 3 1 * *", "Day 1 of every month at 03:00"),
    ])
    def test_a_recurrence_round_trips(self, rec, cron, words):
        assert schedules.to_cron(rec) == cron
        assert schedules.describe(cron) == words
        assert schedules.from_cron(cron) == rec

    def test_cron_may_write_sunday_as_seven(self):
        assert schedules.describe("0 9 * * 7") == "Every Sunday at 09:00"

    def test_a_cadence_the_builder_cannot_express_is_kept_and_shown_as_cron(self):
        assert schedules.from_cron("*/15 * * * *") is None
        assert schedules.describe("*/15 * * * *") == "Custom schedule (*/15 * * * *)"

    @pytest.mark.parametrize("rec", [
        schedules.Recurrence("weekly", hour=9),                 # no day chosen
        schedules.Recurrence("monthly", hour=9),                # no day chosen
        schedules.Recurrence("monthly", hour=9, day=31),        # a day some months lack
        schedules.Recurrence("hourly", hour=9),                 # not offered
    ])
    def test_an_incomplete_choice_is_refused(self, rec):
        with pytest.raises(ValidationFailed):
            schedules.to_cron(rec)

    def test_a_day_that_skips_short_months_never_round_trips(self):
        # 0 3 31 * * is valid cron but would not run in February; the builder does not own it.
        assert schedules.from_cron("0 3 31 * *") is None


class TestApi:
    def test_a_schedule_is_created_from_words(self, signed_in):
        client, org, profile, h = signed_in
        r = client.post("/api/v1/schedules", headers=h, json={
            "organization_id": org, "profile_id": profile, "name": "Weekly sweep",
            "repeat": {"frequency": "weekly", "hour": 9, "minute": 0, "weekday": 0}, "timezone": "Asia/Riyadh"})
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["description"] == "Every Sunday at 09:00"
        assert body["recurrence"] == {"frequency": "weekly", "hour": 9, "minute": 0, "weekday": 0, "day": None}
        assert body["cron"] == "0 9 * * 0" and body["next_run_at"]

    def test_an_existing_cron_schedule_still_reads_back(self, signed_in):
        client, org, profile, h = signed_in
        r = client.post("/api/v1/schedules", headers=h, json={
            "organization_id": org, "profile_id": profile, "name": "Odd one", "cron": "*/15 * * * *"})
        assert r.status_code == 201, r.text
        assert r.json()["description"] == "Custom schedule (*/15 * * * *)"
        assert r.json()["recurrence"] is None, "the builder cannot show it, and must not pretend otherwise"

    def test_changing_when_it_runs(self, signed_in):
        client, org, profile, h = signed_in
        sid = client.post("/api/v1/schedules", headers=h, json={
            "organization_id": org, "profile_id": profile, "name": "Weekly sweep",
            "repeat": {"frequency": "weekly", "hour": 9, "weekday": 0}}).json()["id"]
        r = client.patch(f"/api/v1/schedules/{sid}", headers=h,
                         json={"repeat": {"frequency": "daily", "hour": 22, "minute": 15}})
        assert r.status_code == 200, r.text
        assert r.json()["description"] == "Every day at 22:15" and r.json()["cron"] == "15 22 * * *"

    def test_one_way_or_the_other_but_not_both(self, signed_in):
        client, org, profile, h = signed_in
        base = {"organization_id": org, "profile_id": profile, "name": "x"}
        assert client.post("/api/v1/schedules", headers=h, json=base).status_code == 422
        assert client.post("/api/v1/schedules", headers=h, json={
            **base, "cron": "0 9 * * 0", "repeat": {"frequency": "daily", "hour": 9}}).status_code == 422

    def test_the_listing_speaks_words_too(self, signed_in):
        client, org, profile, h = signed_in
        client.post("/api/v1/schedules", headers=h, json={
            "organization_id": org, "profile_id": profile, "name": "Weekly sweep",
            "repeat": {"frequency": "weekly", "hour": 9, "weekday": 0}})
        rows = client.get("/api/v1/schedules", headers=h).json()
        assert [s["description"] for s in rows] == ["Every Sunday at 09:00"]
