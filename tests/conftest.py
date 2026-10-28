# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import json
import socket
from pathlib import Path
from datetime import datetime, timezone
import pytest

FIXTURES = Path(__file__).parent / "fixtures"
PW = "test-pass-123"

@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    # hard control: any real connection attempt in any test fails loudly
    def refuse(*args, **kwargs):
        raise RuntimeError("tests must not touch the network")
    monkeypatch.setattr(socket.socket, "connect", refuse)


@pytest.fixture
def load_fixture():
    def _load(name):
        return json.loads((FIXTURES / name).read_text())
    return _load


@pytest.fixture
def kev_entry():
    def _make(**overrides):
        entry = {
            "cveID": "CVE-2099-0001",
            "vendorProject": "Acme",
            "product": "Widget",
            "vulnerabilityName": "Acme Widget Test Vulnerability",
            "shortDescription": "Fake entry for tests.",
            "dateAdded": "2099-01-01",
            "dueDate": "2099-01-22",
            "knownRansomwareCampaignUse": "Unknown",
            "cwes": [],
            "notes": "",
        }
        entry.update(overrides)
        return entry
    return _make

@pytest.fixture(autouse=True)
def clear_cache():
    from django.core.cache import cache
    cache.clear()
    yield
    cache.clear()


class FakeClock:
    def __init__(self):
        self.now = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


class FakeFetchers:
    def __init__(self, kev_feed, nvd_doc_for):
        self.kev_feed, self.nvd_doc_for = kev_feed, nvd_doc_for
        self.kev_error = self.nvd_error = None
        self.kev_calls, self.nvd_calls = 0, []

    def kev(self):
        self.kev_calls += 1
        if self.kev_error is not None:
            raise self.kev_error
        return self.kev_feed

    def nvd(self, cve_id):
        self.nvd_calls.append(cve_id)
        if self.nvd_error is not None:
            raise self.nvd_error
        return self.nvd_doc_for(cve_id)


@pytest.fixture
def clock(monkeypatch):
    c = FakeClock()
    monkeypatch.setattr("threatintel.services.now", c)
    return c


@pytest.fixture
def fetchers(monkeypatch, clock, kev_entry, load_fixture):
    def nvd_doc_for(cve_id):
        doc = load_fixture("nvd_undergoing_analysis.json")
        doc["vulnerabilities"][0]["cve"]["id"] = cve_id
        return doc

    feed = {"vulnerabilities": [kev_entry(cveID=f"CVE-2099-{i:04d}") for i in (1, 2, 3)]}
    fake = FakeFetchers(feed, nvd_doc_for)
    monkeypatch.setattr("threatintel.services.fetch_kev", fake.kev)
    monkeypatch.setattr("threatintel.services.fetch_nvd", fake.nvd)
    return fake


@pytest.fixture
def seed(db):
    from threatintel.services import upsert_kev
    from threatintel.sources import parse_kev

    def _seed(entries):
        upsert_kev(parse_kev({"vulnerabilities": entries}))
    return _seed


@pytest.fixture
def make_client(db):
    from django.contrib.auth import get_user_model
    from django.test import Client

    def _make(username, enforce_csrf=False):
        user = get_user_model().objects.create_user(username=username, password=PW)
        c = Client(enforce_csrf_checks=enforce_csrf)
        c.force_login(user)
        c.user = user
        return c
    return _make


@pytest.fixture
def alice(make_client):
    return make_client("alice")


@pytest.fixture
def bob(make_client):
    return make_client("bob")


