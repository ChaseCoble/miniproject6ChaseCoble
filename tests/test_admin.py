# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import re

import pytest
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.test import Client
from django.urls import reverse

from threatintel.models import Vulnerability, Watch

pytestmark = pytest.mark.django_db

PW = "test-pass-123"
ID1, ID2 = "CVE-2099-0001", "CVE-2099-0002"
VULN_LIST = "admin:threatintel_vulnerability_changelist"
VULN_ADD = "admin:threatintel_vulnerability_add"
WATCH_LIST = "admin:threatintel_watch_changelist"
WATCH_ADD = "admin:threatintel_watch_add"
NVD_FIELDS = {
    "nvd_status", "nvd_published", "nvd_last_modified", "cvss_score", "cvss_version",
    "cvss_severity", "cvss_vector", "cvss_source", "cvss_type", "nvd_fetched_at",
}


@pytest.fixture
def superuser_client(db):
    user = get_user_model().objects.create_superuser("root", "root@example.test", PW)
    c = Client()
    c.force_login(user)
    return c


def cve_ids_in(content):
    return set(re.findall(rb"CVE-2099-\d{4}", content))


# ---------- who can get in ----------

def test_admin_is_not_at_the_default_path(client):
    assert reverse("admin:index") != "/admin/"
    assert client.get("/admin/").status_code == 404


def test_anonymous_users_are_sent_to_the_admin_login(client):
    response = client.get(reverse("admin:index"))
    assert response.status_code == 302 and response["Location"].startswith(reverse("admin:login"))


def test_non_staff_users_are_sent_to_the_admin_login(make_client):
    response = make_client("alice").get(reverse("admin:index"))
    assert response.status_code == 302 and response["Location"].startswith(reverse("admin:login"))


def test_staff_without_permissions_cannot_open_the_models(db):
    user = get_user_model().objects.create_user("staffer", password=PW, is_staff=True)
    c = Client()
    c.force_login(user)
    assert c.get(reverse(VULN_LIST)).status_code == 403
    assert c.get(reverse(WATCH_LIST)).status_code == 403


def test_admin_login_is_throttled_like_the_site_login(client, clock):
    get_user_model().objects.create_superuser("root", "root@example.test", PW)
    url, nxt = reverse("admin:login"), reverse("admin:index")
    for _ in range(5):
        client.post(url, {"username": "root", "password": "wrong-pass-999", "next": nxt})
    assert client.post(url, {"username": "root", "password": PW, "next": nxt}).status_code == 429


# ---------- registration and configuration ----------

def test_both_models_are_registered():
    assert admin.site.is_registered(Vulnerability) and admin.site.is_registered(Watch)


def test_vulnerability_admin_is_set_up_for_triage():
    ma = admin.site._registry[Vulnerability]
    assert {"cve_id", "vendor", "product", "date_added", "due_date", "ransomware_use", "cvss_score"} <= set(ma.list_display)
    assert {"cve_id", "vendor", "product"} <= set(ma.search_fields)
    assert {"ransomware_use", "cvss_severity"} <= set(ma.list_filter)


def test_vulnerability_admin_makes_nvd_data_read_only():
    assert NVD_FIELDS <= set(admin.site._registry[Vulnerability].readonly_fields)


def test_watch_admin_is_usable_with_a_large_catalogue():
    ma = admin.site._registry[Watch]
    assert {"user", "vulnerability", "created"} <= set(ma.list_display)
    assert {"user", "vulnerability"} <= set(ma.raw_id_fields)


# ---------- pages ----------

@pytest.mark.parametrize("name", ["admin:index", VULN_LIST, VULN_ADD, WATCH_LIST, WATCH_ADD])
def test_superuser_can_open_the_admin_pages(superuser_client, name):
    assert superuser_client.get(reverse(name)).status_code == 200


def test_admin_search_filters_the_changelist(superuser_client, seed, kev_entry):
    seed([kev_entry(cveID=ID1, vendorProject="Acme"), kev_entry(cveID=ID2, vendorProject="Globex")])
    response = superuser_client.get(reverse(VULN_LIST), {"q": "globex"})
    assert response.status_code == 200 and cve_ids_in(response.content) == {ID2.encode()}


# ---------- entry ----------

VULN_FORM = {
    "cve_id": ID1, "vendor": "Acme", "product": "Widget", "name": "Acme Widget Vulnerability",
    "short_description": "Fake entry.", "date_added": "2099-01-01", "due_date": "2099-01-22",
}


def test_admin_can_add_a_vulnerability(superuser_client):
    assert superuser_client.post(reverse(VULN_ADD), VULN_FORM).status_code == 302
    row = Vulnerability.objects.get(cve_id=ID1)
    assert row.ransomware_use is False and row.nvd_fetched_at is None


def test_admin_rejects_a_malformed_cve_id(superuser_client):
    response = superuser_client.post(reverse(VULN_ADD), {**VULN_FORM, "cve_id": "not-a-cve"})
    assert response.status_code == 200 and Vulnerability.objects.count() == 0


def test_admin_cannot_overwrite_nvd_fields_even_if_they_are_posted(superuser_client, seed, kev_entry):
    seed([kev_entry(cveID=ID1)])
    row = Vulnerability.objects.get()
    url = reverse("admin:threatintel_vulnerability_change", args=[row.pk])
    response = superuser_client.post(url, {**VULN_FORM, "vendor": "Changed", "cvss_score": "0", "nvd_status": "Forged"})
    assert response.status_code == 302
    row.refresh_from_db()
    assert row.vendor == "Changed" and row.cvss_score is None and row.nvd_status is None


def test_admin_user_page_never_shows_the_full_password_hash(superuser_client):
    target = get_user_model().objects.create_user("target", password=PW)
    response = superuser_client.get(reverse("admin:auth_user_change", args=[target.pk]))
    assert response.status_code == 200 and target.password.encode() not in response.content


def test_admin_login_page_loads(client):
    assert client.get(reverse("admin:login")).status_code == 200


def test_superuser_can_log_in_through_the_admin_login(client, clock):
    get_user_model().objects.create_superuser("root", "root@example.test", PW)
    response = client.post(reverse("admin:login"), {"username": "root", "password": PW, "next": reverse("admin:index")})
    assert response.status_code == 302
    assert client.get(reverse("admin:index")).status_code == 200


def test_non_staff_user_cannot_log_in_through_the_admin_login(client, clock):
    get_user_model().objects.create_user("alice", password=PW)
    response = client.post(reverse("admin:login"), {"username": "alice", "password": PW, "next": reverse("admin:index")})
    assert response.status_code == 200
    assert "_auth_user_id" not in client.session


def test_site_login_failures_also_lock_the_admin_login(client, clock):
    get_user_model().objects.create_superuser("root", "root@example.test", PW)
    for _ in range(5):
        client.post("/accounts/login/", {"username": "root", "password": "wrong-pass-999"})
    response = client.post(reverse("admin:login"), {"username": "root", "password": PW, "next": reverse("admin:index")})
    assert response.status_code == 429
