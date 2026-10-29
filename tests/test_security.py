# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import logging
import re

import pytest
from django.test import Client

from threatintel.models import Vulnerability, Watch

pytestmark = pytest.mark.django_db

ID1, ID2, ID3 = "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"
FORM = re.compile(rb"<form\b[^>]*>.*?</form>", re.S | re.I)


@pytest.fixture
def three(seed, kev_entry):
    seed([kev_entry(cveID=i) for i in (ID1, ID2, ID3)])


def make_watch(user, cve_id=ID1, note=""):
    return Watch.objects.create(user=user, vulnerability=Vulnerability.objects.get(cve_id=cve_id), note=note)


def watch_rows():
    return sorted(Watch.objects.values_list("user__username", "vulnerability__cve_id", "note"))


def post_forms(content):
    return [f for f in FORM.findall(content)
            if re.search(rb'method="post"', f[: f.index(b">") + 1], re.I)]


# ---------- CSRF ----------

@pytest.mark.parametrize("path", [
    "/accounts/register/", "/accounts/login/", "/accounts/logout/",
    f"/watch/{ID1}/add/", f"/watch/{ID1}/edit/", f"/watch/{ID1}/delete/", "/refresh/",
])
def test_post_without_a_csrf_token_is_refused_and_changes_nothing(make_client, three, fetchers, path):
    c = make_client("alice", enforce_csrf=True)
    make_watch(c.user, note="keep")
    response = c.post(path, {"note": "changed", "username": "x", "password1": "p", "password2": "p"})
    assert response.status_code == 403
    assert watch_rows() == [("alice", ID1, "keep")]
    assert fetchers.kev_calls == 0
    assert "_auth_user_id" in c.session


def test_a_valid_csrf_token_is_accepted(make_client, three):
    c = make_client("alice", enforce_csrf=True)
    c.get("/")
    token = c.cookies["csrftoken"].value
    response = c.post(f"/watch/{ID1}/add/", {"csrfmiddlewaretoken": token})
    assert response.status_code == 302 and watch_rows() == [("alice", ID1, "")]


@pytest.mark.parametrize("path", ["/accounts/login/", "/accounts/register/"])
def test_anonymous_forms_carry_a_csrf_token(client, path):
    forms = post_forms(client.get(path).content)
    assert forms and all(b"csrfmiddlewaretoken" in f for f in forms)


@pytest.mark.parametrize("path", ["/", "/watchlist/", f"/watch/{ID1}/edit/", f"/cve/{ID1}/"])
def test_signed_in_forms_carry_a_csrf_token(make_client, three, fetchers, path):
    c = make_client("alice")
    make_watch(c.user, note="n")
    forms = post_forms(c.get(path).content)
    assert forms and all(b"csrfmiddlewaretoken" in f for f in forms)


def test_csrf_cookie_is_httponly_and_samesite_lax(client):
    cookie = client.get("/accounts/login/").cookies["csrftoken"]
    assert cookie["httponly"] and cookie["samesite"] == "Lax"


# ---------- headers ----------

def csp(response):
    policy = {}
    for part in response["Content-Security-Policy"].split(";"):
        tokens = part.split()
        if tokens:
            policy[tokens[0]] = tokens[1:]
    return policy


PUBLIC = ["/", "/about/", "/accounts/login/", "/no-such-page/"]


@pytest.mark.parametrize("path", PUBLIC)
def test_baseline_security_headers(client, path):
    response = client.get(path)
    assert response["X-Content-Type-Options"] == "nosniff"
    assert response["X-Frame-Options"] == "DENY"
    assert response["Referrer-Policy"] in {"same-origin", "strict-origin", "strict-origin-when-cross-origin", "no-referrer"}


@pytest.mark.parametrize("path", PUBLIC)
def test_content_security_policy_is_strict(client, path):
    policy = csp(client.get(path))
    assert policy["default-src"] == ["'self'"]
    assert policy["frame-ancestors"] == ["'none'"]
    assert policy["object-src"] == ["'none'"]
    assert policy["base-uri"] == ["'self'"]
    assert policy["form-action"] == ["'self'"]
    for directive, sources in policy.items():
        assert "'unsafe-inline'" not in sources and "'unsafe-eval'" not in sources, directive


@pytest.mark.parametrize("path", ["/watchlist/", f"/watch/{ID1}/edit/"])
def test_private_pages_are_not_cacheable(make_client, three, path):
    c = make_client("alice")
    make_watch(c.user)
    assert "no-store" in c.get(path)["Cache-Control"]


def test_unknown_host_header_is_rejected(client):
    assert client.get("/", HTTP_HOST="evil.example").status_code == 400


# ---------- errors and logs ----------

def test_404_page_leaks_nothing(client):
    response = client.get("/no-such-page/")
    assert response.status_code == 404
    for leak in (b"URLconf", b"Traceback", b"DEBUG", b"config.urls"):
        assert leak not in response.content


def test_unhandled_error_gives_a_500_page_that_leaks_nothing(make_client, three, monkeypatch, fetchers):
    def boom(cve_id):
        raise RuntimeError("secret-internal-detail")

    monkeypatch.setattr("threatintel.services.fetch_nvd", boom)
    signed_in = make_client("alice")
    c = Client(raise_request_exception=False)
    c.force_login(signed_in.user)
    response = c.get(f"/cve/{ID1}/")
    assert response.status_code == 500
    for leak in (b"secret-internal-detail", b"RuntimeError", b"Traceback"):
        assert leak not in response.content


def test_passwords_never_reach_the_logs(client, caplog):
    secret = "UNIQUE-pw-marker-91-x"
    with caplog.at_level(logging.DEBUG):
        client.post("/accounts/register/", {"username": "alice", "password1": secret, "password2": secret})
        client.post("/accounts/login/", {"username": "alice", "password": secret})
        client.post("/accounts/login/", {"username": "alice", "password": "wrong-" + secret})
    assert secret not in caplog.text


@pytest.mark.parametrize("path", PUBLIC)
def test_content_security_policy_allows_only_self_and_data_images(client, path):
    assert csp(client.get(path))["img-src"] == ["'self'", "data:"]

def test_dashboard_search_rejects_queries_over_200_characters(client, three):
    assert client.get("/", {"q": "a" * 201}).status_code == 400


def test_dashboard_search_accepts_queries_at_the_200_character_limit(client, three):
    assert client.get("/", {"q": "a" * 200}).status_code == 200
