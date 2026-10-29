# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import timedelta
from html.parser import HTMLParser
from urllib.parse import quote, urlparse

import pytest
from django.contrib.auth import get_user_model

PW = "test-pass-123"
REGISTER, LOGIN, LOGOUT = "/accounts/register/", "/accounts/login/", "/accounts/logout/"

pytestmark = pytest.mark.django_db


def register(client, username="alice", password=PW, confirm=None):
    return client.post(REGISTER, {"username": username, "password1": password,
                                  "password2": password if confirm is None else confirm})


def login(client, username="alice", password=PW):
    return client.post(LOGIN, {"username": username, "password": password})


def usernames():
    return sorted(get_user_model().objects.values_list("username", flat=True))


def logged_in(client):
    return "_auth_user_id" in client.session


# ---------- register ----------

def test_register_page_loads(client):
    assert client.get(REGISTER).status_code == 200


def test_register_creates_the_user_and_redirects_to_login(client):
    response = register(client)
    assert response.status_code == 302
    assert urlparse(response["Location"]).path == LOGIN
    assert usernames() == ["alice"]


def test_register_does_not_log_the_user_in(client):
    register(client)
    assert not logged_in(client)


def test_register_stores_a_hash_not_the_password(client):
    register(client)
    user = get_user_model().objects.get(username="alice")
    assert user.password != PW and PW not in user.password
    assert user.check_password(PW) and not user.check_password(PW + "x")


def test_register_hashes_are_salted(client):
    register(client, "alice")
    register(client, "bob")
    first, second = (u.password for u in get_user_model().objects.order_by("username"))
    assert first != second


def test_register_duplicate_username_adds_no_row_and_keeps_the_original(client):
    register(client)
    response = register(client, "alice", "other-pass-456")
    assert response.status_code == 200
    assert usernames() == ["alice"]
    assert get_user_model().objects.get().check_password(PW)


def test_register_usernames_are_unique_ignoring_case(client):
    register(client, "alice")
    register(client, "Alice")
    assert usernames() == ["alice"]


@pytest.mark.parametrize("password", ["short", "12345678", "password"])
def test_register_rejects_weak_passwords(client, password):
    assert register(client, "alice", password).status_code == 200
    assert usernames() == []


def test_register_rejects_mismatched_confirmation(client):
    assert register(client, confirm="different-pass-456").status_code == 200
    assert usernames() == []


@pytest.mark.parametrize("data", [
    {}, {"username": "alice"}, {"password1": PW, "password2": PW},
    {"username": "", "password1": PW, "password2": PW},
    {"username": "alice", "password1": "", "password2": ""},
], ids=["nothing", "no-passwords", "no-username", "empty-username", "empty-passwords"])
def test_register_rejects_missing_or_empty_fields(client, data):
    assert client.post(REGISTER, data).status_code == 200
    assert usernames() == []


@pytest.mark.parametrize("length, accepted", [(150, True), (151, False)])
def test_register_username_length_limit(client, length, accepted):
    response = register(client, "u" * length)
    assert (response.status_code == 302) is accepted
    assert len(usernames()) == (1 if accepted else 0)


@pytest.mark.parametrize("name", ["bad name", "<script>alert(1)</script>", "a/b"])
def test_register_rejects_usernames_with_unsafe_characters(client, name):
    assert register(client, name).status_code == 200
    assert usernames() == []


# ---------- login / logout ----------

def test_login_page_loads(client):
    assert client.get(LOGIN).status_code == 200


def test_login_success_redirects_home_and_logs_in(client):
    register(client)
    response = login(client)
    assert response.status_code == 302
    assert urlparse(response["Location"]).path == "/"
    assert logged_in(client)


def test_wrong_password_and_unknown_user_give_the_same_error(client):
    register(client)
    for response in (login(client, "alice", "wrong-pass-999"), login(client, "ghost", PW)):
        assert response.status_code == 200
        assert b"correct username and password" in response.content


@pytest.mark.parametrize("creds", [("alice", "wrong-pass-999"), ("ghost", PW), ("", ""), ("alice", "")])
def test_failed_login_does_not_log_in(client, creds):
    register(client)
    login(client, *creds)
    assert not logged_in(client)


def test_login_changes_the_session_key(client):
    register(client)
    before = client.session.session_key
    login(client)
    assert client.session.session_key != before


@pytest.mark.parametrize("target", [
    "https://evil.example/", "//evil.example/", "/\\evil.example",
    "javascript:alert(1)", "http:evil.example",
])
def test_login_never_redirects_off_site(client, target):
    register(client)
    response = client.post(f"{LOGIN}?next={quote(target, safe='')}",
                           {"username": "alice", "password": PW})
    location = urlparse(response["Location"])
    assert response.status_code == 302
    assert location.scheme == "" and location.netloc == ""


def test_login_honours_a_safe_next_path(client):
    register(client)
    response = client.post(f"{LOGIN}?next=/watchlist/", {"username": "alice", "password": PW})
    assert urlparse(response["Location"]).path == "/watchlist/"


def test_logout_clears_the_session_and_redirects(client):
    register(client)
    login(client)
    response = client.post(LOGOUT)
    assert response.status_code == 302
    assert not logged_in(client)


def test_logout_rejects_get_and_keeps_the_session(client):
    register(client)
    login(client)
    assert client.get(LOGOUT).status_code == 405
    assert logged_in(client)


def test_logout_when_anonymous_is_harmless(client):
    assert client.post(LOGOUT).status_code == 302


def test_a_session_for_a_deleted_user_is_anonymous(client):
    register(client)
    login(client)
    get_user_model().objects.all().delete()
    response = client.get("/watchlist/")
    assert response.status_code == 302
    assert urlparse(response["Location"]).path == LOGIN


def test_session_cookie_is_httponly_and_samesite_lax(client):
    register(client)
    cookie = login(client).cookies["sessionid"]
    assert cookie["httponly"] and cookie["samesite"] == "Lax"


# ---------- the forms as rendered ----------

class _FormScanner(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self._current = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._current = {"method": (a.get("method") or "get").lower(),
                             "action": a.get("action"), "inputs": []}
            self.forms.append(self._current)
        elif tag in ("input", "textarea") and self._current is not None:
            self._current["inputs"].append((a.get("name"), (a.get("type") or "text").lower()))

    def handle_endtag(self, tag):
        if tag == "form":
            self._current = None


def _password_form(client, path):
    scanner = _FormScanner()
    scanner.feed(client.get(path).content.decode())
    forms = [f for f in scanner.forms if any(t == "password" for _, t in f["inputs"])]
    assert len(forms) == 1, f"expected exactly one form with a password field on {path}"
    return forms[0]


def _fill(form, username, password):
    data = {}
    for name, type_ in form["inputs"]:
        if name and type_ == "text":
            data[name] = username
        elif name and type_ == "password":
            data[name] = password
    return data


@pytest.mark.parametrize("path", [REGISTER, LOGIN])
def test_rendered_auth_forms_post_back_to_their_own_page(client, path):
    form = _password_form(client, path)
    assert form["method"] == "post"
    assert form["action"] in (None, "", path)


def test_register_and_login_work_with_the_fields_the_rendered_forms_use(client):
    assert client.post(REGISTER, _fill(_password_form(client, REGISTER), "alice", PW)).status_code == 302
    response = client.post(LOGIN, _fill(_password_form(client, LOGIN), "alice", PW))
    assert response.status_code == 302 and logged_in(client)


# ---------- throttling ----------

def fail_logins(client, n, username="alice"):
    for _ in range(n):
        login(client, username, "wrong-pass-999")


def test_login_is_throttled_after_five_failures_even_with_the_right_password(client, clock):
    register(client)
    fail_logins(client, 5)
    response = login(client)
    assert response.status_code == 429
    assert b"too many" in response.content.lower()
    assert not logged_in(client)


def test_login_throttle_is_per_username(client, clock):
    register(client, "alice")
    register(client, "bob")
    fail_logins(client, 5, "alice")
    assert login(client, "bob").status_code == 302


def test_login_throttle_counts_unknown_usernames_too(client, clock):
    fail_logins(client, 5, "ghost")
    assert login(client, "ghost", PW).status_code == 429


def test_login_throttle_ignores_case_and_whitespace_in_the_username(client, clock):
    register(client)
    for name in ("alice", "ALICE", " alice ", "Alice", "aLiCe"):
        login(client, name, "wrong-pass-999")
    assert login(client).status_code == 429


def test_login_throttle_window_expires_and_blocked_attempts_do_not_extend_it(client, clock):
    register(client)
    fail_logins(client, 5)
    clock.advance(timedelta(minutes=14))
    assert login(client).status_code == 429
    clock.advance(timedelta(minutes=2))
    assert login(client).status_code == 302


def test_register_is_throttled_to_five_posts_per_hour_per_address(client, clock):
    for i in range(5):
        assert register(client, f"user{i}").status_code == 302
    assert register(client, "user5").status_code == 429
    assert "user5" not in usernames()


def test_register_throttle_ignores_x_forwarded_for(client, clock):
    for i in range(5):
        client.post(REGISTER, {"username": f"user{i}", "password1": PW, "password2": PW},
                    HTTP_X_FORWARDED_FOR=f"10.0.0.{i}")
    response = client.post(REGISTER, {"username": "user5", "password1": PW, "password2": PW},
                           HTTP_X_FORWARDED_FOR="10.9.9.9")
    assert response.status_code == 429


def test_register_throttle_window_expires(client, clock):
    for i in range(5):
        register(client, f"user{i}")
    clock.advance(timedelta(minutes=61))
    assert register(client, "late").status_code == 302

def test_login_throttle_blocks_spraying_across_five_distinct_usernames(client, clock):
    for name in ("alice", "bob", "carol", "dave", "eve"):
        register(client, name)
    for name in ("alice", "bob", "carol", "dave", "eve"):
        login(client, name, "wrong-pass-999")
    response = login(client, "frank")
    assert response.status_code == 429


def test_spray_throttle_does_not_block_a_single_repeatedly_tried_username(client, clock):
    register(client, "alice")
    register(client, "bob")
    for _ in range(5):
        login(client, "alice", "wrong-pass-999")
    assert login(client, "bob", "test-pass-123").status_code == 302
