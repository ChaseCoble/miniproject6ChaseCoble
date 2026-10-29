# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import re
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

import pytest

from threatintel.fetch import FetchError
from threatintel.models import Vulnerability, Watch

pytestmark = pytest.mark.django_db

ID1, ID2, ID3 = "CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0003"
PAYLOAD = "<script>alert(1)</script>"
ESCAPED = b"&lt;script&gt;alert(1)&lt;/script&gt;"
SECRET_NOTE = "alice-private-triage-note"
LOGIN = "/accounts/login/"


def watch(user, cve_id, note=""):
    return Watch.objects.create(user=user, vulnerability=Vulnerability.objects.get(cve_id=cve_id), note=note)


def watch_rows():
    return sorted(Watch.objects.values_list("user__username", "vulnerability__cve_id", "note"))


def vuln(cve_id=ID1):
    return Vulnerability.objects.get(cve_id=cve_id)


def cve_ids_in(content):
    return set(re.findall(rb"CVE-2099-\d{4}", content))


def form_tags(content):
    return re.findall(rb"<form[^>]*>", content)


def hrefs(content):
    return re.findall(rb'href="([^"]*)"', content)


@pytest.fixture
def three(seed, kev_entry):
    seed([kev_entry(cveID=i, vendorProject="Acme", product="Widget") for i in (ID1, ID2, ID3)])


# ---------- dashboard ----------

@pytest.mark.parametrize("path", ["/", "/about/", LOGIN, "/accounts/register/"])
def test_public_pages_load_for_anonymous_users(client, path):
    assert client.get(path).status_code == 200


def test_dashboard_lists_the_vulnerabilities(client, three):
    assert cve_ids_in(client.get("/").content) == {i.encode() for i in (ID1, ID2, ID3)}


def test_dashboard_search_matches_vendor_product_and_cve_id_ignoring_case(client, seed, kev_entry):
    seed([kev_entry(cveID=ID1, vendorProject="Acme", product="Widget"),
          kev_entry(cveID=ID2, vendorProject="Globex", product="Gadget")])

    def found(q):
        return cve_ids_in(client.get("/", {"q": q}).content)

    assert found("acme") == {ID1.encode()}
    assert found("GADGET") == {ID2.encode()}
    assert found("cve-2099-0002") == {ID2.encode()}
    assert found("zzz-no-match") == set()


@pytest.mark.parametrize("q", ["' OR 1=1 --", "'; DROP TABLE threatintel_vulnerability; --", '" OR ""="'])
def test_dashboard_search_survives_sql_metacharacters(client, three, q):
    response = client.get("/", {"q": q})
    assert response.status_code == 200
    assert cve_ids_in(response.content) == set()
    assert Vulnerability.objects.count() == 3


@pytest.mark.parametrize("q", ["%", "_"])
def test_dashboard_search_treats_like_wildcards_literally(client, three, q):
    assert cve_ids_in(client.get("/", {"q": q}).content) == set()


def test_dashboard_shows_at_most_100_rows_per_page(client, seed, kev_entry):
    seed([kev_entry(cveID=f"CVE-2099-{i:04d}") for i in range(1, 151)])
    assert len(cve_ids_in(client.get("/").content)) == 100


def test_dashboard_pages_are_disjoint_and_cover_everything(client, seed, kev_entry):
    seed([kev_entry(cveID=f"CVE-2099-{i:04d}", dateAdded="2099-01-01") for i in range(1, 151)])
    page1 = cve_ids_in(client.get("/", {"page": 1}).content)
    page2 = cve_ids_in(client.get("/", {"page": 2}).content)
    assert not (page1 & page2) and len(page1 | page2) == 150
    assert cve_ids_in(client.get("/").content) == page1


@pytest.mark.parametrize("page", ["abc", "0", "-1", "99999", "1.5", ""])
def test_dashboard_invalid_page_values_do_not_crash(client, three, page):
    assert client.get("/", {"page": page}).status_code == 200


@pytest.mark.parametrize("path", ["/", f"/cve/{ID1}/"])
def test_kev_text_is_html_escaped(client, seed, kev_entry, fetchers, path):
    seed([kev_entry(cveID=ID1, vulnerabilityName=PAYLOAD, shortDescription=PAYLOAD, product=PAYLOAD)])
    content = client.get(path).content
    assert PAYLOAD.encode() not in content and ESCAPED in content


# ---------- detail page and NVD enrichment ----------

def test_detail_first_view_fetches_nvd_once_shows_score_with_version_and_caches(alice, three, fetchers, clock):
    response = alice.get(f"/cve/{ID1}/")
    assert response.status_code == 200
    assert fetchers.nvd_calls == [ID1]
    assert re.search(rb"9\.3.{0,40}4\.0|4\.0.{0,40}9\.3", response.content, re.S)
    assert vuln().cvss_score == 9.3 and vuln().nvd_fetched_at == clock.now


def test_detail_second_view_does_not_fetch_again(alice, three, fetchers):
    alice.get(f"/cve/{ID1}/")
    alice.get(f"/cve/{ID1}/")
    assert fetchers.nvd_calls == [ID1]


@pytest.mark.parametrize("status, wait, refetch", [
    ("Undergoing Analysis", timedelta(hours=23), False),
    ("Undergoing Analysis", timedelta(hours=25), True),
    ("Analyzed", timedelta(days=29), False),
    ("Analyzed", timedelta(days=31), True),
])
def test_detail_refetches_only_when_the_cache_is_stale(alice, three, fetchers, clock, status, wait, refetch):
    base = fetchers.nvd_doc_for

    def with_status(cve_id):
        doc = base(cve_id)
        doc["vulnerabilities"][0]["cve"]["vulnStatus"] = status
        return doc

    fetchers.nvd_doc_for = with_status
    alice.get(f"/cve/{ID1}/")
    clock.advance(wait)
    alice.get(f"/cve/{ID1}/")
    assert len(fetchers.nvd_calls) == (2 if refetch else 1)


@pytest.mark.parametrize("bad", [
    "CVE-2021-1", "cve-2099-0001", "CVE-2099-0001%0A", "CVE-2099-0001&x=1", "CVE-2099-0001;x",
])
def test_detail_malformed_id_is_404_and_never_reaches_the_fetcher(alice, three, fetchers, bad):
    assert alice.get(f"/cve/{bad}/").status_code == 404
    assert fetchers.nvd_calls == []


def test_detail_valid_but_unknown_cve_is_404_and_never_reaches_the_fetcher(alice, three, fetchers):
    assert alice.get("/cve/CVE-2099-9999/").status_code == 404
    assert fetchers.nvd_calls == []


def test_detail_nvd_failure_still_shows_kev_data_and_caches_nothing(alice, seed, kev_entry, fetchers):
    seed([kev_entry(cveID=ID1, vendorProject="Acme")])
    fetchers.nvd_error = FetchError("simulated outage")
    response = alice.get(f"/cve/{ID1}/")
    assert response.status_code == 200
    assert b"Acme" in response.content and b"unavailable" in response.content.lower()
    assert vuln().nvd_fetched_at is None and vuln().cvss_score is None


@pytest.mark.parametrize("make_doc", [
    lambda cve_id: {"vulnerabilities": "nope"},
    lambda cve_id: {},
    lambda cve_id: {"vulnerabilities": []},
], ids=["malformed", "not-nvd", "unknown-to-nvd"])
def test_detail_unusable_nvd_response_is_treated_as_unavailable(alice, three, fetchers, make_doc):
    fetchers.nvd_doc_for = make_doc
    response = alice.get(f"/cve/{ID1}/")
    assert response.status_code == 200 and b"unavailable" in response.content.lower()
    assert vuln().nvd_fetched_at is None


def test_detail_recovers_after_a_failed_fetch(alice, three, fetchers):
    fetchers.nvd_error = FetchError("down")
    alice.get(f"/cve/{ID1}/")
    fetchers.nvd_error = None
    alice.get(f"/cve/{ID1}/")
    assert fetchers.nvd_calls == [ID1, ID1] and vuln().nvd_fetched_at is not None


def test_detail_escapes_text_that_came_from_nvd(alice, three, fetchers):
    base = fetchers.nvd_doc_for

    def hostile(cve_id):
        doc = base(cve_id)
        doc["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV40"][0]["cvssData"]["vectorString"] = \
            "<img src=x onerror=alert(1)>"
        return doc

    fetchers.nvd_doc_for = hostile
    content = alice.get(f"/cve/{ID1}/").content
    assert b"<img src=x" not in content
    assert b"&lt;img src=x onerror=alert(1)&gt;" in content


@pytest.mark.parametrize("bad_url", ["javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "vbscript:x"])
def test_detail_never_renders_a_non_http_url_as_a_link(client, three, fetchers, bad_url):
    Vulnerability.objects.filter(cve_id=ID1).update(kev_urls=bad_url + "\nhttps://ok.example/a")
    found = hrefs(client.get(f"/cve/{ID1}/").content)
    assert b"https://ok.example/a" in found
    assert all(h.startswith((b"/", b"#", b"http://", b"https://")) for h in found)


def test_detail_links_to_nvd_using_the_validated_id(client, three, fetchers):
    assert b'href="https://nvd.nist.gov/vuln/detail/' + ID1.encode() + b'"' in client.get(f"/cve/{ID1}/").content


def test_detail_shows_kev_reference_urls_as_links(client, seed, kev_entry, fetchers):
    seed([kev_entry(cveID=ID1, notes="https://a.example/1 ; https://a.example/2")])
    found = hrefs(client.get(f"/cve/{ID1}/").content)
    assert b"https://a.example/1" in found and b"https://a.example/2" in found


def test_anonymous_detail_shows_kev_data_and_never_fetches(client, three, fetchers):
    response = client.get(f"/cve/{ID1}/")
    assert response.status_code == 200 and b"Acme" in response.content
    assert fetchers.nvd_calls == []


def test_anonymous_detail_shows_what_a_signed_in_user_already_cached(client, alice, three, fetchers):
    alice.get(f"/cve/{ID1}/")
    assert b"9.3" in client.get(f"/cve/{ID1}/").content
    assert len(fetchers.nvd_calls) == 1


def test_anonymous_detail_never_refetches_a_stale_cache(client, alice, three, fetchers, clock):
    alice.get(f"/cve/{ID1}/")
    clock.advance(timedelta(days=40))
    client.get(f"/cve/{ID1}/")
    assert len(fetchers.nvd_calls) == 1


def test_nvd_lookups_are_limited_to_five_per_thirty_seconds_app_wide(alice, bob, seed, kev_entry, fetchers, clock):
    ids = [f"CVE-2099-{i:04d}" for i in range(1, 8)]
    seed([kev_entry(cveID=i) for i in ids])
    for cve in ids[:5]:
        alice.get(f"/cve/{cve}/")
    assert len(fetchers.nvd_calls) == 5
    response = bob.get(f"/cve/{ids[5]}/")
    assert response.status_code == 200 and b"unavailable" in response.content.lower()
    assert len(fetchers.nvd_calls) == 5 and vuln(ids[5]).nvd_fetched_at is None
    clock.advance(timedelta(seconds=31))
    bob.get(f"/cve/{ids[5]}/")
    assert len(fetchers.nvd_calls) == 6


# ---------- login gate ----------

@pytest.mark.parametrize("path", ["/watchlist/", f"/watch/{ID1}/edit/"])
def test_gated_pages_redirect_anonymous_users_to_login_with_next(client, three, path):
    response = client.get(path)
    location = urlparse(response["Location"])
    assert response.status_code == 302 and location.path == LOGIN
    assert parse_qs(location.query)["next"] == [path]


@pytest.mark.parametrize("path", [f"/watch/{ID1}/add/", f"/watch/{ID1}/edit/", f"/watch/{ID1}/delete/", "/refresh/"])
def test_gated_posts_redirect_anonymous_users_and_change_nothing(client, three, fetchers, path):
    response = client.post(path, {"note": "x"})
    assert response.status_code == 302 and urlparse(response["Location"]).path == LOGIN
    assert watch_rows() == [] and fetchers.kev_calls == 0


@pytest.mark.parametrize("path", [f"/watch/{ID1}/add/", f"/watch/{ID1}/delete/", "/refresh/"])
def test_mutating_routes_reject_get(alice, three, path):
    assert alice.get(path).status_code == 405


# ---------- watchlist ----------

def test_watch_add_creates_a_row_for_the_logged_in_user_only(alice, bob, three):
    assert alice.post(f"/watch/{ID1}/add/").status_code == 302
    assert watch_rows() == [("alice", ID1, "")]


def test_watch_add_ignores_a_user_id_in_the_form(alice, bob, three):
    alice.post(f"/watch/{ID1}/add/", {"user": bob.user.pk, "username": "bob"})
    assert [r[0] for r in watch_rows()] == ["alice"]


def test_watch_add_duplicate_makes_no_second_row_and_says_so(alice, three):
    alice.post(f"/watch/{ID1}/add/")
    response = alice.post(f"/watch/{ID1}/add/", follow=True)
    assert response.status_code == 200 and b"already" in response.content.lower()
    assert len(watch_rows()) == 1


@pytest.mark.parametrize("cve", ["CVE-2099-9999", "CVE-2021-1", "cve-2099-0001"])
def test_watch_add_unknown_or_malformed_id_is_404(alice, three, cve):
    assert alice.post(f"/watch/{cve}/add/").status_code == 404
    assert watch_rows() == []


def test_watchlist_shows_only_the_current_users_watches(alice, bob, three):
    watch(alice.user, ID1)
    watch(bob.user, ID2)
    assert cve_ids_in(alice.get("/watchlist/").content) == {ID1.encode()}


def test_watchlist_loads_for_a_user_with_no_watches(alice):
    assert alice.get("/watchlist/").status_code == 200


def test_watchlist_escapes_notes(alice, three):
    watch(alice.user, ID1, note="<i>note-payload</i>")
    content = alice.get("/watchlist/").content
    assert b"<i>note-payload</i>" not in content and b"&lt;i&gt;note-payload&lt;/i&gt;" in content


def test_watchlist_delete_button_opens_a_modal_holding_a_post_form(alice, three):
    watch(alice.user, ID1)
    content = alice.get("/watchlist/").content
    assert b'data-bs-toggle="modal"' in content and b'class="modal' in content
    target = f"/watch/{ID1}/delete/".encode()
    assert any(target in f and b"post" in f.lower() for f in form_tags(content))


def test_base_template_loads_bootstrap_css_and_js(client):
    content = client.get("/").content
    assert re.search(rb"<link[^>]+bootstrap[^>]*\.css", content, re.I)
    assert re.search(rb"<script[^>]+bootstrap[^>]*\.js", content, re.I)


def test_nav_offers_logout_as_a_post_form_when_logged_in(alice):
    assert any(b"/accounts/logout/" in f and b"post" in f.lower() for f in form_tags(alice.get("/").content))


def test_nav_offers_login_and_register_when_anonymous(client):
    content = client.get("/").content
    assert b'href="/accounts/login/"' in content and b'href="/accounts/register/"' in content


# ---------- edit note ----------

def test_edit_note_get_shows_the_current_note_escaped(alice, three):
    watch(alice.user, ID1, note="<i>note-payload</i>")
    content = alice.get(f"/watch/{ID1}/edit/").content
    assert b"<i>note-payload</i>" not in content and b"&lt;i&gt;note-payload&lt;/i&gt;" in content


def test_edit_note_post_updates_the_note_and_redirects_locally(alice, three):
    watch(alice.user, ID1)
    response = alice.post(f"/watch/{ID1}/edit/", {"note": "triage first"})
    location = urlparse(response["Location"])
    assert response.status_code == 302 and location.scheme == "" and location.netloc == ""
    assert watch_rows() == [("alice", ID1, "triage first")]


@pytest.mark.parametrize("length, accepted", [(500, True), (501, False)])
def test_edit_note_length_limit(alice, three, length, accepted):
    watch(alice.user, ID1, note="old")
    response = alice.post(f"/watch/{ID1}/edit/", {"note": "n" * length})
    assert (response.status_code == 302) is accepted
    assert watch_rows()[0][2] == ("n" * length if accepted else "old")


def test_edit_note_can_be_cleared(alice, three):
    watch(alice.user, ID1, note="old")
    alice.post(f"/watch/{ID1}/edit/", {"note": ""})
    assert watch_rows()[0][2] == ""


@pytest.mark.parametrize("method", ["get", "post"])
def test_edit_note_for_a_cve_you_do_not_watch_is_404(alice, three, method):
    assert getattr(alice, method)(f"/watch/{ID1}/edit/").status_code == 404


# ---------- other users' watches ----------

@pytest.fixture
def alice_watch(alice, bob, three):
    watch(alice.user, ID1, note=SECRET_NOTE)


def test_other_users_cannot_read_a_watch_note(bob, alice_watch):
    response = bob.get(f"/watch/{ID1}/edit/")
    assert response.status_code == 404 and SECRET_NOTE.encode() not in response.content


def test_other_users_cannot_change_a_watch_note(bob, alice_watch):
    assert bob.post(f"/watch/{ID1}/edit/", {"note": "hijacked"}).status_code == 404
    assert watch_rows()[0][2] == SECRET_NOTE


def test_other_users_cannot_delete_a_watch(bob, alice_watch):
    assert bob.post(f"/watch/{ID1}/delete/").status_code == 404
    assert len(watch_rows()) == 1


def test_each_user_has_an_independent_note_for_the_same_cve(alice, bob, three):
    watch(alice.user, ID1, note="alice's note")
    watch(bob.user, ID1, note="bob's note")
    bob.post(f"/watch/{ID1}/edit/", {"note": "bob edited"})
    assert watch_rows() == [("alice", ID1, "alice's note"), ("bob", ID1, "bob edited")]


def test_delete_removes_only_my_watch_and_keeps_the_vulnerabilities(alice, bob, three):
    watch(alice.user, ID1)
    watch(bob.user, ID1)
    watch(alice.user, ID2)
    assert alice.post(f"/watch/{ID1}/delete/").status_code == 302
    assert [(r[0], r[1]) for r in watch_rows()] == [("alice", ID2), ("bob", ID1)]
    assert Vulnerability.objects.count() == 3


def test_delete_of_a_watch_you_do_not_have_is_404(alice, three):
    assert alice.post(f"/watch/{ID1}/delete/").status_code == 404


# ---------- refresh ----------

def test_refresh_loads_the_feed_into_the_database(alice, fetchers):
    assert alice.post("/refresh/").status_code == 302
    assert fetchers.kev_calls == 1
    assert list(Vulnerability.objects.order_by("cve_id").values_list("cve_id", flat=True)) == [ID1, ID2, ID3]


def test_refresh_is_limited_to_once_an_hour_across_all_users(alice, bob, fetchers, clock):
    alice.post("/refresh/")
    clock.advance(timedelta(minutes=59))
    bob.post("/refresh/")
    assert fetchers.kev_calls == 1
    clock.advance(timedelta(minutes=2))
    alice.post("/refresh/")
    assert fetchers.kev_calls == 2


def test_refresh_fetch_failure_changes_nothing_and_does_not_start_the_window(alice, fetchers):
    fetchers.kev_error = FetchError("down")
    assert alice.post("/refresh/").status_code == 302
    assert Vulnerability.objects.count() == 0
    fetchers.kev_error = None
    alice.post("/refresh/")
    assert fetchers.kev_calls == 2 and Vulnerability.objects.count() == 3


@pytest.mark.parametrize("feed", [{}, {"count": 1}, {"vulnerabilities": "nope"}],
                         ids=["empty", "no-list", "wrong-type"])
def test_refresh_with_a_feed_that_is_not_kev_changes_nothing(alice, fetchers, feed):
    fetchers.kev_feed = feed
    assert alice.post("/refresh/").status_code == 302
    assert Vulnerability.objects.count() == 0


def test_refresh_skips_bad_entries_but_loads_the_rest(alice, fetchers, kev_entry):
    fetchers.kev_feed = {"vulnerabilities": [kev_entry(cveID="not-a-cve"), kev_entry(cveID=ID1)]}
    alice.post("/refresh/")
    assert list(Vulnerability.objects.values_list("cve_id", flat=True)) == [ID1]


def test_refresh_keeps_enrichment_and_watches(alice, fetchers, clock):
    alice.post("/refresh/")
    alice.get(f"/cve/{ID1}/")
    alice.post(f"/watch/{ID1}/add/")
    clock.advance(timedelta(hours=2))
    alice.post("/refresh/")
    assert fetchers.kev_calls == 2 and vuln().cvss_score == 9.3 and len(watch_rows()) == 1


@pytest.mark.parametrize("q", ['"><script>alert(1)</script>', "'><img src=x onerror=alert(1)>"])
def test_dashboard_escapes_the_search_query_it_echoes(client, three, q):
    content = client.get("/", {"q": q}).content
    assert b"<script>alert(1)</script>" not in content
    assert b"<img src=x" not in content


def test_dashboard_pagination_links_do_not_break_out_on_a_hostile_query(client, seed, kev_entry):
    marker = 'ZQ"><i id=zq>'
    seed([kev_entry(cveID=f"CVE-2099-{i:04d}", vendorProject=marker) for i in range(1, 151)])
    content = client.get("/", {"q": marker}).content
    assert b"<i id=zq>" not in content
    assert b"page=2" in content
