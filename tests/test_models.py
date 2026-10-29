# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import logging
from datetime import date, datetime, timedelta, timezone

import pytest
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction

from threatintel.models import Vulnerability, Watch
from threatintel.services import save_nvd, upsert_kev
from threatintel.sources import parse_kev

pytestmark = pytest.mark.django_db

NOW = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)
NO_CVSS = dict.fromkeys([
    "cvss_score", "cvss_version", "cvss_severity",
    "cvss_vector", "cvss_source", "cvss_type",
])
NVD_FIELDS = (
    "nvd_status", "nvd_published", "nvd_last_modified", "cvss_score", "cvss_version",
    "cvss_severity", "cvss_vector", "cvss_source", "cvss_type", "nvd_fetched_at",
)


# ---------- helpers ----------

def make_user(name="alice"):
    return get_user_model().objects.create_user(username=name, password="test-pass-123")


def vuln_fields(**overrides):
    fields = dict(
        cve_id="CVE-2099-0001", vendor="Acme", product="Widget",
        name="Acme Widget Test Vulnerability", short_description="Fake entry.",
        date_added=date(2099, 1, 1), due_date=date(2099, 1, 22),
    )
    fields.update(overrides)
    return fields


def make_vuln(**overrides):
    return Vulnerability.objects.create(**vuln_fields(**overrides))


def make_watch(user, vuln, note=""):
    return Watch.objects.create(user=user, vulnerability=vuln, note=note)


def rows_for(kev_entry, n=1, **overrides):
    entries = [kev_entry(cveID=f"CVE-2099-{i:04d}", **overrides) for i in range(1, n + 1)]
    return parse_kev({"vulnerabilities": entries})


def nvd_result(**overrides):
    base = {
        "cve_id": "CVE-2099-0001", "nvd_status": "Analyzed",
        "nvd_published": "2099-01-01T00:00:00.000",
        "nvd_last_modified": "2099-01-02T00:00:00.000",
        "cvss_score": 9.3, "cvss_version": "4.0", "cvss_severity": "CRITICAL",
        "cvss_vector": "CVSS:4.0/AV:N", "cvss_source": "nvd@nist.gov", "cvss_type": "Primary",
    }
    base.update(overrides)
    return base


# ---------- Vulnerability ----------

def test_vulnerability_cve_id_is_unique():
    make_vuln()
    with pytest.raises(IntegrityError), transaction.atomic():
        make_vuln()
    assert Vulnerability.objects.count() == 1


def test_vulnerability_str_contains_the_cve_id():
    assert "CVE-2099-0001" in str(make_vuln())


def test_vulnerability_defaults():
    vuln = make_vuln()
    vuln.refresh_from_db()
    assert vuln.ransomware_use is False
    assert vuln.cwes == "" and vuln.kev_urls == ""
    for field in NVD_FIELDS:
        assert getattr(vuln, field) is None, field


@pytest.mark.parametrize("cve_id", ["CVE-2021-44228", "CVE-2026-105134"])
def test_full_clean_accepts_a_wellformed_cve_id(cve_id):
    Vulnerability(**vuln_fields(cve_id=cve_id)).full_clean()


@pytest.mark.parametrize("bad", ["CVE-2021-1", "cve-2099-0001", "CVE-2099-0001\n", "../x", ""])
def test_full_clean_rejects_a_malformed_cve_id(bad):
    with pytest.raises(ValidationError) as excinfo:
        Vulnerability(**vuln_fields(cve_id=bad)).full_clean()
    assert "cve_id" in excinfo.value.message_dict


def test_reference_urls_returns_http_and_https_links_in_order():
    vuln = Vulnerability(kev_urls="https://a.example/1\nhttp://a.example/2")
    assert vuln.reference_urls == ["https://a.example/1", "http://a.example/2"]


@pytest.mark.parametrize("planted", [
    "javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "vbscript:x",
])
def test_reference_urls_drops_non_http_schemes_planted_in_the_database(planted):
    vuln = Vulnerability(kev_urls=planted + "\nhttps://ok.example/a")
    assert vuln.reference_urls == ["https://ok.example/a"]


@pytest.mark.parametrize("raw", ["", "\n\n"])
def test_reference_urls_empty(raw):
    assert Vulnerability(kev_urls=raw).reference_urls == []


# ---------- Watch ----------

def test_watch_links_a_user_to_a_vulnerability():
    assert Watch._meta.get_field("user").related_model is get_user_model()
    assert Watch._meta.get_field("vulnerability").related_model is Vulnerability


def test_watch_pair_is_unique():
    user, vuln = make_user(), make_vuln()
    make_watch(user, vuln)
    with pytest.raises(IntegrityError), transaction.atomic():
        make_watch(user, vuln)
    assert Watch.objects.count() == 1


def test_different_users_can_watch_the_same_vulnerability():
    # positive control: uniqueness is on the pair, not on the vulnerability alone
    vuln = make_vuln()
    make_watch(make_user("alice"), vuln)
    make_watch(make_user("bob"), vuln)
    assert Watch.objects.count() == 2


def test_one_user_can_watch_different_vulnerabilities():
    user = make_user()
    make_watch(user, make_vuln(cve_id="CVE-2099-0001"))
    make_watch(user, make_vuln(cve_id="CVE-2099-0002"))
    assert Watch.objects.count() == 2


def test_watch_note_defaults_to_empty_and_created_is_timezone_aware():
    watch = make_watch(make_user(), make_vuln())
    watch.refresh_from_db()
    assert watch.note == ""
    assert watch.created is not None and watch.created.tzinfo is not None


@pytest.mark.parametrize("length, accepted", [(500, True), (501, False)])
def test_watch_note_length_limit(length, accepted):
    watch = Watch(user=make_user(), vulnerability=make_vuln(), note="n" * length)
    if accepted:
        watch.full_clean()
    else:
        with pytest.raises(ValidationError) as excinfo:
            watch.full_clean()
        assert "note" in excinfo.value.message_dict


def test_deleting_a_user_deletes_their_watches_only():
    alice, bob, vuln = make_user("alice"), make_user("bob"), make_vuln()
    make_watch(alice, vuln)
    make_watch(bob, vuln)
    alice.delete()
    assert [w.user.username for w in Watch.objects.all()] == ["bob"]
    assert Vulnerability.objects.count() == 1


def test_deleting_a_vulnerability_deletes_its_watches():
    user, vuln = make_user(), make_vuln()
    make_watch(user, vuln)
    vuln.delete()
    assert Watch.objects.count() == 0
    assert get_user_model().objects.count() == 1


def test_deleting_a_watch_leaves_the_user_and_the_vulnerability():
    watch = make_watch(make_user(), make_vuln())
    watch.delete()
    assert get_user_model().objects.count() == 1
    assert Vulnerability.objects.count() == 1


# ---------- upsert_kev ----------

def test_upsert_kev_inserts_rows_with_expected_values(kev_entry):
    upsert_kev(rows_for(kev_entry, cwes=["CWE-77", "CWE-78"],
                        knownRansomwareCampaignUse="Known",
                        notes="https://a.example/1 ; https://a.example/2"))
    row = Vulnerability.objects.get(cve_id="CVE-2099-0001")
    assert row.vendor == "Acme"
    assert row.date_added == date(2099, 1, 1)
    assert row.due_date == date(2099, 1, 22)
    assert row.cwes == "CWE-77,CWE-78"
    assert row.ransomware_use is True
    assert row.kev_urls == "https://a.example/1\nhttps://a.example/2"
    assert row.cvss_score is None and row.nvd_fetched_at is None


def test_upsert_kev_is_idempotent(kev_entry):
    rows = rows_for(kev_entry, n=3)
    upsert_kev(rows)
    upsert_kev(rows)
    assert Vulnerability.objects.count() == 3


def test_upsert_kev_updates_changed_fields(kev_entry):
    upsert_kev(rows_for(kev_entry))
    upsert_kev(rows_for(kev_entry, dueDate="2099-02-01"))
    assert [v.due_date for v in Vulnerability.objects.all()] == [date(2099, 2, 1)]


def test_upsert_kev_keeps_the_row_id_and_existing_watches(kev_entry):
    upsert_kev(rows_for(kev_entry))
    vuln = Vulnerability.objects.get()
    make_watch(make_user(), vuln)
    upsert_kev(rows_for(kev_entry, dueDate="2099-02-01"))
    assert Vulnerability.objects.get().pk == vuln.pk
    assert Watch.objects.count() == 1


def test_upsert_kev_preserves_nvd_enrichment(kev_entry):
    upsert_kev(rows_for(kev_entry))
    save_nvd(nvd_result(), NOW)
    upsert_kev(rows_for(kev_entry, dueDate="2099-02-01"))
    row = Vulnerability.objects.get()
    assert row.cvss_score == 9.3
    assert row.nvd_status == "Analyzed"
    assert row.nvd_fetched_at == NOW
    assert row.due_date == date(2099, 2, 1)  # the refresh itself still happened


@pytest.mark.parametrize("bad_date", [
    "not-a-date", "2099-13-45", "", "2099-01-01\nERROR forged line",
])
def test_upsert_kev_skips_a_row_with_an_unparseable_date_and_logs_it(kev_entry, caplog, bad_date):
    rows = rows_for(kev_entry, n=2)
    rows[0]["date_added"] = bad_date
    with caplog.at_level(logging.WARNING):
        upsert_kev(rows)
    assert list(Vulnerability.objects.values_list("cve_id", flat=True)) == ["CVE-2099-0002"]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "CVE-2099-0001" in warnings[0].getMessage()
    assert "\n" not in warnings[0].getMessage()


def test_upsert_kev_failure_midway_leaves_no_partial_rows(kev_entry):
    good, broken = rows_for(kev_entry, n=2)
    broken["vendor"] = None  # NOT NULL violation at the database, which parse_kev would never produce
    with pytest.raises(Exception):  # loose on purpose: the assertion that matters is below
        upsert_kev([good, broken])
    assert Vulnerability.objects.count() == 0


# ---------- save_nvd ----------

def test_save_nvd_stores_the_fields_and_marks_fetched(kev_entry):
    upsert_kev(rows_for(kev_entry))
    save_nvd(nvd_result(), NOW)
    row = Vulnerability.objects.get()
    assert (row.cvss_score, row.cvss_version, row.cvss_severity) == (9.3, "4.0", "CRITICAL")
    assert row.cvss_vector == "CVSS:4.0/AV:N"
    assert (row.cvss_source, row.cvss_type) == ("nvd@nist.gov", "Primary")
    assert row.nvd_status == "Analyzed"
    assert row.nvd_published == "2099-01-01T00:00:00.000"
    assert row.nvd_last_modified == "2099-01-02T00:00:00.000"
    assert row.nvd_fetched_at == NOW


def test_save_nvd_overwrites_previous_enrichment(kev_entry):
    upsert_kev(rows_for(kev_entry))
    save_nvd(nvd_result(cvss_score=9.3), NOW)
    later = NOW + timedelta(days=1)
    save_nvd(nvd_result(cvss_score=7.5, nvd_status="Modified"), later)
    row = Vulnerability.objects.get()
    assert row.cvss_score == 7.5 and row.nvd_status == "Modified"
    assert row.nvd_fetched_at == later


def test_save_nvd_with_no_cvss_stores_nulls_and_still_marks_fetched(kev_entry):
    upsert_kev(rows_for(kev_entry))
    save_nvd(nvd_result(**NO_CVSS, nvd_status="Undergoing Analysis"), NOW)
    row = Vulnerability.objects.get()
    assert row.cvss_score is None and row.cvss_version is None
    assert row.nvd_status == "Undergoing Analysis"
    assert row.nvd_fetched_at == NOW


def test_save_nvd_touches_only_the_named_cve(kev_entry):
    upsert_kev(rows_for(kev_entry, n=2))
    save_nvd(nvd_result(cve_id="CVE-2099-0001"), NOW)
    other = Vulnerability.objects.get(cve_id="CVE-2099-0002")
    assert other.cvss_score is None and other.nvd_fetched_at is None


def test_save_nvd_for_an_unknown_cve_creates_no_row():
    save_nvd(nvd_result(cve_id="CVE-2099-0404"), NOW)
    assert Vulnerability.objects.count() == 0


def test_save_nvd_rejects_a_timezone_naive_clock_value(kev_entry):
    upsert_kev(rows_for(kev_entry))
    with pytest.raises(ValueError):
        save_nvd(nvd_result(), datetime(2099, 6, 1, 12, 0))
    assert Vulnerability.objects.get().nvd_fetched_at is None
