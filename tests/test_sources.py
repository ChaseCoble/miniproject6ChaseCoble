# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import pytest
import logging

from threatintel.sources import parse_kev, parse_notes_urls, validate_cve_id

REQUIRED_KEYS = [
    "cveID", "vendorProject", "product", "vulnerabilityName",
    "shortDescription", "dateAdded", "dueDate",
    "knownRansomwareCampaignUse", "cwes", "notes",
]
STRING_KEYS = [k for k in REQUIRED_KEYS if k not in ("cveID", "cwes")]

def row_for(rows, cve_id):
    match = [r for r in rows if r["cve_id"] == cve_id]
    assert len(match) == 1, f"expected exactly one row for {cve_id}"
    return match[0]


def test_parse_kev_returns_expected_fields(load_fixture):
    rows = parse_kev(load_fixture("kev_sample.json"))

    assert len(rows) == 4

    row = row_for(rows, "CVE-2026-105134")
    assert row["vendor"] == "Ahsay"
    assert row["product"] == "AhsayCBS"
    assert row["name"] == "Ahsay AhsayCBS Command Injection Vulnerability"
    assert row["date_added"] == "2026-10-14"
    assert row["due_date"] == "2026-10-17"
    assert row["cwes"] == "CWE-77,CWE-78"
    assert row["ransomware_use"] is False
    assert row["short_description"].startswith("Ahsay AhsayCBS contains")

def test_parse_kev_empty_cwes_gives_empty_string(load_fixture):
    rows = parse_kev(load_fixture("kev_sample.json"))
    assert row_for(rows, "CVE-2026-53362")["cwes"] == ""


def test_parse_kev_ransomware_known_is_true(load_fixture):
    rows = parse_kev(load_fixture("kev_sample.json"))
    assert row_for(rows, "CVE-2026-59310")["ransomware_use"] is True
    assert row_for(rows, "CVE-2021-44228")["ransomware_use"] is True

def test_parse_kev_includes_notes_urls(load_fixture):
    rows = parse_kev(load_fixture("kev_sample.json"))
    urls = row_for(rows, "CVE-2026-105134")["urls"]
    assert len(urls) == 4
    assert "https://nvd.nist.gov/vuln/detail/CVE-2026-105134" in urls
    assert all(u.startswith(("http://", "https://")) for u in urls)

def test_parse_notes_urls_strips_labels_and_blanks():
    notes = (
        "https://vendor.example/advisory ; ; "
        "BOD 99-99: https://gov.example/bod ; "
        "Triage Requirements: https://gov.example/triage"
    )
    assert parse_notes_urls(notes) == [
        "https://vendor.example/advisory",
        "https://gov.example/bod",
        "https://gov.example/triage",
    ]

def test_parse_kev_ignores_unknown_fields(kev_entry):
    rows = parse_kev({"vulnerabilities": [kev_entry(brandNewField="x", cwes=["CWE-79"])]})
    assert rows[0]["cwes"] == "CWE-79"
    assert "brandNewField" not in rows[0]

@pytest.mark.parametrize("notes, expected", [
    ("javascript:alert(1)", []),
    ("data:text/html,<script>alert(1)</script>", []),
    ("ftp://files.example/x", []),
    ("see vendor site", []),
    ("javascript:alert(1) ; https://ok.example/a", ["https://ok.example/a"]),
])
def test_parse_notes_urls_drops_non_http(notes, expected):
    assert parse_notes_urls(notes) == expected


@pytest.mark.parametrize("notes", [None, "", "   ", " ; ; "])
def test_parse_notes_urls_empty_or_missing(notes):
    assert parse_notes_urls(notes) == []

def test_parse_kev_accepts_complete_synthetic_entry(kev_entry):
    # positive control: without it, the skip tests below could pass
    # against a parser that rejects everything
    rows = parse_kev({"vulnerabilities": [kev_entry()]})
    assert [r["cve_id"] for r in rows] == ["CVE-2099-0001"]


@pytest.mark.parametrize("key", REQUIRED_KEYS)
def test_parse_kev_skips_entry_missing_required_key(kev_entry, key):
    bad = kev_entry(cveID="CVE-2099-0002")
    del bad[key]
    rows = parse_kev({"vulnerabilities": [bad, kev_entry()]})
    assert [r["cve_id"] for r in rows] == ["CVE-2099-0001"]


@pytest.mark.parametrize("bad_id", [
    "CVE-2021-1", "cve-2021-44228", "CVE-2021-44228&x=1",
    "CVE-2021-44228\n", "", None, 12345,
])
def test_parse_kev_skips_invalid_cve_id(kev_entry, bad_id):
    rows = parse_kev({"vulnerabilities": [kev_entry(cveID=bad_id), kev_entry()]})
    assert [r["cve_id"] for r in rows] == ["CVE-2099-0001"]


@pytest.mark.parametrize("junk", [None, "CVE-2021-44228", 42, ["CVE-2021-44228"]])
def test_parse_kev_skips_non_dict_entries(kev_entry, junk):
    rows = parse_kev({"vulnerabilities": [junk, kev_entry()]})
    assert len(rows) == 1


def test_parse_kev_logs_one_warning_per_skipped_entry(kev_entry, caplog):
    bad = kev_entry(cveID="CVE-2099-0002")
    del bad["dueDate"]
    with caplog.at_level(logging.WARNING):
        parse_kev({"vulnerabilities": [bad, kev_entry()]})
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "CVE-2099-0002" in warnings[0].getMessage()


def test_parse_kev_empty_list_returns_empty():
    assert parse_kev({"vulnerabilities": []}) == []


@pytest.mark.parametrize("data", [
    {}, {"count": 1}, {"vulnerabilities": None},
    {"vulnerabilities": "nope"}, [], None,
])
def test_parse_kev_raises_when_feed_is_not_kev(data):
    with pytest.raises(ValueError):
        parse_kev(data)


@pytest.mark.parametrize("cve_id", [
    "CVE-2021-44228", "CVE-2026-105134", "CVE-1999-0001",
])
def test_validate_cve_id_accepts(cve_id):
    assert validate_cve_id(cve_id) is True


@pytest.mark.parametrize("cve_id", [
    "CVE-2021-1", "CVE-2021-123", "cve-2021-44228",
    "CVE-2021-44228&x=1", "CVE-2021-44228\n", " CVE-2021-44228",
    "../etc/passwd", "", " ", None, 12345, "CVE-２０２１-44228", 
])
def test_validate_cve_id_rejects(cve_id):
    assert validate_cve_id(cve_id) is False

def test_parse_kev_warning_does_not_embed_raw_newlines(kev_entry, caplog):
    bad = kev_entry(cveID="CVE-2099-0002\nERROR forged line")
    with caplog.at_level(logging.WARNING):
        parse_kev({"vulnerabilities": [bad]})
    assert "\n" not in caplog.records[0].getMessage()

@pytest.mark.parametrize("notes", [
    "https://", "http://", "BOD 26-04: https://", "https:// ; http://",
])
def test_parse_notes_urls_drops_scheme_only(notes):
    assert parse_notes_urls(notes) == []


@pytest.mark.parametrize("key", STRING_KEYS)
@pytest.mark.parametrize("bad_value", [None, 42, True, ["x"], {"a": 1}])
def test_parse_kev_skips_entry_with_non_string_field(kev_entry, key, bad_value):
    bad = kev_entry(cveID="CVE-2099-0002", **{key: bad_value})
    rows = parse_kev({"vulnerabilities": [bad, kev_entry()]})
    assert [r["cve_id"] for r in rows] == ["CVE-2099-0001"]


@pytest.mark.parametrize("bad_cwes", [
    "CWE-79", None, 79, [79], ["CWE-79", None], {"a": "b"},
])
def test_parse_kev_skips_entry_with_malformed_cwes(kev_entry, bad_cwes):
    bad = kev_entry(cveID="CVE-2099-0002", cwes=bad_cwes)
    rows = parse_kev({"vulnerabilities": [bad, kev_entry()]})
    assert [r["cve_id"] for r in rows] == ["CVE-2099-0001"]

def test_parse_notes_urls_comma_separated_in_one_segment():
    notes = "https://a.example/1, https://a.example/2, https://a.example/3 ; https://b.example/x"
    assert parse_notes_urls(notes) == [
        "https://a.example/1", "https://a.example/2",
        "https://a.example/3", "https://b.example/x",
    ]


def test_parse_notes_urls_comma_without_space_between_urls():
    notes = "https://a.example/HT1,https://a.example/HT2,https://a.example/HT3"
    assert parse_notes_urls(notes) == [
        "https://a.example/HT1", "https://a.example/HT2", "https://a.example/HT3",
    ]


def test_parse_notes_urls_keeps_comma_inside_a_url():
    notes = "https://a.example/page#:~:text=one,-two,-three ; https://ok.example/a"
    assert parse_notes_urls(notes) == [
        "https://a.example/page#:~:text=one,-two,-three", "https://ok.example/a",
    ]


def test_parse_notes_urls_embedded_url_stays_one_url():
    notes = "https://archive.example/web/2021/https://vendor.example/advisory.html ; https://ok.example/a"
    assert parse_notes_urls(notes) == [
        "https://archive.example/web/2021/https://vendor.example/advisory.html",
        "https://ok.example/a",
    ]


def test_parse_notes_urls_url_after_long_prose():
    notes = "For more information, please see: https://vendor.example/kb ; https://ok.example/a"
    assert parse_notes_urls(notes) == ["https://vendor.example/kb", "https://ok.example/a"]


def test_parse_notes_urls_semicolon_without_space():
    notes = "https://a.example/x; https://b.example/y;https://c.example/z"
    assert parse_notes_urls(notes) == [
        "https://a.example/x", "https://b.example/y", "https://c.example/z",
    ]


def test_parse_notes_urls_unwraps_parenthesized_url():
    notes = "Mitigate per ED 21-04 (https://a.example/ed-21-04) ; https://ok.example/a"
    assert parse_notes_urls(notes) == ["https://a.example/ed-21-04", "https://ok.example/a"]


def test_parse_notes_urls_keeps_balanced_parens_inside_url():
    notes = "https://a.example/vuln-(cve-2020-1)"
    assert parse_notes_urls(notes) == ["https://a.example/vuln-(cve-2020-1)"]


def test_parse_notes_urls_unwraps_parens_around_url_with_inner_parens():
    assert parse_notes_urls("(https://a.example/x-(y))") == ["https://a.example/x-(y)"]


def test_parse_notes_urls_strips_trailing_quote():
    notes = 'https://a.example/x" ; https://ok.example/a'
    assert parse_notes_urls(notes) == ["https://a.example/x", "https://ok.example/a"]


def test_parse_notes_urls_strips_trailing_period_keeps_interior_periods():
    notes = "https://a.example/aa23-158a. ; https://b.example/v1.2/page.html"
    assert parse_notes_urls(notes) == [
        "https://a.example/aa23-158a", "https://b.example/v1.2/page.html",
    ]


@pytest.mark.parametrize("url", [
    "https://a.example/slug-",
    "https://a.example/page.php#",
    "https://a.example/file.docx/0?",
])
def test_parse_notes_urls_keeps_trailing_dash_hash_question(url):
    assert parse_notes_urls(url) == [url]

@pytest.mark.parametrize("notes, expected", [
    ("(https://a.example/x).", ["https://a.example/x"]),
    ("https://a.example/v-(cve-1).", ["https://a.example/v-(cve-1)"]),
    ("https://a.example/x...", ["https://a.example/x"]),
])
def test_parse_notes_urls_strips_combined_trailing_punctuation(notes, expected):
    assert parse_notes_urls(notes) == expected

@pytest.mark.parametrize("url", [
    "https://a.example/x)y",
    "https://a.example/a)b)c",
])
def test_parse_notes_urls_leaves_non_trailing_close_paren_alone(url):
    assert parse_notes_urls(url) == [url]


@pytest.mark.parametrize("make_bad", [
    lambda e: None,
    lambda e: {k: v for k, v in e().items() if k != "dueDate"},
    lambda e: e(cveID="not-a-cve"),
    lambda e: e(product=42),
    lambda e: e(cwes="CWE-79"),
], ids=["not-a-dict", "missing-key", "invalid-id", "wrong-string-type", "wrong-cwes-type"])
def test_parse_kev_logs_exactly_one_warning_per_skip_reason(kev_entry, caplog, make_bad):
    with caplog.at_level(logging.WARNING):
        rows = parse_kev({"vulnerabilities": [make_bad(kev_entry)]})
    assert rows == []
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1

@pytest.mark.parametrize("key, bad_value", [("cwes", "CWE-79"), ("product", 42)])
def test_parse_kev_wrong_type_warning_names_the_field(kev_entry, caplog, key, bad_value):
    with caplog.at_level(logging.WARNING):
        parse_kev({"vulnerabilities": [kev_entry(**{key: bad_value})]})
    assert key in caplog.records[0].getMessage()
