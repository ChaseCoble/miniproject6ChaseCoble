# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import copy

import pytest

from threatintel.sources import parse_nvd, select_cvss

CVSS_KEYS = {
    "cvss_score", "cvss_version", "cvss_severity",
    "cvss_vector", "cvss_source", "cvss_type",
}
NO_CVSS = dict.fromkeys(CVSS_KEYS)


def metric(score, type_="Primary", severity="HIGH", vector="V", source="nvd@nist.gov"):
    return {
        "source": source,
        "type": type_,
        "cvssData": {"baseScore": score, "baseSeverity": severity, "vectorString": vector},
    }


def metric_v2(score, type_="Primary", severity="HIGH", vector="AV:N/AC:L/Au:N/C:C/I:C/A:C"):
    # v2 differs: severity sits on the metric, not inside cvssData
    return {
        "source": "nvd@nist.gov",
        "type": type_,
        "cvssData": {"baseScore": score, "vectorString": vector},
        "baseSeverity": severity,
    }


def cve_of(doc):
    return doc["vulnerabilities"][0]["cve"]


# ---------- select_cvss ----------

def test_select_cvss_returns_exactly_the_six_fields():
    m = {"cvssMetricV31": [metric(9.8, severity="CRITICAL", vector="CVSS:3.1/AV:N")]}
    assert select_cvss(m) == {
        "cvss_score": 9.8, "cvss_version": "3.1", "cvss_severity": "CRITICAL",
        "cvss_vector": "CVSS:3.1/AV:N", "cvss_source": "nvd@nist.gov", "cvss_type": "Primary",
    }


def test_select_cvss_prefers_v40_over_v31():
    m = {"cvssMetricV31": [metric(10.0)], "cvssMetricV40": [metric(9.3)]}
    got = select_cvss(m)
    assert (got["cvss_version"], got["cvss_score"]) == ("4.0", 9.3)


@pytest.mark.parametrize("present, expected_version", [
    (["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"], "4.0"),
    (["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"], "3.1"),
    (["cvssMetricV30", "cvssMetricV2"], "3.0"),
    (["cvssMetricV2"], "2.0"),
])
def test_select_cvss_version_precedence(present, expected_version):
    # built lowest-first so dict insertion order can't help the implementation
    m = {key: [metric(5.0)] for key in reversed(present)}
    assert select_cvss(m)["cvss_version"] == expected_version


def test_select_cvss_newer_secondary_beats_older_primary():
    m = {
        "cvssMetricV31": [metric(10.0, "Primary")],
        "cvssMetricV40": [metric(9.3, "Secondary")],
    }
    got = select_cvss(m)
    assert got["cvss_version"] == "4.0" and got["cvss_type"] == "Secondary"


@pytest.mark.parametrize("secondary_first", [True, False])
def test_select_cvss_primary_beats_secondary_in_either_order(secondary_first):
    sec = metric(7.0, "Secondary", source="cna.example")
    pri = metric(9.0, "Primary", source="nvd@nist.gov")
    entries = [sec, pri] if secondary_first else [pri, sec]
    got = select_cvss({"cvssMetricV31": entries})
    assert got["cvss_type"] == "Primary" and got["cvss_score"] == 9.0


def test_select_cvss_first_entry_wins_when_types_tie():
    m = {"cvssMetricV31": [metric(6.0, "Secondary"), metric(8.0, "Secondary")]}
    assert select_cvss(m)["cvss_score"] == 6.0


def test_select_cvss_v2_severity_comes_from_metric_level():
    assert select_cvss({"cvssMetricV2": [metric_v2(10.0, severity="HIGH")]})["cvss_severity"] == "HIGH"


def test_select_cvss_v2_without_severity_gives_none_but_keeps_score():
    m = metric_v2(10.0)
    del m["baseSeverity"]
    got = select_cvss({"cvssMetricV2": [m]})
    assert got["cvss_score"] == 10.0 and got["cvss_severity"] is None


def test_select_cvss_version_comes_from_the_metric_key():
    m = metric(5.0)
    m["cvssData"]["version"] = "9.9"
    assert select_cvss({"cvssMetricV31": [m]})["cvss_version"] == "3.1"


@pytest.mark.parametrize("metrics", [
    {"ssvcV203": [{"source": "x", "ssvcData": {"id": "CVE-2099-0001"}}]},
    {"cvssMetricV99": [metric(9.0)]},
    {"cvssMetricV31": "nope"},
    {"cvssMetricV31": None},
    {}, None, [], "nope",
])
def test_select_cvss_returns_no_cvss_when_nothing_usable(metrics):
    assert select_cvss(metrics) == NO_CVSS


def test_select_cvss_ignores_ssvc_alongside_real_scores():
    m = {"ssvcV203": [{"source": "x", "ssvcData": {}}], "cvssMetricV31": [metric(7.5)]}
    assert select_cvss(m)["cvss_score"] == 7.5


def test_select_cvss_empty_list_falls_through_to_next_version():
    m = {"cvssMetricV40": [], "cvssMetricV31": [metric(7.5)]}
    assert select_cvss(m)["cvss_version"] == "3.1"


@pytest.mark.parametrize("bad_score", [None, "9.3", True, 11.0, -0.1])
def test_select_cvss_skips_entry_with_unusable_score(bad_score):
    got = select_cvss({"cvssMetricV31": [metric(bad_score, "Primary"), metric(5.0, "Secondary")]})
    assert got["cvss_score"] == 5.0


def test_select_cvss_unusable_higher_version_falls_through():
    m = {"cvssMetricV40": [metric("n/a")], "cvssMetricV31": [metric(7.5)]}
    assert select_cvss(m)["cvss_version"] == "3.1"


@pytest.mark.parametrize("junk", [
    None, "x", 42, {}, {"type": "Primary"}, {"cvssData": None}, {"cvssData": "x"},
])
def test_select_cvss_skips_malformed_entries(junk):
    got = select_cvss({"cvssMetricV31": [junk, metric(5.0)]})
    assert got["cvss_score"] == 5.0


@pytest.mark.parametrize("score", [0.0, 10.0])
def test_select_cvss_accepts_score_range_endpoints(score):
    assert select_cvss({"cvssMetricV31": [metric(score)]})["cvss_score"] == score


def test_select_cvss_does_not_mutate_its_input():
    m = {"cvssMetricV31": [metric(7.5)], "cvssMetricV40": [metric(9.3)]}
    before = copy.deepcopy(m)
    select_cvss(m)
    assert m == before


# ---------- parse_nvd ----------

def test_parse_nvd_undergoing_analysis_prefers_v40(load_fixture):
    got = parse_nvd(load_fixture("nvd_undergoing_analysis.json"))
    assert got["cve_id"] == "CVE-2026-105134"
    assert got["nvd_status"] == "Undergoing Analysis"
    assert got["cvss_score"] == 9.3
    assert got["cvss_version"] == "4.0"
    assert got["cvss_severity"] == "CRITICAL"
    assert got["cvss_type"] == "Secondary"
    assert got["cvss_vector"].startswith("CVSS:4.0/")


def test_parse_nvd_keeps_timestamps_as_raw_strings(load_fixture):
    doc = load_fixture("nvd_undergoing_analysis.json")
    got = parse_nvd(doc)
    assert got["nvd_published"] == cve_of(doc)["published"]
    assert got["nvd_last_modified"] == cve_of(doc)["lastModified"]
    assert isinstance(got["nvd_published"], str)


def test_parse_nvd_log4shell_prefers_primary_nvd_entry(load_fixture):
    doc = load_fixture("nvd_log4shell.json")
    got = parse_nvd(doc)
    assert got["cve_id"] == "CVE-2021-44228"
    assert got["cvss_version"] == "3.1"
    assert got["cvss_score"] == 10.0
    assert got["cvss_severity"] == "CRITICAL"
    assert got["cvss_type"] == "Primary"
    assert got["cvss_source"] == "nvd@nist.gov"
    assert got["nvd_status"] == cve_of(doc)["vulnStatus"]


def test_parse_nvd_log4shell_primary_wins_even_if_listed_second(load_fixture):
    doc = load_fixture("nvd_log4shell.json")
    entries = cve_of(doc)["metrics"]["cvssMetricV31"]
    entries.reverse()
    assert entries[0]["type"] == "Secondary"  # precondition: the reversal really happened
    got = parse_nvd(doc)
    assert got["cvss_type"] == "Primary"
    assert got["cvss_source"] == "nvd@nist.gov"


def test_parse_nvd_no_metrics_fixture(load_fixture):
    got = parse_nvd(load_fixture("nvd_no_metrics.json"))
    assert got["cve_id"] == "CVE-2026-105134"
    assert got["nvd_status"] == "Undergoing Analysis"
    assert {k: got[k] for k in CVSS_KEYS} == NO_CVSS


def test_parse_nvd_empty_metrics_object_is_same_as_absent(load_fixture):
    doc = load_fixture("nvd_undergoing_analysis.json")
    cve_of(doc)["metrics"] = {}
    got = parse_nvd(doc)
    assert {k: got[k] for k in CVSS_KEYS} == NO_CVSS


def test_parse_nvd_v2_only_fixture(load_fixture):
    got = parse_nvd(load_fixture("nvd_v2_only.json"))
    assert got["cvss_version"] == "2.0"
    assert got["cvss_score"] == 10.0
    assert got["cvss_severity"] == "HIGH"
    assert got["cvss_vector"] == "AV:N/AC:L/Au:N/C:C/I:C/A:C"


def test_parse_nvd_v30_only_fixture(load_fixture):
    got = parse_nvd(load_fixture("nvd_v30_only.json"))
    assert got["cvss_version"] == "3.0"
    assert got["cvss_score"] == 10.0
    assert got["cvss_severity"] == "CRITICAL"


def test_parse_nvd_unknown_cve_returns_none(load_fixture):
    assert parse_nvd(load_fixture("nvd_empty.json")) is None


def test_parse_nvd_missing_status_gives_none(load_fixture):
    doc = load_fixture("nvd_undergoing_analysis.json")
    del cve_of(doc)["vulnStatus"]  # optional in NVD's schema
    assert parse_nvd(doc)["nvd_status"] is None


def test_parse_nvd_unknown_status_string_passes_through(load_fixture):
    doc = load_fixture("nvd_undergoing_analysis.json")
    cve_of(doc)["vulnStatus"] = "Brand New Status"
    assert parse_nvd(doc)["nvd_status"] == "Brand New Status"


@pytest.mark.parametrize("data", [
    None, [], "x", {}, {"vulnerabilities": None}, {"vulnerabilities": "nope"},
])
def test_parse_nvd_raises_when_response_is_not_nvd(data):
    with pytest.raises(ValueError):
        parse_nvd(data)


@pytest.mark.parametrize("record", [None, {}, {"cve": None}, {"cve": "x"}, {"cve": {}}])
def test_parse_nvd_raises_on_malformed_record(record):
    with pytest.raises(ValueError):
        parse_nvd({"vulnerabilities": [record]})


@pytest.mark.parametrize("key", ["id", "published", "lastModified"])
def test_parse_nvd_raises_when_required_field_missing(load_fixture, key):
    doc = load_fixture("nvd_undergoing_analysis.json")
    del cve_of(doc)[key]
    with pytest.raises(ValueError):
        parse_nvd(doc)


@pytest.mark.parametrize("bad_id", ["CVE-2021-1", "../x", "", None, 42])
def test_parse_nvd_raises_on_invalid_cve_id(load_fixture, bad_id):
    doc = load_fixture("nvd_undergoing_analysis.json")
    cve_of(doc)["id"] = bad_id
    with pytest.raises(ValueError):
        parse_nvd(doc)


@pytest.mark.parametrize("key", ["published", "lastModified", "vulnStatus"])
@pytest.mark.parametrize("bad_value", [None, 123, ["x"]])
def test_parse_nvd_raises_on_non_string_field(load_fixture, key, bad_value):
    doc = load_fixture("nvd_undergoing_analysis.json")
    cve_of(doc)[key] = bad_value
    with pytest.raises(ValueError):
        parse_nvd(doc)

@pytest.mark.parametrize("field, key", [
    ("baseSeverity", "cvss_severity"),
    ("vectorString", "cvss_vector"),
])
@pytest.mark.parametrize("bad", [None, 42, ["x"], {"a": 1}])
def test_select_cvss_non_string_cvssdata_field_becomes_none(field, key, bad):
    m = metric(7.5)
    m["cvssData"][field] = bad
    got = select_cvss({"cvssMetricV31": [m]})
    assert got["cvss_score"] == 7.5 and got[key] is None


@pytest.mark.parametrize("field, key", [("source", "cvss_source"), ("type", "cvss_type")])
@pytest.mark.parametrize("bad", [None, 42, ["x"]])
def test_select_cvss_non_string_metric_field_becomes_none(field, key, bad):
    m = metric(7.5)
    m[field] = bad
    got = select_cvss({"cvssMetricV31": [m]})
    assert got["cvss_score"] == 7.5 and got[key] is None

@pytest.mark.parametrize("bad", [None, 42, ["x"], {"a": 1}])
def test_select_cvss_v2_non_string_severity_becomes_none(bad):
    # v2 keeps severity on the metric itself, a different code path from the other versions
    m = metric_v2(10.0)
    m["baseSeverity"] = bad
    got = select_cvss({"cvssMetricV2": [m]})
    assert got["cvss_score"] == 10.0 and got["cvss_severity"] is None
