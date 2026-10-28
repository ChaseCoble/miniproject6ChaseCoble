# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import logging
import re

logger = logging.getLogger(__name__)

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.ASCII)

KEV_STRING_KEYS = (
    "vendorProject", "product", "vulnerabilityName",
    "shortDescription", "dateAdded", "dueDate",
    "knownRansomwareCampaignUse", "notes",
)
KEV_REQUIRED_KEYS = ("cveID", "cwes") + KEV_STRING_KEYS

# Split notes into tokens on ";" or whitespace, or on a comma that
# directly starts another URL (commas elsewhere can be part of a URL)
NOTES_SPLIT_RE = re.compile(r"[;\s]+|,(?=https?://)")
# Scheme plus at least one character, so a bare "https://" is rejected
URL_RE = re.compile(r"https?://.")

# NVD metric keys in precedence order; the version label comes from the
# key, not from cvssData["version"]
CVSS_METRIC_KEYS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
CVSS_KEYS = (
    "cvss_score", "cvss_version", "cvss_severity",
    "cvss_vector", "cvss_source", "cvss_type",
)


def validate_cve_id(cve_id):
    # fullmatch (not match + $) so a trailing "\n" is rejected;
    # re.ASCII so \d only matches 0-9, not full-width digits
    return isinstance(cve_id, str) and CVE_ID_RE.fullmatch(cve_id) is not None


def parse_notes_urls(notes):
    # Labels and prose are just tokens that aren't http(s) URLs, so they drop out.
    if not notes:
        return []
    urls = []
    for token in NOTES_SPLIT_RE.split(notes):
        token = token.lstrip("(")
        # Trim trailing punctuation from the surrounding sentence; only drop
        # ")" when it's unbalanced, so "x-(y)" keeps its own paren
        while token.endswith((".", ",", '"')) or (
            token.endswith(")") and token.count(")") > token.count("(")
        ):
            token = token[:-1]
        if URL_RE.match(token):
            urls.append(token)
    return urls


def parse_kev(data):
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("not a KEV feed: missing 'vulnerabilities' list")

    rows = []
    for entry in data["vulnerabilities"]:
        if not isinstance(entry, dict):
            logger.warning("skipping KEV entry: not an object (%s)", type(entry).__name__)
            continue
        # %r escapes control characters so a hostile cveID can't forge log lines
        missing = [key for key in KEV_REQUIRED_KEYS if key not in entry]
        if missing:
            logger.warning("skipping KEV entry %r: missing %s", entry.get("cveID"), ",".join(missing))
            continue
        if not validate_cve_id(entry["cveID"]):
            logger.warning("skipping KEV entry %r: invalid CVE ID", entry["cveID"])
            continue
        bad_types = [key for key in KEV_STRING_KEYS if not isinstance(entry[key], str)]
        cwes = entry["cwes"]
        if not (isinstance(cwes, list) and all(isinstance(cwe, str) for cwe in cwes)):
            bad_types.append("cwes")
        if bad_types:
            logger.warning("skipping KEV entry %r: wrong type for %s", entry["cveID"], ",".join(bad_types))
            continue
        rows.append({
            "cve_id": entry["cveID"],
            "vendor": entry["vendorProject"],
            "product": entry["product"],
            "name": entry["vulnerabilityName"],
            "short_description": entry["shortDescription"],
            "date_added": entry["dateAdded"],
            "due_date": entry["dueDate"],
            "ransomware_use": entry["knownRansomwareCampaignUse"] == "Known",
            "cwes": ",".join(entry["cwes"]),
            "urls": parse_notes_urls(entry["notes"]),
        })
    return rows


def select_cvss(metrics):
    # Newest CVSS version with a usable entry wins; within it, the first
    # Primary entry, else the first usable entry
    if not isinstance(metrics, dict):
        return dict.fromkeys(CVSS_KEYS)
    for key, version in CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        usable = [
            entry for entry in entries
            if isinstance(entry, dict)
            and isinstance(entry.get("cvssData"), dict)
            and is_cvss_score(entry["cvssData"].get("baseScore"))
        ]
        if not usable:
            continue
        primary = [entry for entry in usable if entry.get("type") == "Primary"]
        chosen = (primary or usable)[0]
        data = chosen["cvssData"]
        # v2 keeps baseSeverity on the metric itself, not inside cvssData
        severity = chosen.get("baseSeverity") if version == "2.0" else data.get("baseSeverity")
        return {
            "cvss_score": data["baseScore"],
            "cvss_version": version,
            "cvss_severity": str_or_none(severity),
            "cvss_vector": str_or_none(data.get("vectorString")),
            "cvss_source": str_or_none(chosen.get("source")),
            "cvss_type": str_or_none(chosen.get("type")),
        }
    return dict.fromkeys(CVSS_KEYS)


def is_cvss_score(score):
    # bool is a subclass of int, so it has to be excluded explicitly
    return (
        isinstance(score, (int, float))
        and not isinstance(score, bool)
        and 0.0 <= score <= 10.0
    )


def str_or_none(value):
    # Descriptive CVSS fields are optional: a non-string becomes None
    # rather than disqualifying an entry that has a usable score
    return value if isinstance(value, str) else None


def parse_nvd(data):
    # Returns None for an unknown CVE; raises ValueError for anything that
    # can't be interpreted, so it isn't cached as a real answer
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("not an NVD response: missing 'vulnerabilities' list")
    if not data["vulnerabilities"]:
        return None
    record = data["vulnerabilities"][0]
    if not isinstance(record, dict) or not isinstance(record.get("cve"), dict):
        raise ValueError("malformed NVD record: missing 'cve' object")
    cve = record["cve"]
    if not validate_cve_id(cve.get("id")):
        raise ValueError(f"malformed NVD record: invalid CVE ID {cve.get('id')!r}")
    for key in ("published", "lastModified"):
        if not isinstance(cve.get(key), str):
            raise ValueError(f"malformed NVD record {cve['id']}: {key} is not a string")
    # vulnStatus is optional in NVD's schema; present-but-wrong-type is an error
    if "vulnStatus" in cve and not isinstance(cve["vulnStatus"], str):
        raise ValueError(f"malformed NVD record {cve['id']}: vulnStatus is not a string")
    return {
        "cve_id": cve["id"],
        "nvd_status": cve.get("vulnStatus"),
        "nvd_published": cve["published"],
        "nvd_last_modified": cve["lastModified"],
        **select_cvss(cve.get("metrics")),
    }
