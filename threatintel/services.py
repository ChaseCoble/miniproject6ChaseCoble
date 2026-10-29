# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import logging
from datetime import date, datetime, timezone

from django.db import transaction

from threatintel.fetch import fetch_kev, fetch_nvd  # noqa: F401 (callers use services.fetch_*)
from threatintel.models import Vulnerability

logger = logging.getLogger(__name__)

KEV_FIELDS = ("vendor", "product", "name", "short_description", "ransomware_use", "cwes")
NVD_FIELDS = (
    "nvd_status", "nvd_published", "nvd_last_modified", "cvss_score", "cvss_version",
    "cvss_severity", "cvss_vector", "cvss_source", "cvss_type",
)


def now():
    return datetime.now(timezone.utc)


def upsert_kev(rows):
    # One transaction, so a database error anywhere rolls back the whole batch
    with transaction.atomic():
        for row in rows:
            try:
                date_added = date.fromisoformat(row["date_added"])
                due_date = date.fromisoformat(row["due_date"])
            except ValueError:
                # %r escapes control characters so the CVE ID can't forge log lines
                logger.warning("skipping KEV row %r: unparseable date", row["cve_id"])
                continue
            defaults = {field: row[field] for field in KEV_FIELDS}
            defaults.update(date_added=date_added, due_date=due_date, kev_urls="\n".join(row["urls"]))
            # Only the defaults are written, so the row id and NVD fields survive
            Vulnerability.objects.update_or_create(cve_id=row["cve_id"], defaults=defaults)


def save_nvd(result, now):
    if now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    fields = {field: result[field] for field in NVD_FIELDS}
    # filter().update() writes nothing for an unknown CVE
    Vulnerability.objects.filter(cve_id=result["cve_id"]).update(nvd_fetched_at=now, **fields)
