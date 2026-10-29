# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import datetime, timedelta, timezone

import pytest

from threatintel.nvd_cache import nvd_is_stale

NOW = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize("status, age, stale", [
    ("Analyzed", timedelta(days=29), False),
    ("Analyzed", timedelta(days=31), True),
    ("Rejected", timedelta(days=29), False),
    ("Rejected", timedelta(days=31), True),
    ("Undergoing Analysis", timedelta(hours=23), False),
    ("Undergoing Analysis", timedelta(hours=25), True),
    ("Brand New Status", timedelta(hours=23), False),
    ("Brand New Status", timedelta(hours=25), True),
    (None, timedelta(hours=23), False),
    (None, timedelta(hours=25), True),
])
def test_nvd_is_stale_follows_ttl_by_status(status, age, stale):
    assert nvd_is_stale(status, NOW - age, NOW) is stale


@pytest.mark.parametrize("status", ["Analyzed", "Undergoing Analysis", None])
def test_nvd_is_stale_when_never_fetched(status):
    assert nvd_is_stale(status, None, NOW) is True


def test_nvd_is_stale_when_fetched_time_has_no_timezone():
    naive = (NOW - timedelta(hours=1)).replace(tzinfo=None)
    assert nvd_is_stale("Analyzed", naive, NOW) is True
