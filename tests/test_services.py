# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import datetime, timedelta, timezone


def test_services_defaults_are_the_real_fetchers():
    from threatintel import fetch, services
    assert services.fetch_kev is fetch.fetch_kev and services.fetch_nvd is fetch.fetch_nvd


def test_services_now_is_utc_aware_and_current():
    from threatintel import services
    now = services.now()
    assert now.tzinfo is not None and now.utcoffset() == timedelta(0)
    assert abs((datetime.now(timezone.utc) - now).total_seconds()) < 5
