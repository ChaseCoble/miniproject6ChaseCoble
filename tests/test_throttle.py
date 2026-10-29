# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import datetime, timedelta, timezone

import pytest

from threatintel import throttle

T0 = datetime(2099, 6, 1, 12, 0, tzinfo=timezone.utc)
WINDOW = timedelta(minutes=15)
SECOND = timedelta(seconds=1)


def test_nothing_recorded_means_not_limited():
    assert throttle.is_limited("b", "k", 3, WINDOW, T0) is False


def test_limited_once_the_limit_is_reached():
    for _ in range(2):
        throttle.record("b", "k", T0)
    assert throttle.is_limited("b", "k", 3, WINDOW, T0) is False
    throttle.record("b", "k", T0)
    assert throttle.is_limited("b", "k", 3, WINDOW, T0) is True


def test_checking_does_not_record():
    for _ in range(10):
        throttle.is_limited("b", "k", 3, WINDOW, T0)
    assert throttle.count("b", "k", WINDOW, T0) == 0


def test_hits_expire_after_the_window():
    for _ in range(3):
        throttle.record("b", "k", T0)
    assert throttle.is_limited("b", "k", 3, WINDOW, T0 + WINDOW - SECOND) is True
    assert throttle.is_limited("b", "k", 3, WINDOW, T0 + WINDOW + SECOND) is False


def test_count_only_includes_hits_inside_the_window():
    throttle.record("b", "k", T0)
    throttle.record("b", "k", T0 + WINDOW)
    assert throttle.count("b", "k", WINDOW, T0 + WINDOW + SECOND) == 1


def test_keys_are_independent():
    throttle.record("b", "one", T0)
    assert throttle.count("b", "two", WINDOW, T0) == 0


def test_buckets_are_independent():
    throttle.record("login", "k", T0)
    assert throttle.count("register", "k", WINDOW, T0) == 0


@pytest.mark.parametrize("call", [
    lambda naive: throttle.record("b", "k", naive),
    lambda naive: throttle.count("b", "k", WINDOW, naive),
    lambda naive: throttle.is_limited("b", "k", 3, WINDOW, naive),
])
def test_naive_datetimes_are_rejected(call):
    with pytest.raises(ValueError):
        call(T0.replace(tzinfo=None))


