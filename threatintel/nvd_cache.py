# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

from datetime import timedelta

# Analyzed and Rejected records rarely change; anything else is still in flux
SETTLED_STATUSES = ("Analyzed", "Rejected")
SETTLED_TTL = timedelta(days=30)
DEFAULT_TTL = timedelta(hours=24)


def nvd_is_stale(nvd_status, fetched_at, now):
    if fetched_at is None or fetched_at.utcoffset() is None or now.utcoffset() is None:
        return True
    ttl = SETTLED_TTL if nvd_status in SETTLED_STATUSES else DEFAULT_TTL
    return now - fetched_at > ttl
