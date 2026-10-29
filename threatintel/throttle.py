# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import hashlib
from datetime import timedelta

from django.core.cache import cache

# Hits older than this are dropped on record, so no window may be longer
# (the longest in use is the one-hour KEV refresh / registration window)
RETENTION = timedelta(hours=1)


def cache_key(bucket, key):
    # Hash the caller's key so any username is a safe, fixed-length cache key
    digest = hashlib.sha256(key.encode()).hexdigest()
    return f"throttle:{bucket}:{digest}"


def require_aware(now):
    if now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")


def record(bucket, key, now):
    require_aware(now)
    cutoff = (now - RETENTION).timestamp()
    hits = [t for t in cache.get(cache_key(bucket, key), []) if t > cutoff]
    hits.append(now.timestamp())
    cache.set(cache_key(bucket, key), hits, timeout=int(RETENTION.total_seconds()))


def count(bucket, key, window, now):
    require_aware(now)
    cutoff = (now - window).timestamp()
    return sum(1 for t in cache.get(cache_key(bucket, key), []) if t > cutoff)


def is_limited(bucket, key, limit, window, now):
    # Read-only: checking never adds a hit
    return count(bucket, key, window, now) >= limit
