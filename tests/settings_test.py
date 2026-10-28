# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import os

os.environ.setdefault("DJANGO_SECRET_KEY", "abcdefghij" * 6)
os.environ.setdefault("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1")

from config.settings import *  # noqa: E402,F401,F403

PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]  # speed only
CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage"},
}
