# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GOOD_KEY = "abcdefghij" * 6
BASE_ENV = {"DJANGO_SECRET_KEY": GOOD_KEY, "DJANGO_ALLOWED_HOSTS": "app.example"}


def run_python(code, env_updates, args=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("DJANGO_")}
    env.update(env_updates)
    env["DJANGO_SETTINGS_MODULE"] = "config.settings"
    env["PYTHONPATH"] = str(ROOT)
    cmd = [sys.executable, *(args if args else ["-c", code])]
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)


def read(expr, **env):
    code = ("import json, django\nfrom django.conf import settings\ndjango.setup()\n"
            f"print(json.dumps({expr}))")
    result = run_python(code, {**BASE_ENV, **env})
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def refuses(**env):
    updates = {**BASE_ENV, **env}
    updates = {k: v for k, v in updates.items() if v is not None}
    code = "from django.conf import settings\nsettings.SECRET_KEY\nsettings.ALLOWED_HOSTS"
    return run_python(code, updates)


# ---------- secret key ----------

def test_settings_refuse_to_load_without_a_secret_key():
    result = refuses(DJANGO_SECRET_KEY=None)
    assert result.returncode != 0 and "SECRET_KEY" in result.stderr


@pytest.mark.parametrize("key", ["short", "x" * 60, "django-insecure-" + "abcdefghij" * 6])
def test_settings_refuse_weak_secret_keys(key):
    assert refuses(DJANGO_SECRET_KEY=key).returncode != 0


def test_settings_use_the_configured_secret_key():
    assert read("settings.SECRET_KEY") == GOOD_KEY


# ---------- debug and hosts ----------

def test_debug_is_off_by_default():
    assert read("settings.DEBUG") is False


@pytest.mark.parametrize("value, expected", [
    ("1", True), ("true", True), ("0", False), ("false", False), ("", False), ("yes please", False),
])
def test_debug_follows_the_environment_variable(value, expected):
    assert read("settings.DEBUG", DJANGO_DEBUG=value) is expected


def test_allowed_hosts_must_be_configured():
    assert refuses(DJANGO_ALLOWED_HOSTS=None).returncode != 0


@pytest.mark.parametrize("hosts", ["*", "app.example,*"])
def test_wildcard_allowed_hosts_are_refused(hosts):
    assert refuses(DJANGO_ALLOWED_HOSTS=hosts).returncode != 0


def test_allowed_hosts_are_split_and_trimmed():
    assert read("settings.ALLOWED_HOSTS", DJANGO_ALLOWED_HOSTS="a.example, b.example ,") == ["a.example", "b.example"]


# ---------- cookies, headers, hashing ----------

def test_cookie_flags_are_hardened():
    assert read("[settings.SESSION_COOKIE_HTTPONLY, settings.SESSION_COOKIE_SAMESITE, "
                "settings.CSRF_COOKIE_HTTPONLY, settings.CSRF_COOKIE_SAMESITE]") == [True, "Lax", True, "Lax"]


def test_secure_cookies_are_a_deliberate_switch():
    expr = "[settings.SESSION_COOKIE_SECURE, settings.CSRF_COOKIE_SECURE]"
    assert read(expr) == [False, False]
    assert read(expr, DJANGO_SECURE_COOKIES="1") == [True, True]


def test_hsts_seconds_come_from_the_environment():
    assert read("settings.SECURE_HSTS_SECONDS") == 0
    assert read("settings.SECURE_HSTS_SECONDS", DJANGO_HSTS_SECONDS="3600") == 3600


def test_password_hashing_is_not_downgraded():
    code = ("import json, django\ndjango.setup()\n"
            "from django.contrib.auth.hashers import make_password\nprint(json.dumps(make_password('x')))")
    result = run_python(code, BASE_ENV)
    assert result.returncode == 0, result.stderr
    assert not json.loads(result.stdout.strip().splitlines()[-1]).startswith(("md5$", "sha1$", "crypt$", "unsalted_"))


def test_default_password_validators_are_kept():
    names = read("[v['NAME'].rsplit('.', 1)[-1] for v in settings.AUTH_PASSWORD_VALIDATORS]")
    assert {"UserAttributeSimilarityValidator", "MinimumLengthValidator",
            "CommonPasswordValidator", "NumericPasswordValidator"} <= set(names)


def test_minimum_password_length_is_at_least_eight():
    lengths = read("[v.get('OPTIONS', {}).get('min_length', 8) for v in settings.AUTH_PASSWORD_VALIDATORS "
                   "if v['NAME'].endswith('MinimumLengthValidator')]")
    assert lengths and all(n >= 8 for n in lengths)


# ---------- the rest ----------

def test_timezones_are_enabled_and_utc():
    assert read("[settings.USE_TZ, settings.TIME_ZONE]") == [True, "UTC"]


def test_cache_is_shared_across_workers():
    assert read("settings.CACHES['default']['BACKEND']") == "django.core.cache.backends.db.DatabaseCache"


def test_admin_url_is_not_the_default_and_can_be_overridden():
    default = read("settings.ADMIN_URL")
    assert default != "admin/" and default.endswith("/") and not default.startswith("/")
    assert read("settings.ADMIN_URL", DJANGO_ADMIN_URL="x-panel/") == "x-panel/"


def test_the_app_is_installed():
    assert any(a.startswith("threatintel") for a in read("settings.INSTALLED_APPS"))


@pytest.mark.parametrize("name", [
    "SecurityMiddleware", "SessionMiddleware", "CsrfViewMiddleware",
    "AuthenticationMiddleware", "MessageMiddleware", "XFrameOptionsMiddleware",
])
def test_required_middleware_is_enabled(name):
    assert any(m.endswith(name) for m in read("settings.MIDDLEWARE"))


def test_django_system_check_passes():
    assert run_python("", BASE_ENV, ["manage.py", "check"]).returncode == 0


def test_no_model_changes_are_missing_a_migration():
    result = run_python("", BASE_ENV, ["manage.py", "makemigrations", "--check", "--dry-run"])
    assert result.returncode == 0, result.stdout + result.stderr


def test_referrer_and_opener_policies_are_set_explicitly():
    assert read("[settings.SECURE_REFERRER_POLICY, settings.SECURE_CROSS_ORIGIN_OPENER_POLICY]") == ["same-origin", "same-origin"]
