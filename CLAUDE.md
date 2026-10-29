# CLAUDE.md

Standing instructions for Claude Code in this repository. Read the whole file before acting.

## Environment constraints (do not work around these)

- This account (`claude_agent`) is permanently denied execute access to `setfacl`, `chmod` and `chown` at the OS level (ACL-denied on the binaries themselves). This is intentional and permanent, not a bug. Do not attempt these commands, variations of them, or workarounds (including via sudo, which is also unavailable to this account). If a task seems to require a permission or ownership change, stop and tell the user what is needed and why.
- This account has no sudo access, for anything, under any circumstance. Do not propose `sudo` as a fix for a permission error.
- Access is scoped per project by ACL, granted by `claude_init` and revoked by `claude_close`. Assume you can read and write only inside this project directory and its subdirectories, never above or outside it.
- This project uses a venv. Run `source .venv/bin/activate` before `pytest -q` or `python manage.py ...`.

## Workflow rules

- **TDD.** For any new function or method, a failing test must exist before the implementation is written, unless the user explicitly directs otherwise for a specific case.
- **Pairing partner, not a code generator.** The user must be able to explain every line submitted. For anything non-trivial, explain the approach before writing code. Exception: a handoff that names test files to make pass (for example "Make tests/test_models.py pass. Rules are in CLAUDE.md.") is an explicit go-ahead to implement. The tests are the specification, so do not stop to ask for confirmation, and report what you did afterward.
- **Confirm understanding when the task is ambiguous.** State your understanding and wait, or ask, rather than assuming.
- **Do not guess at API or library behavior.** If you are not certain what a Django function, setting or class does in the installed version, say so and suggest checking the documentation or testing it directly. This matters most for the items under "Names to verify" below.
- **Record decisions.** When the user confirms a decision or finding, offer a one-line entry for `DECISIONS.md` and wait for approval. Never add entries unprompted, and never state reasoning the user has not given.
- **Never change the repository's history or index.** No `git commit`, `git push`, `git add`, `git reset` or similar. The user commits.
- **No new dependencies.** Runtime: `django` only. Dev: `pytest` and `pytest-django`. If a task seems to need another package, stop and ask.

## Security posture

- Treat this environment as deliberately least-privilege. If something you would normally expect to be able to do fails with a permission error, that is very likely intentional scoping, not a misconfiguration to fix. Report it, do not circumvent it.
- Do not attempt to install, invoke, or rely on tools that would require privileges this account does not have.
- File ownership during a session is not a long-term audit signal. `claude_close` reassigns ownership back to the human operator when a project concludes. Conversation logs serve as provenance instead.

---

## Project: Threat Intel Aggregator (INF601 Mini Project 6, Django)

### Assignment
A small Django app that aggregates two public sources, CISA KEV and NVD, joined on CVE ID. It will be attacked live in class, so security takes priority over features.
- 5+ commits (the user commits), a pinned `requirements.txt`, and a README covering the project, install, database initialization, running the dev server, and an AI Usage section.
- Django: a proper folder structure with at least one app, 5+ pages on a template structure, at least one form page, the admin set up with the models styled for entry, Bootstrap in the templates (at minimum a modal), and a register and login system.

### Rules for every slice
- Never edit `tests/` or `pytest.ini`. If a test looks wrong, stop and say so.
- Implement only what the tests require. No helpers nothing calls.
- Run `pytest -q` with the venv active. Stop at green.
- Report every guess the tests do not pin down, and every place you deviated from this file.
- Every `.py` file outside `tests/` starts with exactly this header, including `manage.py`, everything under `config/`, `apps.py`, `admin.py`, `models.py`, `views.py` and every migration (re-add it after each `makemigrations`). Headers inside `tests/` are added by the user.
  ```
  # INF601 - Advanced Programming in Python
  # Chase Coble
  # Mini Project 6
  ```
- Never build SQL by string formatting, and never use `.raw()`, `.extra()`, `RawSQL`, or `cursor()` in app code. Use the ORM.
- Third-party text (KEV, NVD) is untrusted. Log it with `%r`, and render it escaped.
- Never log passwords or session data.
- No `|safe`, no `{% autoescape off %}`, no `mark_safe` anywhere.

### Layout
- Project package `config/`, app `threatintel/`. Delete the generated `threatintel/tests.py`.
- Pure modules (stdlib only, no `django` or `flask` import, no I/O except `fetch.py`'s injected network call): `threatintel/sources.py`, `threatintel/fetch.py`, `threatintel/nvd_cache.py`. Copied from the earlier project. Do not change `sources.py` or `fetch.py`, since their tests are already green.
- `threatintel/models.py`, `services.py`, `throttle.py`, `views.py`, `forms.py`, `urls.py`, `admin.py`, `middleware.py` (only if needed), `templates/`, `static/`.

## Django contract (what the tests pin)

### Models
- `Vulnerability`: `cve_id` (unique; `full_clean()` rejects anything not matching `CVE-[0-9]{4}-[0-9]{4,}` as a whole string, so a trailing newline fails), `vendor`, `product`, `name`, `short_description`, `date_added` and `due_date` (`DateField`), `ransomware_use` (bool, default False), `cwes` and `kev_urls` (blank allowed, default empty string, `kev_urls` is newline-joined). NVD fields, all nullable: `nvd_status`, `nvd_published` and `nvd_last_modified` (raw strings, never parsed), `cvss_score` (float), `cvss_version`, `cvss_severity`, `cvss_vector`, `cvss_source`, `cvss_type`, `nvd_fetched_at` (`DateTimeField`). `__str__` contains the CVE ID. A `reference_urls` property returns only the `http://` and `https://` entries of `kev_urls`, in order.
- `Watch`: FK `user` and FK `vulnerability` (both `on_delete=CASCADE`), `note` (max 500, blank allowed, default empty), `created` (`auto_now_add`, timezone-aware), and a `UniqueConstraint` on `(user, vulnerability)`. Use Django's automatic `id`, not a composite primary key, because composite keys can't be registered in the admin.

### `services.py` (all DB writes live here)
- Module-level attributes `fetch_kev` and `fetch_nvd` (imported from `fetch`) and `now()` (returns `datetime.now(timezone.utc)`). Views and `throttle.py` call them as `services.X(...)` at request time, never `from services import X`, because tests monkeypatch the module attributes.
- `upsert_kev(rows)`: takes `parse_kev` output, one `transaction.atomic()` for the whole batch, update-or-create keyed on `cve_id`. It keeps the row id and existing watches, leaves every NVD field alone, and is idempotent. A row whose dates won't parse is skipped with exactly one `logger.warning` that shows the CVE ID with `%r` (so it can contain no newline). A database error mid-batch rolls back the whole batch.
- `save_nvd(result, now)`: takes `parse_nvd` output, updates only the named CVE, stores `nvd_fetched_at=now`, does nothing for an unknown CVE, and raises `ValueError` if `now` is timezone-naive.

### `nvd_cache.py`
- `nvd_is_stale(nvd_status, fetched_at, now) -> bool`, stdlib only. Never fetched or a naive datetime gives True. `Analyzed` and `Rejected` go stale after 30 days. Any other status, including None and unknown strings, after 24 hours. Strictly greater than the TTL means stale.

### `throttle.py`
- `record(bucket, key, now)`, `count(bucket, key, window, now)`, `is_limited(bucket, key, limit, window, now)`, built on the Django cache. A naive datetime raises `ValueError`. Checking never records. Hits older than the window stop counting. Keys and buckets are independent. Time always comes from `services.now()`.
- Limits (a limited response is HTTP 429 with the words "too many" in the body): logins 5 failures per 15 minutes per normalized username (stripped, lowercased, unknown usernames count too, and a blocked attempt is not recorded, so the window cannot be extended); registration 5 POSTs per hour per `REMOTE_ADDR` (never trust `X-Forwarded-For`); NVD lookups 5 per 30 seconds app-wide; KEV refresh once per hour app-wide, and a failed fetch or a non-KEV feed does not start the window. The admin login shares the site's login bucket.

### URLs
- `/` dashboard, `/about/`, `/cve/<cve_id>/`, `/watchlist/`, `/watch/<cve_id>/{add,edit,delete}/`, `/refresh/`, `/accounts/{register,login,logout}/`, and the admin at `settings.ADMIN_URL`, never the default. A request to `/admin/` returns 404.
- `LOGIN_URL="/accounts/login/"`, `LOGIN_REDIRECT_URL="/"`. Anonymous requests to a gated route get a 302 to the login URL with `?next=<path>`. `add`, `delete` and `refresh` are POST-only (GET gives 405). `edit` is GET (form prefilled) and POST. Logout is POST-only.

### Views
- **Dashboard.** Public. Rows ordered `date_added` descending then `cve_id` ascending (the tie-break keeps pages stable), 100 per page, `?page=` clamped (invalid or out-of-range values never error). `?q=` searches `cve_id`, `vendor` and `product` with ORM `icontains`, so `%` and `_` stay literal.
- **Detail.** Validate with `validate_cve_id` first: malformed gives 404 and no fetch, valid but not in the database gives 404 and no fetch. Fetch NVD only for a logged-in user, only when `nvd_is_stale(...)` is true, and only if the NVD throttle allows it. Then `parse_nvd`, then `save_nvd(result, services.now())`. `FetchError`, `ValueError` from the parser, a throttled lookup, or `parse_nvd` returning None all mean the same thing: render the KEV data with a notice containing the word "unavailable" and save nothing. Anonymous visitors see KEV data plus anything already cached, and never trigger a fetch. Show the CVSS score with its version in one element, for example `9.3 (CVSS v4.0)`, the severity, the NVD status, a link to `https://nvd.nist.gov/vuln/detail/<validated id>`, and `reference_urls` as links.
- **Watchlist.** Every query is scoped to `request.user`. A watch that is not yours behaves exactly like a missing one: 404, never 403, and never a hint of its contents. Add: 404 for an unknown or malformed ID, a duplicate adds no row and flashes a message containing "already". Edit note: max 500 characters, an over-limit value re-renders the form and changes nothing, a valid one redirects to a local path. Delete: removes only your watch, never the vulnerability.
- **Refresh.** POST, login required. On success: `services.fetch_kev()`, `parse_kev`, `upsert_kev`. A fetch failure or a non-KEV feed changes nothing.

### Auth
- Register is a view on Django's `UserCreationForm`: it redirects to the login page and does not log the user in. Login and logout use Django's built-in views. `?next=` is honored only for a safe local path (off-site, scheme-relative and `javascript:` targets fall back to `/`). Do not reveal whether a username exists through the wording of a login error. The session key must change on login.

### Settings (`config/settings.py`, environment variables only, no dotenv package)
- `DJANGO_SECRET_KEY` is required: at least 50 characters, at least 5 distinct characters, never starting with `django-insecure-`. Fail to load without a good one. No fallback in code and no literal `SECRET_KEY = "..."`.
- `DJANGO_DEBUG` is True only for "1" or "true" (any case), otherwise False. `DJANGO_ALLOWED_HOSTS` is required, comma-separated, whitespace trimmed, empty entries dropped, and `*` is refused. An unknown `Host` header gets 400.
- `SESSION_COOKIE_HTTPONLY`, `CSRF_COOKIE_HTTPONLY` True and both `SameSite` set to `"Lax"`. `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` default False and turn True with `DJANGO_SECURE_COOKIES`. `SECURE_HSTS_SECONDS` defaults to 0 and comes from `DJANGO_HSTS_SECONDS`. `SECURE_REFERRER_POLICY` and `SECURE_CROSS_ORIGIN_OPENER_POLICY` are both set explicitly to `"same-origin"`.
- `USE_TZ=True`, `TIME_ZONE="UTC"`. Keep the default password validators (minimum length at least 8) and do not downgrade the hasher. `ADMIN_URL` comes from `DJANGO_ADMIN_URL`, defaults to something other than `admin/`, ends with `/` and has no leading slash. The cache is `django.core.cache.backends.db.DatabaseCache` (so throttles are shared across workers), which needs `createcachetable`, and the README says so.
- `python manage.py check` and `python manage.py makemigrations --check --dry-run` must pass.

### Middleware and headers
- Required: Security, Session, Csrf, Authentication, Message and XFrameOptions middleware. Every response sends `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` and a referrer policy.
- CSP: on Django 6.x, add `django.middleware.csp.ContentSecurityPolicyMiddleware` and set `SECURE_CSP` with the `django.utils.csp.CSP` constants: `default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`, and no `unsafe-inline` or `unsafe-eval` in any directive. Do not write a custom CSP middleware. On Django 5.2 there is no built-in: stop and ask.
- Private pages (`/watchlist/` and the edit page) use `never_cache` so the response says `no-store`. Error pages (404 and 500) show no traceback, settings, URLconf or exception text.

### Admin
- `Vulnerability`: `list_display` includes `cve_id`, `vendor`, `product`, `date_added`, `due_date`, `ransomware_use`, `cvss_score`. `search_fields` includes `cve_id`, `vendor`, `product`. `list_filter` includes `ransomware_use` and `cvss_severity`. Every NVD field is `readonly_fields`. `Watch`: `list_display` includes `user`, `vulnerability`, `created`, and `raw_id_fields` for both foreign keys. Anonymous users and non-staff are redirected to the admin login, and staff without permissions get 403.

### Templates and static files
- Every page extends `base.html`; there must be 5 or more. Bootstrap 5.3 is vendored at `threatintel/static/vendor/bootstrap/bootstrap.min.css` and `bootstrap.bundle.min.js`, loaded with `{% static %}`. No CDN, no web fonts, no icon fonts.
- **No inline `<script>`, `<style>`, `style=` attributes or `on...=` handlers in any template.** Use external files under `static/`. The strict CSP forbids them.
- The anonymous nav contains exactly `href="/accounts/login/"` and `href="/accounts/register/"`. The logged-in nav has a logout `<form method="post">` pointing at `/accounts/logout/`. Every form that posts includes `{% csrf_token %}`.
- Watchlist delete: one modal per watch row, rendered server-side. The button has `data-bs-toggle="modal"`, the modal element's class attribute starts with `class="modal`, and the `<form>` inside has `method="post"` and an `action` containing `/watch/<cve_id>/delete/`. Do not set the action with JavaScript.
- Dashboard and watchlist show CVE IDs only for the rows they list. No "recent", "top" or "related" panels. Use double-quoted `href` attributes, and render a reference link only for URLs starting with `http://` or `https://`.
- Messages contain the exact words "unavailable" (NVD) and "already" (duplicate watch).
   - Static files: Django's `staticfiles` and `{% static %}` as already used. Do not add WhiteNoise or any other package. How static files are served in production is an open decision for the user.
### Names to verify before relying on them (report any that differ)
The CSP constants (`CSP.SELF`, `CSP.NONE`), the admin URL names (`admin:threatintel_vulnerability_changelist` and similar), and the exact wording of Django's login error. If one of these is wrong in the installed version, say so instead of working around it.

### Open decisions (do not guess, ask)
Whether the class box serves over TLS (this decides the `Secure` cookie switch), how static files are served in production, whether registration needs an invite code, and the Python version on the box.

## Styling run authorization (delete this block after the run)
- A styling run is an explicit "just write it" for `threatintel/templates/` and `threatintel/static/` only. It adds no new function, so the TDD rule does not apply. Do not touch any `.py` file.
- Run `pytest -q` after each change. It must stay green with the same count as before. If a test breaks, fix the template, not the test.
