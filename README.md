# Threat Intel Aggregator (Django)

A Django web application that aggregates known-exploited vulnerability data from the CISA
KEV catalog and supplementary CVE detail from the NVD API, letting registered users browse,
search, and maintain a personal watchlist with private notes.

## Features

- Ingests and displays entries from the CISA Known Exploited Vulnerabilities (KEV) catalog
- Looks up supplementary CVE detail from the NVD API, with graceful degradation to
  KEV-only data if NVD is unavailable
- User registration and authentication
- Per-user watchlist with private notes, access-scoped so one user cannot read, edit, or
  delete another user's entries
- Search across tracked CVEs
- Hardened for exposure to untrusted traffic: CSRF protection, a strict Content-Security-Policy,
  standard security response headers, and rate limiting on registration, login, and
  refresh actions

## Tech stack

- Python 3.13, Django 6.1
- SQLite, with foreign-key-enforced relations between users, watchlist entries, and notes
- Bootstrap for the front end
- Automated tests via the Django test runner / pytest

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Environment variables

The application reads its configuration from environment variables rather than hardcoding
it in `settings.py`. These must be set before running any `manage.py` command
(`runserver`, `migrate`, `test`, etc.):

| Variable | Required | Purpose |
|---|---|---|
| `DJANGO_SECRET_KEY` | Yes | Cryptographic signing key for sessions, CSRF tokens, and password-reset tokens. Generate your own per environment — never reuse one, and never commit a real one to this repository. |
| `DJANGO_ALLOWED_HOSTS` | Yes | Comma-separated list of hostnames Django will accept requests for. |
| `DJANGO_ADMIN_URL` | Yes | Path segment the Django admin is mounted at. In any deployment exposed beyond localhost, set this to something other than the default `admin/` so the admin login isn't sitting at a well-known path; for local development any value works. |

Generate a real secret key rather than typing one in by hand:
```bash
python -c "import secrets; print(secrets.token_urlsafe(50))"
```

**Set them for local development** — pick one:

Export them directly in your shell (simplest; lost when the shell closes):
```bash
export DJANGO_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(50))')"
export DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost"
export DJANGO_ADMIN_URL="admin/"
```

Or put them in a local file and source it before running the app:
```bash
cat > .env.local <<'EOF'
DJANGO_SECRET_KEY=replace-with-output-of-the-command-above
DJANGO_ALLOWED_HOSTS=127.0.0.1,localhost
DJANGO_ADMIN_URL=admin/
EOF
set -a; source .env.local; set +a
```
Confirm `.env.local` (or whatever name you use) is covered by `.gitignore` before creating
it — this file will contain a real secret key and must never be committed.

Then apply migrations and run the app:
```bash
python manage.py migrate
python manage.py runserver
```

## Running the tests

```bash
python manage.py test
# or, if pytest-django is configured:
pytest
```

This project follows test-driven development: for each feature or fix, a failing test was
written first to specify the expected behavior, and implementation code was written
afterward to satisfy it. The test suite is the executable record of those requirements —
running it is the fastest way to confirm the application still behaves as specified.

## Security testing note

This application was built, in part, to serve as a live penetration-testing target for a
class exercise: classmates attempt black-box exploitation of a deployed instance of this
code.

Beyond the automated test suite above, this project has an associated body of security
documentation — an initial penetration-test report, a mitigations record explaining the
root cause and fix for each finding, and a post-mitigation retest confirming the results.
That documentation exists, but it is **intentionally withheld from this repository** (kept
out of version control) until after the live class exercise concludes. Publishing it now
would hand every other student a map of this application's weaknesses before they do their
own testing, which defeats the point of the exercise.

That security-engagement documentation will be added to this repository, or published
separately, after the live exercise and the grading period for it have ended.

## AI usage disclosure

I designed and built this project's architecture, infrastructure, and process. AI tools
were used for specific, bounded tasks under my direction and review — not as an
unsupervised author of this repository.

**What I did directly:**
- Decided the application's architecture, including the port from the original Flask
  version of this project to Django, and specified the security requirements this version
  needed to meet, since it would serve as a live attack target for other students in class.
- Designed and built the isolated environment this application runs in for that
  exercise — network isolation, host provisioning, service configuration, and the egress
  controls on what the application and its tooling can reach — and diagnosed
  environment-level problems myself from direct evidence (for example, tracing a
  registration failure to a file-ownership problem using the application's own logs, not
  by asking an AI what was wrong).
- Wrote the `CLAUDE.md` contract that bounds how AI-assisted implementation is allowed to
  proceed on this project: it may not modify tests, may not commit changes, and must
  report every assumption instead of resolving ambiguity on its own.
- Reviewed every AI-produced test, implementation change, and document before accepting
  it, and rejected or corrected output that was wrong, imprecise, or overclaimed something
  not yet verified — including catching a misplaced pair of tests, status language that
  described a fix as "verified" when only the test suite had passed, and inconsistent
  terminology in an early draft of the security report.
- Made every scoping and risk-acceptance decision reflected in this project's security
  documentation — what gets fixed, what gets deferred, and what gets accepted as a
  permanent tradeoff — and authored every commit.

**Where AI assistance was used, within that process:**
- An AI assistant (Claude) wrote failing tests first, to a specification I gave it, before
  any implementation existed to satisfy them.
- A separate AI coding agent (Claude Code) implemented application code against those
  tests, operating under the `CLAUDE.md` contract above.
- During the live security exercise, an AI coding agent ran black-box tests against the
  deployed application from a separate host and reported candidate findings, which I then
  reviewed — discarding retracted false leads and overclaiming language — before using
  them to decide the mitigations in this project's security documentation.
- AI assistance helped produce an initial draft of that security documentation, which I
  then edited for factual accuracy and consistent terminology before finalizing it.

I treat AI-authored code and text the way I'd treat a draft from anyone else I'm
responsible for reviewing: useful, but not authoritative until I've checked it myself.

## License / Author

Chase Coble — FHSU, submitted as coursework. See repository history for commit-level detail
on individual changes.
