# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import http.client
import json
import urllib.request

from threatintel.sources import validate_cve_id

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
USER_AGENT = "threatintel-inf601/0.4"
TIMEOUT_SECONDS = 30
# ~9x the real KEV feed (about 1.8 MB), so growth is fine but a runaway body is not
MAX_RESPONSE_BYTES = 16 * 1024 * 1024


class FetchError(Exception):
    """The upstream feed could not be fetched or its body was not a JSON object."""


def fetch_kev(urlopen=urllib.request.urlopen):
    return get_json(KEV_URL, urlopen)


def fetch_nvd(cve_id, urlopen=urllib.request.urlopen):
    # Validate before building the URL so user input can't add query params
    if not validate_cve_id(cve_id):
        raise ValueError(f"invalid CVE ID {cve_id!r}")
    data = get_json(NVD_URL + cve_id, urlopen)
    # Only a well-formed record for a different CVE is rejected here;
    # anything malformed is left for parse_nvd to judge
    records = data.get("vulnerabilities")
    if isinstance(records, list) and records and isinstance(records[0], dict):
        cve = records[0].get("cve")
        if isinstance(cve, dict) and isinstance(cve.get("id"), str) and cve["id"] != cve_id:
            raise FetchError(f"NVD returned {cve['id']!r} when asked for {cve_id}")
    return data


def get_json(url, urlopen):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = read_capped(response)
    # HTTPError, URLError, timeouts and resets are all OSError;
    # IncompleteRead is an HTTPException
    except (OSError, http.client.HTTPException) as e:
        raise FetchError(f"request to {url} failed: {e!r}") from e
    if len(body) > MAX_RESPONSE_BYTES:
        raise FetchError(f"response from {url} exceeds {MAX_RESPONSE_BYTES} bytes")
    try:
        data = json.loads(body.decode("utf-8"))
    # UnicodeDecodeError and JSONDecodeError are both ValueError;
    # deeply nested input raises RecursionError
    except (ValueError, RecursionError) as e:
        raise FetchError(f"response from {url} is not valid JSON") from e
    if not isinstance(data, dict):
        raise FetchError(f"response from {url} is not a JSON object")
    return data


def read_capped(response):
    # Read at most one byte past the cap, so an oversize body is detectable
    # without ever reading it all. Loop because read(n) may return fewer
    # than n bytes before the end of the body.
    remaining = MAX_RESPONSE_BYTES + 1
    chunks = []
    while remaining > 0:
        chunk = response.read(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
