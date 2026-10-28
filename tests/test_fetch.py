# INF601 - Advanced Programming in Python
# Chase Coble
# Mini Project 6

import http.client
import io
import json
import urllib.error

import pytest

from threatintel.fetch import MAX_RESPONSE_BYTES, FetchError, fetch_kev, fetch_nvd

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
NVD_ID = "CVE-2021-44228"
OK_BODY = b'{"vulnerabilities": []}'
REAL_KEV_BYTES = 1787354  # fill in from: stat -c %s /tmp/kev.json


# ---------- fakes and helpers ----------

class FakeResponse:
    """Stands in for the object urlopen returns. Records every read size."""

    def __init__(self, body=OK_BODY, read_error=None):
        self._body = body
        self._pos = 0
        self._read_error = read_error
        self.read_sizes = []
        self.status = 200
        self.headers = {}

    def getcode(self):
        return 200

    def getheader(self, name, default=None):
        return default

    def read(self, amt=-1):
        self.read_sizes.append(amt)
        if self._read_error is not None:
            raise self._read_error
        if amt is None or amt < 0:
            chunk, self._pos = self._body[self._pos:], len(self._body)
        else:
            chunk = self._body[self._pos:self._pos + amt]
            self._pos += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass


class FakeUrlopen:
    """Stands in for urllib.request.urlopen. Records each request and timeout."""

    def __init__(self, response=None, error=None):
        self.response, self.error = response, error
        self.requests, self.timeouts = [], []

    def __call__(self, request, timeout=None):
        self.requests.append(request)
        self.timeouts.append(timeout)
        if self.error is not None:
            raise self.error
        return self.response


def url_of(request):
    return request if isinstance(request, str) else request.full_url


def as_bytes(obj):
    return json.dumps(obj).encode()


def body_of_size(n):
    body = b'{"a":"' + b"x" * (n - 8) + b'"}'
    assert len(body) == n
    return body


def http_error(code):
    return urllib.error.HTTPError("https://example.invalid/", code, "err", {}, io.BytesIO(b""))


def call_kev(urlopen):
    return fetch_kev(urlopen=urlopen)


def call_nvd(urlopen):
    return fetch_nvd(NVD_ID, urlopen=urlopen)


BOTH = pytest.mark.parametrize("call", [call_kev, call_nvd], ids=["kev", "nvd"])


# ---------- happy paths ----------

def test_fetch_kev_requests_the_cisa_feed_and_returns_decoded_json(load_fixture):
    feed = load_fixture("kev_sample.json")
    fake = FakeUrlopen(FakeResponse(as_bytes(feed)))
    assert fetch_kev(urlopen=fake) == feed
    assert [url_of(r) for r in fake.requests] == [KEV_URL]


def test_fetch_nvd_requests_that_cve_and_returns_decoded_json(load_fixture):
    doc = load_fixture("nvd_log4shell.json")
    fake = FakeUrlopen(FakeResponse(as_bytes(doc)))
    assert fetch_nvd(NVD_ID, urlopen=fake) == doc
    assert [url_of(r) for r in fake.requests] == [NVD_URL + NVD_ID]


def test_fetch_nvd_unknown_cve_response_passes_through(load_fixture):
    doc = load_fixture("nvd_empty.json")
    fake = FakeUrlopen(FakeResponse(as_bytes(doc)))
    assert fetch_nvd("CVE-2099-0001", urlopen=fake) == doc


# ---------- user input never reaches the request ----------

@pytest.mark.parametrize("bad_id", [
    "CVE-2021-44228&x=1", "CVE-2021-44228#frag", "CVE-2021-44228\n",
    "../etc/passwd", "cve-2021-44228", "CVE-\uff12\uff10\uff12\uff11-44228",
    "", None, 42,
])
def test_fetch_nvd_rejects_invalid_cve_id_without_any_request(bad_id):
    fake = FakeUrlopen(FakeResponse())
    with pytest.raises(ValueError):
        fetch_nvd(bad_id, urlopen=fake)
    assert fake.requests == []


# ---------- the response must be for the CVE we asked about ----------

def test_fetch_nvd_rejects_a_response_for_a_different_cve(load_fixture):
    fake = FakeUrlopen(FakeResponse(as_bytes(load_fixture("nvd_log4shell.json"))))
    with pytest.raises(FetchError):
        fetch_nvd("CVE-2099-0001", urlopen=fake)


@pytest.mark.parametrize("data", [
    {}, {"vulnerabilities": "nope"}, {"vulnerabilities": [None]},
    {"vulnerabilities": [{}]}, {"vulnerabilities": [{"cve": None}]},
    {"vulnerabilities": [{"cve": {}}]}, {"vulnerabilities": [{"cve": {"id": 42}}]},
])
def test_fetch_nvd_passes_through_records_it_cannot_compare(data):
    # only a well-formed record with a DIFFERENT id is a FetchError;
    # anything else is parse_nvd's job to judge
    fake = FakeUrlopen(FakeResponse(as_bytes(data)))
    assert fetch_nvd(NVD_ID, urlopen=fake) == data


# ---------- request hygiene ----------

@BOTH
def test_fetch_passes_an_explicit_sane_timeout(call):
    fake = FakeUrlopen(FakeResponse())
    call(fake)
    t = fake.timeouts[0]
    assert isinstance(t, (int, float)) and not isinstance(t, bool)
    assert 0 < t <= 60


@BOTH
def test_fetch_sends_a_user_agent(call):
    fake = FakeUrlopen(FakeResponse())
    call(fake)
    request = fake.requests[0]
    assert not isinstance(request, str), "build a urllib.request.Request so a header can be set"
    agent = request.get_header("User-agent")
    assert isinstance(agent, str) and agent.strip()


@BOTH
def test_fetch_makes_exactly_one_request_on_success(call):
    fake = FakeUrlopen(FakeResponse())
    call(fake)
    assert len(fake.requests) == 1


@BOTH
def test_fetch_does_not_retry_after_failure(call):
    fake = FakeUrlopen(error=http_error(429))
    with pytest.raises(FetchError):
        call(fake)
    assert len(fake.requests) == 1


# ---------- every failure becomes one exception type ----------

@BOTH
@pytest.mark.parametrize("make_error", [
    lambda: http_error(403), lambda: http_error(429), lambda: http_error(500),
    lambda: urllib.error.URLError("refused"), lambda: TimeoutError(),
    lambda: ConnectionResetError(), lambda: OSError("boom"),
], ids=["http-403", "http-429", "http-500", "urlerror", "timeout", "conn-reset", "oserror"])
def test_fetch_maps_request_failures_to_fetch_error(call, make_error):
    with pytest.raises(FetchError):
        call(FakeUrlopen(error=make_error()))


@BOTH
@pytest.mark.parametrize("make_error", [
    lambda: http.client.IncompleteRead(b"partial"),
    lambda: TimeoutError(),
    lambda: ConnectionResetError(),
], ids=["incomplete-read", "timeout", "conn-reset"])
def test_fetch_maps_failures_while_reading_the_body_to_fetch_error(call, make_error):
    fake = FakeUrlopen(FakeResponse(read_error=make_error()))
    with pytest.raises(FetchError):
        call(fake)


@BOTH
@pytest.mark.parametrize("body", [
    b"<html>blocked</html>", b"", b"\xff\xfe", b"{not json", b"[" * 200000,
], ids=["html", "empty", "bad-utf8", "truncated", "deep-nesting"])
def test_fetch_rejects_bodies_that_are_not_json(call, body):
    with pytest.raises(FetchError):
        call(FakeUrlopen(FakeResponse(body)))


@BOTH
@pytest.mark.parametrize("body", [b"[]", b'"x"', b"42", b"null"],
                         ids=["list", "string", "number", "null"])
def test_fetch_rejects_json_that_is_not_an_object(call, body):
    with pytest.raises(FetchError):
        call(FakeUrlopen(FakeResponse(body)))


def test_fetch_error_is_not_a_value_error():
    # views treat FetchError as "enrichment unavailable" and ValueError as "bad input / bad data"
    assert issubclass(FetchError, Exception)
    assert not issubclass(FetchError, ValueError)


# ---------- size cap ----------

def test_fetch_kev_accepts_a_body_of_exactly_the_cap():
    fake = FakeUrlopen(FakeResponse(body_of_size(MAX_RESPONSE_BYTES)))
    assert isinstance(fetch_kev(urlopen=fake), dict)


def test_fetch_kev_rejects_a_body_one_byte_over_the_cap():
    fake = FakeUrlopen(FakeResponse(body_of_size(MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(FetchError):
        fetch_kev(urlopen=fake)


@BOTH
def test_fetch_never_reads_without_a_bound(call):
    response = FakeResponse()
    call(FakeUrlopen(response))
    assert response.read_sizes
    assert all(isinstance(n, int) and 0 < n <= MAX_RESPONSE_BYTES + 1
               for n in response.read_sizes)


def test_max_response_bytes_is_well_above_the_real_feed_but_still_a_cap():
    assert REAL_KEV_BYTES > 0, "set REAL_KEV_BYTES from: stat -c %s /tmp/kev.json"
    assert MAX_RESPONSE_BYTES >= 4 * REAL_KEV_BYTES
    assert MAX_RESPONSE_BYTES <= 50 * 1024 * 1024
