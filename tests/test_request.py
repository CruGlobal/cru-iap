"""Pulling the assertion off each kind of request object a Cru app might hand us.

Mirrors ``test/unit/request.test.ts``. The point of these is that application
code never names the header — so every framework shape the two known consumers
(FastAPI) plus the likely next ones (Django, Flask, bare WSGI) could pass in has
to work.
"""

from __future__ import annotations

from cru_iap import HEADER, WSGI_ENVIRON_KEY, assertion_from

TOKEN = "header.payload.signature"


class FakeHeaders:
    """A case-insensitive header mapping, as Starlette and Werkzeug both provide."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = {key.lower(): value for key, value in values.items()}

    def get(self, name, default=None):
        return self._values.get(name.lower(), default)

    def items(self):
        return self._values.items()


class FakeRequest:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = FakeHeaders(headers)


class FakeDjangoRequest:
    """Django exposes both; older code reaches for META."""

    def __init__(self, meta: dict[str, str]) -> None:
        self.META = meta


def test_reads_from_a_framework_request_with_a_headers_mapping():
    request = FakeRequest({HEADER: TOKEN})

    assert assertion_from(request) == TOKEN


def test_is_case_insensitive_about_the_header_name_on_a_framework_request():
    request = FakeRequest({"X-Goog-IAP-JWT-Assertion": TOKEN})

    assert assertion_from(request) == TOKEN


def test_reads_from_a_plain_header_dict():
    assert assertion_from({HEADER: TOKEN}) == TOKEN


def test_is_case_insensitive_about_the_header_name_in_a_plain_dict():
    # A hand-built dict may not be lowercased, unlike anything a framework hands
    # over. Scan rather than trusting the caller.
    assert assertion_from({"X-Goog-Iap-Jwt-Assertion": TOKEN}) == TOKEN


def test_reads_from_a_wsgi_environ():
    assert assertion_from({WSGI_ENVIRON_KEY: TOKEN}) == TOKEN


def test_reads_from_a_django_request_via_meta():
    assert assertion_from(FakeDjangoRequest({WSGI_ENVIRON_KEY: TOKEN})) == TOKEN


def test_prefers_the_headers_mapping_when_a_request_offers_both():
    class Both:
        headers = FakeHeaders({HEADER: TOKEN})
        META = {WSGI_ENVIRON_KEY: "stale.other.token"}

    assert assertion_from(Both()) == TOKEN


def test_decodes_a_bytes_header_value():
    assert assertion_from({HEADER: TOKEN.encode()}) == TOKEN


def test_returns_none_when_the_header_is_absent():
    assert assertion_from({}) is None
    assert assertion_from(FakeRequest({})) is None


def test_returns_none_for_something_that_is_not_a_request_at_all():
    assert assertion_from(None) is None
    assert assertion_from("a string") is None
    assert assertion_from(42) is None


def test_unwraps_a_single_element_list():
    assert assertion_from({HEADER: [TOKEN]}) == TOKEN


def test_treats_a_repeated_header_as_absent():
    # Two assertions is not a shape IAP produces. Treat it as absent rather than
    # guessing which to trust; the verifier then reports missing_token and fails
    # closed.
    assert assertion_from({HEADER: [TOKEN, "another.jwt.here"]}) is None


def test_the_wire_name_is_what_infra_config_expects():
    # Pinned because terraform, the LB and test fixtures all name it literally.
    assert HEADER == "x-goog-iap-jwt-assertion"
    assert WSGI_ENVIRON_KEY == "HTTP_X_GOOG_IAP_JWT_ASSERTION"
